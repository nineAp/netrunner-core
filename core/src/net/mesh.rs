//! Peer directory and latency-aware routing across the node mesh.
//!
//! The control plane supplies peer metadata. This module keeps a short-lived
//! in-memory view and probes peers from this node. Flows select a bounded,
//! loop-free path and carry it through the NRXP mesh legs.

use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{AppError, ERR_INFRA_TIMEOUT};
use rand::RngExt;
use sha2::Digest;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex, OnceCell, RwLock, Semaphore},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::connection::{mesh_process_uptime_ms, ClientHandler, MeshPeerSession, Muxer};
use super::{MeshPeer, MeshRoute, MeshRouteSelection, MAX_MESH_HOPS};
use crate::nrxp::FrameType;

// Mesh peers may have much higher latency than an app-to-ingress leg. Give a
// TCP reachability probe enough time to cross a slow inter-node path instead
// of misclassifying a working node as unhealthy.
const PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const PEER_PROBE_MAX_AGE: Duration = Duration::from_secs(90);
const PEER_PROBE_FAILURES_TO_EVICT: u8 = 3;
const MAX_CACHED_PEER_SESSIONS: usize = 256;
const IDLE_PEER_SESSION_RETENTION: Duration = Duration::from_secs(300);
const ONION_CAPSULE_MAX_AGE_SECS: u64 = 120;
const MAX_ONION_REPLAY_ENTRIES: usize = 262_144;
const ONION_REPLAY_SWEEP_INTERVAL: u64 = 1_024;
const MIX_BATCH_WINDOW: Duration = Duration::from_millis(20);
const MIX_BATCH_MAX_PACKETS: usize = 512;

struct MixPacket {
    flow_id: String,
    target: MixTarget,
    stream_id: u32,
    payload: Bytes,
    is_udp: bool,
    cancel: CancellationToken,
}

enum MixTarget {
    Tunnel(Arc<Muxer>),
    Local(mpsc::Sender<Bytes>),
}

struct CoverState {
    active_flows: AtomicUsize,
    cancel: CancellationToken,
}

pub(crate) struct CoverLease(Arc<CoverState>);

impl Drop for CoverLease {
    fn drop(&mut self) {
        if self.0.active_flows.fetch_sub(1, AtomicOrdering::AcqRel) == 1 {
            self.0.cancel.cancel();
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PeerSessionKey {
    node_id: String,
    peer_fingerprint: [u8; 32],
    auth_fingerprint: [u8; 32],
}

struct PeerSessionSlot {
    establish_lock: Mutex<()>,
    session: std::sync::Mutex<Option<Arc<MeshPeerSession>>>,
}

impl PeerSessionSlot {
    fn new() -> Self {
        Self {
            establish_lock: Mutex::new(()),
            session: std::sync::Mutex::new(None),
        }
    }
}

#[derive(Clone, Copy)]
struct PeerProbe {
    rtt_ms: u32,
    probed_at: std::time::Instant,
    consecutive_failures: u8,
}

#[derive(Default)]
struct EgressRotation {
    candidate_signature: Vec<String>,
    pending: VecDeque<(MeshPeer, String)>,
    last_address: Option<String>,
}

pub struct NodeMesh {
    local_node_id: String,
    local_node_secret: String,
    max_hops: u8,
    mesh_quic_port: u16,
    peers: RwLock<Vec<MeshPeer>>,
    rtt_ms: DashMap<String, PeerProbe>,
    onion_identity: std::sync::RwLock<Option<crate::crypto::LocalIdentity>>,
    onion_replays: DashMap<[u8; 16], Instant>,
    onion_replay_insertions: AtomicU64,
    egress_rotation: Mutex<EgressRotation>,
    peer_sessions: Mutex<HashMap<PeerSessionKey, Arc<PeerSessionSlot>>>,
    mixer: OnceCell<mpsc::Sender<MixPacket>>,
    cover_tasks: Mutex<HashMap<String, Arc<CoverState>>>,
}

impl NodeMesh {
    pub fn new(local_node_id: String, local_node_secret: String) -> Self {
        Self::with_max_hops(local_node_id, local_node_secret, 2)
    }

    pub fn with_max_hops(local_node_id: String, local_node_secret: String, max_hops: u8) -> Self {
        Self::with_max_hops_and_quic_port(
            local_node_id,
            local_node_secret,
            max_hops,
            super::DEFAULT_MESH_QUIC_PORT,
        )
    }

    pub fn with_max_hops_and_quic_port(
        local_node_id: String,
        local_node_secret: String,
        max_hops: u8,
        mesh_quic_port: u16,
    ) -> Self {
        Self {
            local_node_id,
            local_node_secret,
            max_hops: max_hops.clamp(1, MAX_MESH_HOPS),
            mesh_quic_port,
            peers: RwLock::new(Vec::new()),
            rtt_ms: DashMap::new(),
            onion_identity: std::sync::RwLock::new(None),
            onion_replays: DashMap::new(),
            onion_replay_insertions: AtomicU64::new(0),
            egress_rotation: Mutex::new(EgressRotation::default()),
            peer_sessions: Mutex::new(HashMap::new()),
            mixer: OnceCell::new(),
            cover_tasks: Mutex::new(HashMap::new()),
        }
    }

    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    /// A mesh auth token is carried only inside the already encrypted NRXP
    /// session. Do not log or expose it through diagnostics.
    pub fn auth_token(&self) -> String {
        format!("mesh:{}:{}", self.local_node_id, self.local_node_secret)
    }

    pub(crate) fn onion_auth_token(&self) -> String {
        format!("mesh4:{}:{}", self.local_node_id, self.local_node_secret)
    }

    pub fn set_onion_identity(&self, identity: crate::crypto::LocalIdentity) {
        *self
            .onion_identity
            .write()
            .expect("onion identity lock poisoned") = Some(identity);
    }

    pub(crate) async fn open_onion_capsule(
        &self,
        wire: &[u8],
    ) -> Result<super::mesh_onion::OpenedOnionCapsule, String> {
        let identity = self
            .onion_identity
            .read()
            .map_err(|_| "mesh onion identity lock poisoned".to_owned())?
            .clone()
            .ok_or_else(|| "mesh onion identity is unavailable".to_owned())?;
        let opened = super::mesh_onion::open_capsule(&self.local_node_id, &identity, wire)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before UNIX epoch".to_owned())?
            .as_secs();
        if opened.expires_at_unix <= now
            || opened.expires_at_unix > now.saturating_add(ONION_CAPSULE_MAX_AGE_SECS)
        {
            return Err("mesh onion capsule is expired or has an invalid lifetime".into());
        }
        let insertions = self
            .onion_replay_insertions
            .fetch_add(1, AtomicOrdering::Relaxed)
            .saturating_add(1);
        if insertions % ONION_REPLAY_SWEEP_INTERVAL == 0
            || self.onion_replays.len() >= MAX_ONION_REPLAY_ENTRIES
        {
            self.onion_replays.retain(|_, inserted_at| {
                inserted_at.elapsed() <= Duration::from_secs(ONION_CAPSULE_MAX_AGE_SECS + 1)
            });
        }
        if self.onion_replays.len() >= MAX_ONION_REPLAY_ENTRIES {
            return Err("mesh onion replay cache is full".into());
        }
        match self.onion_replays.entry(opened.replay_nonce) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                return Err("mesh onion capsule replay was rejected".into());
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Instant::now());
            }
        }
        Ok(opened)
    }

    /// Build a complete loop-free path at ingress and seal its instructions
    /// backwards so each relay can decrypt only its own next-hop instruction.
    pub(crate) async fn build_onion_route(
        &self,
        target: &str,
        is_udp: bool,
        strong_privacy: bool,
        excluded_first_hops: &[String],
    ) -> Option<(MeshPeer, Vec<u8>)> {
        if self.max_hops <= 1 || target.is_empty() || target.len() > 2048 || target.contains('\0') {
            return None;
        }
        let route = MeshRoute {
            remaining_hops: self.max_hops,
            selection: MeshRouteSelection::WeightedRandom,
            egress_node_id: None,
            visited: vec![self.local_node_id.clone()],
        };
        let mut candidates = self.peers_for_route(&route).await;
        candidates.retain(|peer| {
            !excluded_first_hops
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(&peer.node_id))
        });
        if candidates.is_empty() {
            return None;
        }

        // Fresh RTT samples are preferred when there are enough healthy nodes
        // to build at least the normal two-hop path. On cold start keep
        // unprobed directory peers as a fallback; connection setup will still
        // fail closed and retry a different first hop.
        let probed: Vec<_> = candidates
            .iter()
            .filter(|peer| self.recent_rtt_ms(&peer.node_id).is_some())
            .cloned()
            .collect();
        if probed.len() >= 1 {
            candidates = probed;
        }
        let max_total_hops = self.max_hops.min(candidates.len().saturating_add(1) as u8);
        let total_hops = if self.max_hops > 2 && max_total_hops >= 3 {
            rand::rng().random_range(3..=max_total_hops)
        } else {
            2.min(max_total_hops)
        };
        let relay_count = usize::from(total_hops.saturating_sub(1));
        if relay_count == 0 || candidates.len() < relay_count {
            return None;
        }
        candidates.truncate(relay_count);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let expires_at = now.saturating_add(60);
        let mut rng = rand::rng();
        let mut nonce = || std::array::from_fn(|_| rng.random::<u8>());
        let last = candidates.last()?;
        let mut capsule = super::mesh_onion::seal_capsule(
            last,
            strong_privacy,
            is_udp,
            1,
            expires_at,
            nonce(),
            super::mesh_onion::OnionInstruction::Exit {
                target: target.to_owned(),
            },
        )
        .ok()?;
        for index in (0..candidates.len().saturating_sub(1)).rev() {
            capsule = super::mesh_onion::seal_capsule(
                &candidates[index],
                strong_privacy,
                is_udp,
                (candidates.len() - index) as u8,
                expires_at,
                nonce(),
                super::mesh_onion::OnionInstruction::Forward {
                    next_peer: candidates[index + 1].clone(),
                    next_capsule: capsule,
                },
            )
            .ok()?;
        }
        Some((candidates[0].clone(), capsule))
    }

    pub(crate) async fn send_mixed(
        &self,
        muxer: Arc<Muxer>,
        stream_id: u32,
        payload: Bytes,
        is_udp: bool,
        cancel: CancellationToken,
    ) -> Result<(), ()> {
        let sender = self
            .mixer
            .get_or_init(|| async {
                let (sender, receiver) = mpsc::channel(4096);
                tokio::spawn(run_mix_scheduler(receiver));
                sender
            })
            .await;
        sender
            .send(MixPacket {
                flow_id: format!("tunnel:{}:{stream_id}", muxer.session_id()),
                target: MixTarget::Tunnel(muxer),
                stream_id,
                payload,
                is_udp,
                cancel,
            })
            .await
            .map_err(|_| ())
    }

    pub(crate) async fn send_mixed_to_local(
        &self,
        flow_id: String,
        target: mpsc::Sender<Bytes>,
        payload: Bytes,
        is_udp: bool,
        cancel: CancellationToken,
    ) -> Result<(), ()> {
        let sender = self
            .mixer
            .get_or_init(|| async {
                let (sender, receiver) = mpsc::channel(4096);
                tokio::spawn(run_mix_scheduler(receiver));
                sender
            })
            .await;
        sender
            .send(MixPacket {
                flow_id,
                target: MixTarget::Local(target),
                stream_id: 0,
                payload,
                is_udp,
                cancel,
            })
            .await
            .map_err(|_| ())
    }

    pub(crate) async fn acquire_cover_lease(self: &Arc<Self>, muxer: Arc<Muxer>) -> CoverLease {
        let session_id = muxer.session_id().to_owned();
        let mut tasks = self.cover_tasks.lock().await;
        let state = match tasks.get(&session_id) {
            Some(state) if !state.cancel.is_cancelled() => state.clone(),
            _ => {
                let state = Arc::new(CoverState {
                    active_flows: AtomicUsize::new(0),
                    cancel: CancellationToken::new(),
                });
                tasks.insert(session_id.clone(), state.clone());
                let task_state = state.clone();
                let task_muxer = muxer.clone();
                let weak_mesh = Arc::downgrade(self);
                tokio::spawn(async move {
                    loop {
                        let delay_ms = rand::rng().random_range(900..=2400);
                        tokio::select! {
                            _ = task_state.cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                        }
                        let payload_len = rand::rng().random_range(128..=384);
                        let payload = (0..payload_len)
                            .map(|_| rand::rng().random::<u8>())
                            .collect::<Vec<_>>();
                        if task_muxer
                            .send_control(0, FrameType::Cover, Bytes::from(payload))
                            .await
                            .is_err()
                            && task_muxer.is_fatal()
                        {
                            break;
                        }
                    }
                    if let Some(mesh) = weak_mesh.upgrade() {
                        let mut tasks = mesh.cover_tasks.lock().await;
                        if tasks
                            .get(&session_id)
                            .is_some_and(|current| Arc::ptr_eq(current, &task_state))
                        {
                            tasks.remove(&session_id);
                        }
                    }
                });
                state
            }
        };
        state.active_flows.fetch_add(1, AtomicOrdering::AcqRel);
        CoverLease(state)
    }

    pub async fn update_peers(&self, peers: Vec<MeshPeer>) {
        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_addresses = std::collections::HashSet::new();
        let peers: Vec<_> = peers
            .into_iter()
            // Node ids are UUIDs but may arrive with different casing from
            // provisioning and the backend. Canonicalize comparisons here so
            // this ingress can never select itself as its own egress.
            .filter(|peer| !peer.node_id.eq_ignore_ascii_case(&self.local_node_id))
            .filter(|peer| seen_ids.insert(peer.node_id.to_ascii_lowercase()))
            .filter(|peer| {
                !peer.host.trim().is_empty()
                    && peer.port != 0
                    && !peer.nrxp_secret.is_empty()
                    && !peer.nrxp_static_public.is_empty()
            })
            .filter(|peer| seen_addresses.insert(peer.address().to_ascii_lowercase()))
            .collect();

        let active_peer_fingerprints: std::collections::HashSet<_> = peers
            .iter()
            .map(|peer| (peer.node_id.to_ascii_lowercase(), peer_fingerprint(peer)))
            .collect();
        self.rtt_ms
            .retain(|node_id, _| active_peer_fingerprints.iter().any(|(id, _)| id == node_id));
        self.peer_sessions.lock().await.retain(|key, _| {
            active_peer_fingerprints.contains(&(key.node_id.clone(), key.peer_fingerprint))
        });
        *self.peers.write().await = peers;
    }

    /// Probe all known peers concurrently. A TCP connect is enough to detect
    /// reachability and get an ingress-relative latency estimate; it sends no
    /// destination or user data.
    pub async fn probe_peers(&self) {
        let peers = self.peers.read().await.clone();
        let mut probes = tokio::task::JoinSet::new();

        for peer in peers {
            let rtt_ms = self.rtt_ms.clone();
            probes.spawn(async move {
                let start = std::time::Instant::now();
                let reachable = timeout(PEER_PROBE_TIMEOUT, TcpStream::connect(peer.address()))
                    .await
                    .is_ok_and(|result| result.is_ok());
                if reachable {
                    rtt_ms.insert(
                        peer.node_id.to_ascii_lowercase(),
                        PeerProbe {
                            rtt_ms: start.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32,
                            probed_at: std::time::Instant::now(),
                            consecutive_failures: 0,
                        },
                    );
                } else {
                    // A few lost probes are not enough to declare a node
                    // unhealthy. Keep the last sample through transient misses;
                    // evict only after the configured number of consecutive
                    // failures. recent_rtt_ms() independently expires old
                    // successful samples.
                    let node_id = peer.node_id.to_ascii_lowercase();
                    let evict = if let Some(mut previous) = rtt_ms.get_mut(&node_id) {
                        previous.consecutive_failures =
                            previous.consecutive_failures.saturating_add(1);
                        previous.consecutive_failures >= PEER_PROBE_FAILURES_TO_EVICT
                    } else {
                        false
                    };
                    if evict {
                        rtt_ms.remove(&node_id);
                    }
                }
            });
        }

        while probes.join_next().await.is_some() {}
    }

    /// Lowest measured RTT first. Unprobed peers are retained after measured
    /// peers so the legacy nearest-egress mode can start before its first probe.
    pub async fn ordered_peers(&self) -> Vec<MeshPeer> {
        let mut peers = self.peers.read().await.clone();
        peers.sort_by(|left, right| {
            match (
                self.recent_rtt_ms(&left.node_id),
                self.recent_rtt_ms(&right.node_id),
            ) {
                (Some(left_rtt), Some(right_rtt)) => left_rtt.cmp(&right_rtt),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => left.node_id.cmp(&right.node_id),
            }
        });
        peers
    }

    /// A max-hop value of one means direct output. Two keeps the normal
    /// two-node route and selects a healthy RTT-weighted egress per flow. For
    /// a larger limit, each flow also picks a random path length up to the cap.
    pub fn initial_route(&self) -> Option<MeshRoute> {
        (self.max_hops > 1).then(|| MeshRoute {
            remaining_hops: self.max_hops,
            // Even the normal two-hop mode must rotate healthy egress IPs.
            // `WeightedRandom` selects the egress in route_for_flow; path
            // length is randomized there only when the configured cap is > 2.
            selection: MeshRouteSelection::WeightedRandom,
            egress_node_id: None,
            visited: vec![self.local_node_id.clone()],
        })
    }

    /// Select an RTT-ranked egress and path budget once per application flow.
    /// Freshly probed peers determine the preferred path length; if there are
    /// too few, fall back to a two-hop route from the control-plane directory.
    /// Intermediates preserve both choices from the encrypted mesh claim.
    pub async fn route_for_flow(&self, route: &MeshRoute) -> Option<MeshRoute> {
        if route.selection != MeshRouteSelection::WeightedRandom
            || route.visited.len() != 1
            || route.egress_node_id.is_some()
        {
            return Some(route.clone());
        }

        // Fresh RTT samples guide the preferred path, but missing probe data
        // must not take the entire mesh offline. Peers without a fresh sample
        // remain available as a lower-priority fallback in peers_for_route().
        let candidates = self.peers_for_route(route).await;
        let healthy_candidates: Vec<_> = candidates
            .iter()
            .filter(|peer| self.recent_rtt_ms(&peer.node_id).is_some())
            .cloned()
            .collect();
        if route.remaining_hops == 2 {
            let selected = self.two_hop_fallback(route, healthy_candidates).await;
            if let Some(selected) = selected.as_ref() {
                record_route_hops(selected);
            }
            return selected;
        }

        let max_available_hops = healthy_candidates
            .len()
            .saturating_add(1)
            .min(usize::from(route.remaining_hops));
        if max_available_hops < 3 {
            // A larger hop cap is a maximum, not a minimum. Keep at least a
            // two-node route, even before this ingress has fresh RTT samples.
            let selected = self.two_hop_fallback(route, healthy_candidates).await;
            if let Some(selected) = selected.as_ref() {
                record_route_hops(selected);
            }
            return selected;
        }

        let mut flow_route = route.clone();
        flow_route.remaining_hops = rand::rng().random_range(3..=max_available_hops as u8);
        flow_route.egress_node_id = Some(
            self.next_egress(healthy_candidates, &[], false)
                .await?
                .node_id,
        );
        record_route_hops(&flow_route);
        Some(flow_route)
    }

    async fn two_hop_fallback(
        &self,
        route: &MeshRoute,
        healthy_candidates: Vec<MeshPeer>,
    ) -> Option<MeshRoute> {
        let (egress, selection) =
            if let Some(egress) = self.next_egress(healthy_candidates, &[], false).await {
                (egress, route.selection)
            } else {
                let fallback_peers: Vec<_> = self
                    .peers
                    .read()
                    .await
                    .iter()
                    .filter(|peer| {
                        !route
                            .visited
                            .iter()
                            .any(|visited| visited.eq_ignore_ascii_case(&peer.node_id))
                    })
                    .cloned()
                    .collect();
                (
                    self.next_egress(fallback_peers, &[], true).await?,
                    MeshRouteSelection::Nearest,
                )
            };

        let mut flow_route = route.clone();
        flow_route.remaining_hops = 2;
        flow_route.selection = selection;
        flow_route.egress_node_id = Some(egress.node_id);
        Some(flow_route)
    }

    /// Retry route setup before a flow is established: first try another
    /// egress, then shorten an impossible X-hop chain. A live flow keeps its
    /// selected route pinned for its full lifetime.
    pub async fn retry_with_next_egress(
        &self,
        route: &MeshRoute,
        failed_egress_ids: &[String],
    ) -> Option<MeshRoute> {
        let allow_unprobed_fallback = route.selection == MeshRouteSelection::Nearest
            && route.remaining_hops == 2
            && route.visited.len() == 1;
        if (route.selection != MeshRouteSelection::WeightedRandom && !allow_unprobed_fallback)
            || route.visited.len() != 1
            || route.egress_node_id.is_none()
            || route.remaining_hops < 2
        {
            return None;
        }

        let mut candidates_route = route.clone();
        candidates_route.egress_node_id = None;
        let candidates = self.peers_for_route(&candidates_route).await;
        let probed_candidates: Vec<_> = candidates
            .iter()
            .filter(|peer| self.recent_rtt_ms(&peer.node_id).is_some())
            .cloned()
            .collect();
        let next_probed = self
            .next_egress(probed_candidates, failed_egress_ids, false)
            .await;
        let next_fallback = if next_probed.is_none() {
            self.next_egress(candidates.clone(), failed_egress_ids, true)
                .await
        } else {
            None
        };
        let (next_egress, shorten_chain) = match next_probed.or(next_fallback) {
            Some(peer) => (peer, false),
            None if route.remaining_hops > 2 => {
                (self.next_egress(candidates, &[], true).await?, true)
            }
            None => return None,
        };
        let mut retry_route = route.clone();
        if shorten_chain {
            retry_route.remaining_hops -= 1;
        }
        retry_route.egress_node_id = Some(next_egress.node_id);
        Some(retry_route)
    }

    /// Rotate through a randomized, RTT-weighted permutation of distinct peer
    /// addresses. The two-hop outage fallback may include peers without RTT
    /// samples; each address is still used once before the bag is reshuffled.
    async fn next_egress(
        &self,
        peers: Vec<MeshPeer>,
        excluded_node_ids: &[String],
        allow_unprobed: bool,
    ) -> Option<MeshPeer> {
        let mut by_address = HashMap::<String, (MeshPeer, u32)>::new();
        let mut candidate_signature = Vec::with_capacity(peers.len());
        for peer in peers {
            let rtt = match self.recent_rtt_ms(&peer.node_id) {
                Some(rtt) => rtt,
                None if allow_unprobed => u32::MAX,
                None => continue,
            };
            let address_key = peer.host.trim().to_ascii_lowercase();
            candidate_signature.push(format!(
                "{address_key}:{}:{}:{}={}",
                peer.port,
                peer.node_id.to_ascii_lowercase(),
                peer.nrxp_static_public.to_ascii_lowercase(),
                peer.decoy_sni.to_ascii_lowercase(),
            ));
            match by_address.entry(address_key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((peer, rtt));
                }
                std::collections::hash_map::Entry::Occupied(mut entry) if rtt < entry.get().1 => {
                    entry.insert((peer, rtt));
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
        }
        candidate_signature.sort_unstable();

        let mut rotation = self.egress_rotation.lock().await;
        if rotation.candidate_signature != candidate_signature || rotation.pending.is_empty() {
            let mut next_cycle = weighted_egress_order(by_address);
            if next_cycle.len() > 1
                && next_cycle
                    .first()
                    .is_some_and(|(_, address)| Some(address) == rotation.last_address.as_ref())
            {
                if let Some(next_different) = next_cycle
                    .iter()
                    .position(|(_, address)| Some(address) != rotation.last_address.as_ref())
                {
                    next_cycle.swap(0, next_different);
                }
            }
            rotation.candidate_signature = candidate_signature;
            rotation.pending = next_cycle.into();
        }

        while let Some((peer, address)) = rotation.pending.pop_front() {
            rotation.last_address = Some(address);
            if !excluded_node_ids
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(&peer.node_id))
            {
                return Some(peer);
            }
        }
        None
    }

    /// Return eligible next hops for a route. Freshly probed peers are ordered
    /// first; unprobed directory peers remain as a fallback. Every mode
    /// excludes the originating ingress and all already visited nodes.
    pub async fn peers_for_route(&self, route: &MeshRoute) -> Vec<MeshPeer> {
        let peers = self.peers.read().await.clone();
        let mut candidates: Vec<(MeshPeer, Option<u32>)> = peers
            .into_iter()
            .filter(|peer| {
                !route
                    .visited
                    .iter()
                    .any(|visited| visited.eq_ignore_ascii_case(&peer.node_id))
            })
            .filter(|peer| {
                route.egress_node_id.as_ref().is_none_or(|egress| {
                    if route.remaining_hops == 2 {
                        peer.node_id.eq_ignore_ascii_case(egress)
                    } else {
                        !peer.node_id.eq_ignore_ascii_case(egress)
                    }
                })
            })
            .map(|peer| {
                let rtt = self.recent_rtt_ms(&peer.node_id);
                (peer, rtt)
            })
            .collect();

        match route.selection {
            MeshRouteSelection::Nearest => {
                candidates.sort_by(|(left, left_rtt), (right, right_rtt)| {
                    match (left_rtt, right_rtt) {
                        (Some(left), Some(right)) => left.cmp(right),
                        (Some(_), None) => Ordering::Less,
                        (None, Some(_)) => Ordering::Greater,
                        (None, None) => left
                            .node_id
                            .to_ascii_lowercase()
                            .cmp(&right.node_id.to_ascii_lowercase()),
                    }
                });
            }
            MeshRouteSelection::WeightedRandom => {
                let mut rng = rand::rng();
                let (mut probed, mut unprobed): (Vec<_>, Vec<_>) =
                    candidates.into_iter().partition(|(_, rtt)| rtt.is_some());
                let mut shuffled = Vec::with_capacity(probed.len() + unprobed.len());
                let fastest_rtt = probed
                    .iter()
                    .filter_map(|(_, rtt)| *rtt)
                    .min()
                    .unwrap_or(1)
                    .max(1);
                while !probed.is_empty() {
                    let total_weight: u64 = probed
                        .iter()
                        .map(|(_, rtt)| rtt_weight(fastest_rtt, rtt.unwrap_or(fastest_rtt)))
                        .sum();
                    let mut draw = rng.random_range(0..total_weight);
                    let index = probed
                        .iter()
                        .position(|(_, rtt)| {
                            let weight = rtt_weight(fastest_rtt, rtt.unwrap_or(fastest_rtt));
                            if draw < weight {
                                true
                            } else {
                                draw -= weight;
                                false
                            }
                        })
                        .unwrap_or(0);
                    shuffled.push(probed.remove(index));
                }
                while !unprobed.is_empty() {
                    let index = rng.random_range(0..unprobed.len());
                    shuffled.push(unprobed.remove(index));
                }
                candidates = shuffled;
            }
        }

        candidates.into_iter().map(|(peer, _)| peer).collect()
    }

    fn recent_rtt_ms(&self, node_id: &str) -> Option<u32> {
        self.rtt_ms
            .get(&node_id.to_ascii_lowercase())
            .filter(|probe| probe.probed_at.elapsed() <= PEER_PROBE_MAX_AGE)
            .map(|probe| probe.rtt_ms)
    }

    /// Consume one hop from the current route and add the selected node. This
    /// both keeps the hop limit fixed per flow and prevents route loops.
    pub fn route_via_peer(&self, route: &MeshRoute, peer_id: &str) -> Option<MeshRoute> {
        if route.remaining_hops <= 1
            || route.remaining_hops > MAX_MESH_HOPS
            || route.visited.len() >= MAX_MESH_HOPS as usize
            || route
                .visited
                .iter()
                .any(|visited| visited.eq_ignore_ascii_case(peer_id))
        {
            return None;
        }

        let mut next = route.clone();
        next.remaining_hops -= 1;
        next.visited.push(peer_id.to_owned());
        Some(next)
    }

    pub fn auth_token_for_route(&self, route: &MeshRoute) -> String {
        let route_size = route.remaining_hops as usize + route.visited.len().saturating_sub(1);
        if route_size == 2 {
            // The ingress has already connected directly to the chosen egress,
            // so no route claim is needed on this final hop. Keep the original
            // auth shape for compatibility with nodes that predate mesh2/mesh3.
            return self.auth_token();
        }
        if let Some(egress_node_id) = &route.egress_node_id {
            return format!(
                "mesh3:{}:{}:{}:{}:{}:{}",
                self.local_node_id,
                self.local_node_secret,
                route.remaining_hops,
                route.selection.as_wire_value(),
                egress_node_id,
                route.visited.join(",")
            );
        }
        format!(
            "mesh2:{}:{}:{}:{}:{}",
            self.local_node_id,
            self.local_node_secret,
            route.remaining_hops,
            route.selection.as_wire_value(),
            route.visited.join(",")
        )
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Open one logical flow over a pooled authenticated connection to `peer`.
    /// The pool key fingerprints both the peer identity and encrypted route
    /// claim, keeping each flow on its selected path while reusing handshakes.
    pub(crate) async fn connect_peer_stream(
        &self,
        peer: &MeshPeer,
        auth_token: &str,
        target: &str,
        is_udp: bool,
        cancel: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<(Arc<MeshPeerSession>, u32, mpsc::Receiver<Bytes>), AppError> {
        let session = self.peer_session(peer, auth_token, cancel).await?;
        let (stream_id, receiver) = session.open_stream(target, is_udp, cancel).await?;
        Ok((session, stream_id, receiver))
    }

    pub(crate) async fn connect_onion_stream(
        &self,
        peer: &MeshPeer,
        capsule: &[u8],
        is_udp: bool,
        cancel: Option<&CancellationToken>,
        avoid_stream_id: Option<u32>,
    ) -> Result<(Arc<MeshPeerSession>, u32, mpsc::Receiver<Bytes>), AppError> {
        let auth_token = self.onion_auth_token();
        let session = self.peer_session(peer, &auth_token, cancel).await?;
        let (stream_id, receiver) = session
            .open_onion_stream(capsule, is_udp, cancel, avoid_stream_id)
            .await?;
        Ok((session, stream_id, receiver))
    }

    async fn peer_session(
        &self,
        peer: &MeshPeer,
        auth_token: &str,
        cancel: Option<&CancellationToken>,
    ) -> Result<Arc<MeshPeerSession>, AppError> {
        let key = PeerSessionKey {
            node_id: peer.node_id.to_ascii_lowercase(),
            peer_fingerprint: peer_fingerprint(peer),
            auth_fingerprint: sha256(auth_token.as_bytes()),
        };
        let slot = {
            let mut sessions = self.peer_sessions.lock().await;
            trim_peer_sessions(&mut sessions);
            if let Some(slot) = sessions.get(&key) {
                slot.clone()
            } else if sessions.len() < MAX_CACHED_PEER_SESSIONS {
                let slot = Arc::new(PeerSessionSlot::new());
                sessions.insert(key.clone(), slot.clone());
                slot
            } else {
                // Keep the cache bounded under route churn. Active streams hold
                // this temporary slot/session until they finish; later flows
                // can still use the normal fallback path without growing the
                // long-lived pool.
                Arc::new(PeerSessionSlot::new())
            }
        };

        let _establish_guard = slot.establish_lock.lock().await;
        let existing = slot.session.lock().unwrap().clone();
        let (session, reused) =
            if let Some(session) = existing.filter(|session| session.is_usable()) {
                (session, true)
            } else {
                let create_session =
                    ClientHandler::connect_mesh_session(peer, auth_token, self.mesh_quic_port);
                let session = if let Some(cancel) = cancel {
                    let result = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Mesh session cancelled",
                                "The application flow closed during peer setup",
                            ));
                        }
                        result = create_session => result,
                    };
                    Arc::new(result?)
                } else {
                    Arc::new(create_session.await?)
                };
                *slot.session.lock().unwrap() = Some(session.clone());
                (session, false)
            };
        drop(_establish_guard);

        if reused {
            metrics::counter!("netrunner_mesh_peer_sessions_reused_total").increment(1);
        }
        Ok(session)
    }

    /// Open a destination stream over the route configured on this node.
    /// Each hop authenticates this node through the control plane before
    /// accepting the flow.
    pub async fn connect_stream(&self, target: &str, is_udp: bool) -> Result<MeshTunnel, AppError> {
        let route = self.initial_route().ok_or_else(|| {
            AppError::new(
                ERR_INFRA_TIMEOUT,
                "Mesh routing disabled",
                "Direct output is configured for this node",
            )
        })?;
        let Some(mut route) = self.route_for_flow(&route).await else {
            metrics::counter!("netrunner_mesh_route_selection_failures_total").increment(1);
            return Err(AppError::new(
                ERR_INFRA_TIMEOUT,
                "Mesh egress unavailable",
                "No eligible healthy egress path is available",
            ));
        };
        let mut failed_egress_ids = Vec::new();
        loop {
            if let Some(egress_id) = route.egress_node_id.as_ref() {
                if !failed_egress_ids
                    .iter()
                    .any(|failed: &String| failed.eq_ignore_ascii_case(egress_id))
                {
                    failed_egress_ids.push(egress_id.clone());
                }
            }
            let peers = self.peers_for_route(&route).await;
            for peer in peers {
                let Some(next_route) = self.route_via_peer(&route, &peer.node_id) else {
                    continue;
                };
                let auth_token = self.auth_token_for_route(&next_route);
                match self
                    .connect_peer_stream(&peer, &auth_token, target, is_udp, None)
                    .await
                {
                    Ok((session, stream_id, rx)) => {
                        metrics::counter!("netrunner_mesh_egress_streams_total").increment(1);
                        return Ok(MeshTunnel {
                            sender: MeshTunnelSender {
                                muxer: session.muxer.clone(),
                                stream_id,
                                is_udp,
                            },
                            receiver: rx,
                            peer_session: session,
                            closed: false,
                        });
                    }
                    Err(_) => {
                        metrics::counter!("netrunner_mesh_egress_connect_failures_total")
                            .increment(1);
                    }
                }
            }
            let Some(retry_route) = self
                .retry_with_next_egress(&route, &failed_egress_ids)
                .await
            else {
                break;
            };
            if retry_route.remaining_hops != route.remaining_hops {
                failed_egress_ids.clear();
            }
            route = retry_route;
        }

        Err(AppError::new(
            ERR_INFRA_TIMEOUT,
            "Mesh egress unavailable",
            "No reachable mesh peer accepted the connection",
        ))
    }
}

async fn run_mix_scheduler(mut receiver: mpsc::Receiver<MixPacket>) {
    let lane_tails: Arc<Mutex<HashMap<String, (u64, oneshot::Receiver<()>)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let in_flight_packets = Arc::new(Semaphore::new(4096));
    let mut sequence = 0u64;
    while let Some(first) = receiver.recv().await {
        let deadline = tokio::time::Instant::now() + MIX_BATCH_WINDOW;
        let mut batch = vec![first];
        while batch.len() < MIX_BATCH_MAX_PACKETS {
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(packet)) => batch.push(packet),
                Ok(None) | Err(_) => break,
            }
        }

        // Queue packets by their actual outbound lane. Flows sharing one peer
        // QUIC session are mixed together; different peer sessions stay
        // independent so congestion on one relay cannot stall the others.
        let mut lanes: HashMap<String, Vec<MixPacket>> = HashMap::new();
        let mut lane_order = Vec::new();
        for packet in batch {
            if packet.cancel.is_cancelled() {
                continue;
            }
            let lane_key = mix_lane_key(&packet);
            match lanes.entry(lane_key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    lane_order.push(entry.key().clone());
                    entry.insert(vec![packet]);
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().push(packet);
                }
            }
        }

        for lane_key in lane_order {
            let Some(packets) = lanes.remove(&lane_key) else {
                continue;
            };
            let (schedule, flow_count) = interleave_mix_batch(packets);
            metrics::histogram!("netrunner_mix_batch_packets").record(schedule.len() as f64);
            metrics::histogram!("netrunner_mix_batch_flows").record(flow_count as f64);
            if schedule.is_empty() {
                continue;
            }

            // Task count tracks active outbound lanes, not packet count. Each
            // lane worker submits packets in the randomized schedule; the
            // packet's target and stream id travel with it unchanged.
            let mut permits = Vec::with_capacity(schedule.len());
            for _ in 0..schedule.len() {
                let Ok(permit) = in_flight_packets.clone().acquire_owned().await else {
                    return;
                };
                permits.push(permit);
            }
            sequence = sequence.wrapping_add(1);
            let this_sequence = sequence;
            let (done_tx, done_rx) = oneshot::channel();
            let previous = {
                let mut tails = lane_tails.lock().await;
                let previous = tails.remove(&lane_key).map(|(_, receiver)| receiver);
                tails.insert(lane_key.clone(), (this_sequence, done_rx));
                previous
            };
            let tails = lane_tails.clone();
            tokio::spawn(async move {
                if let Some(previous) = previous {
                    let _ = previous.await;
                }
                for (packet, permit) in schedule.into_iter().zip(permits) {
                    if !packet.cancel.is_cancelled() {
                        let failed = match packet.target {
                            MixTarget::Tunnel(muxer) => {
                                muxer.is_fatal()
                                    || muxer
                                        .send_data_safe(
                                            packet.stream_id,
                                            packet.payload,
                                            packet.is_udp,
                                        )
                                        .await
                                        .is_err()
                            }
                            MixTarget::Local(target) => target.send(packet.payload).await.is_err(),
                        };
                        if failed {
                            metrics::counter!("netrunner_mix_packet_drops_total").increment(1);
                        }
                    }
                    drop(permit);
                    if flow_count > 1 {
                        tokio::task::yield_now().await;
                    }
                }
                let _ = done_tx.send(());
                let mut tails = tails.lock().await;
                if tails
                    .get(&lane_key)
                    .is_some_and(|(current_sequence, _)| *current_sequence == this_sequence)
                {
                    tails.remove(&lane_key);
                }
            });
        }
    }
}

fn mix_lane_key(packet: &MixPacket) -> String {
    match &packet.target {
        MixTarget::Tunnel(muxer) => format!("peer:{}", muxer.session_id()),
        // Public Internet sockets are already separate destinations at the
        // exit. Keep their backpressure isolated instead of coupling unrelated
        // sites through one local socket writer.
        MixTarget::Local(_) => format!("local:{}", packet.flow_id),
    }
}

/// Randomly interleave packets across flows without changing packet contents,
/// routing target, stream id, or order within an individual flow.
fn interleave_mix_batch(batch: Vec<MixPacket>) -> (Vec<MixPacket>, usize) {
    let mut groups: HashMap<String, VecDeque<MixPacket>> = HashMap::new();
    for packet in batch {
        if packet.cancel.is_cancelled() {
            continue;
        }
        groups
            .entry(packet.flow_id.clone())
            .or_default()
            .push_back(packet);
    }

    let flow_count = groups.len();
    let mut active_flows: Vec<_> = groups.keys().cloned().collect();
    let mut schedule = Vec::with_capacity(groups.values().map(VecDeque::len).sum());
    let mut rng = rand::rng();

    while !active_flows.is_empty() {
        // Shuffle each round independently. A flow with a large burst cannot
        // monopolize the batch while short flows wait behind it.
        for index in (1..active_flows.len()).rev() {
            let swap_with = rng.random_range(0..=index);
            active_flows.swap(index, swap_with);
        }

        let mut next_round = Vec::with_capacity(active_flows.len());
        for flow_id in active_flows.drain(..) {
            let Some(queue) = groups.get_mut(&flow_id) else {
                continue;
            };
            if let Some(packet) = queue.pop_front() {
                schedule.push(packet);
            }
            if !queue.is_empty() {
                next_round.push(flow_id);
            }
        }
        active_flows = next_round;
    }

    (schedule, flow_count)
}

fn sha256(value: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(value).into()
}

/// Fingerprint the address and credentials without retaining or displaying the
/// peer secret in the session-pool key.
fn peer_fingerprint(peer: &MeshPeer) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    for value in [
        peer.node_id.as_bytes(),
        peer.host.as_bytes(),
        peer.decoy_sni.as_bytes(),
        peer.nrxp_secret.as_bytes(),
        peer.nrxp_static_public.as_bytes(),
    ] {
        digest.update(value);
        digest.update([0]);
    }
    digest.update(peer.port.to_be_bytes());
    digest.finalize().into()
}

fn trim_peer_sessions(sessions: &mut HashMap<PeerSessionKey, Arc<PeerSessionSlot>>) {
    let now_ms = mesh_process_uptime_ms();
    let idle_retention_ms = IDLE_PEER_SESSION_RETENTION.as_millis() as u64;
    sessions.retain(|_, slot| {
        let session = slot.session.lock().ok().and_then(|entry| entry.clone());
        match session {
            Some(session) => {
                session.is_usable()
                    && (!session.is_idle()
                        || now_ms.saturating_sub(session.last_used_ms()) <= idle_retention_ms)
            }
            None => true,
        }
    });

    while sessions.len() > MAX_CACHED_PEER_SESSIONS {
        let oldest_idle = sessions
            .iter()
            .filter_map(|(key, slot)| {
                let session = slot.session.lock().ok().and_then(|entry| entry.clone())?;
                session
                    .is_idle()
                    .then(|| (key.clone(), session.last_used_ms()))
            })
            .min_by_key(|(_, last_used)| *last_used)
            .map(|(key, _)| key);
        let Some(key) = oldest_idle else {
            break;
        };
        sessions.remove(&key);
    }
}

fn record_route_hops(route: &MeshRoute) {
    let total_hops = route
        .remaining_hops
        .saturating_add(route.visited.len().saturating_sub(1) as u8);
    metrics::histogram!("netrunner_mesh_selected_route_hops").record(f64::from(total_hops));
}

/// Prefer lower-latency peers without letting a very fast peer monopolize
/// route selection. The square-root score and 4:1 cap make RTT a preference,
/// not a near-deterministic selector as inverse-RTT weights were.
fn rtt_weight(fastest_rtt_ms: u32, candidate_rtt_ms: u32) -> u64 {
    let ratio = (f64::from(fastest_rtt_ms.max(1)) / f64::from(candidate_rtt_ms.max(1))).sqrt();
    (ratio * 1_000.0).round().clamp(250.0, 1_000.0) as u64
}

/// Build a weighted random permutation of unique egress IPs. The queue drains
/// completely before another permutation is made, preserving RTT preference
/// while guaranteeing that a stable healthy pool rotates through each IP.
fn weighted_egress_order(by_address: HashMap<String, (MeshPeer, u32)>) -> Vec<(MeshPeer, String)> {
    let mut candidates: Vec<_> = by_address
        .into_iter()
        .map(|(address, (peer, rtt))| (peer, rtt, address))
        .collect();
    let Some(fastest_rtt) = candidates.iter().map(|(_, rtt, _)| *rtt).min() else {
        return Vec::new();
    };
    let fastest_rtt = fastest_rtt.max(1);
    let mut order = Vec::with_capacity(candidates.len());
    let mut rng = rand::rng();

    while !candidates.is_empty() {
        let total_weight: u64 = candidates
            .iter()
            .map(|(_, rtt, _)| rtt_weight(fastest_rtt, *rtt))
            .sum();
        let mut draw = rng.random_range(0..total_weight);
        let index = candidates
            .iter()
            .position(|(_, rtt, _)| {
                let weight = rtt_weight(fastest_rtt, *rtt);
                if draw < weight {
                    true
                } else {
                    draw -= weight;
                    false
                }
            })
            .unwrap_or(0);
        let (peer, _, address) = candidates.remove(index);
        order.push((peer, address));
    }

    order
}

/// One logical TCP or UDP flow carried by a direct NRXP leg to a mesh egress.
pub struct MeshTunnel {
    sender: MeshTunnelSender,
    receiver: mpsc::Receiver<Bytes>,
    peer_session: Arc<MeshPeerSession>,
    closed: bool,
}

impl MeshTunnel {
    pub fn sender(&self) -> MeshTunnelSender {
        self.sender.clone()
    }

    pub async fn recv(&mut self) -> Option<Bytes> {
        self.receiver.recv().await
    }

    pub async fn close(mut self) {
        self.sender.close().await;
        self.closed = true;
    }
}

impl Drop for MeshTunnel {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let muxer = self.peer_session.muxer.clone();
        let stream_id = self.sender.stream_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = muxer
                    .send_control(stream_id, FrameType::Close, Bytes::new())
                    .await;
                muxer.remove_stream(stream_id);
            });
        } else {
            self.peer_session.muxer.remove_stream(stream_id);
        }
    }
}

#[derive(Clone)]
pub struct MeshTunnelSender {
    muxer: Arc<Muxer>,
    stream_id: u32,
    is_udp: bool,
}

impl MeshTunnelSender {
    pub async fn send(&self, data: Bytes) -> Result<(), AppError> {
        self.muxer
            .send_data_safe(self.stream_id, data, self.is_udp)
            .await
    }

    pub async fn close(&self) {
        let _ = self
            .muxer
            .send_control(self.stream_id, FrameType::Close, Bytes::new())
            .await;
        self.muxer.remove_stream(self.stream_id);
    }
}

impl std::fmt::Debug for NodeMesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeMesh")
            .field("local_node_id", &self.local_node_id)
            .field("peer_count", &"dynamic")
            .finish_non_exhaustive()
    }
}

pub type SharedNodeMesh = Arc<NodeMesh>;

#[cfg(test)]
mod tests {
    use super::{
        interleave_mix_batch, run_mix_scheduler, MeshPeer, MeshRoute, MeshRouteSelection,
        MixPacket, MixTarget, NodeMesh, PeerProbe, PEER_PROBE_MAX_AGE,
    };
    use hpke::{kem::X25519HkdfSha256, Kem as KemTrait, Serializable};
    use std::{
        collections::HashSet,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use tokio_util::sync::CancellationToken;

    fn peer(node_id: &str, host: &str, port: u16) -> MeshPeer {
        MeshPeer {
            node_id: node_id.into(),
            host: host.into(),
            port,
            decoy_sni: "www.debian.org".into(),
            nrxp_secret: format!("secret-{node_id}"),
            nrxp_static_public: format!("public-{node_id}"),
        }
    }

    async fn mesh_with_healthy_peers(max_hops: u8, peers: Vec<MeshPeer>) -> NodeMesh {
        let mesh = NodeMesh::with_max_hops("ingress".into(), "node-secret".into(), max_hops);
        mesh.update_peers(peers).await;
        for peer in mesh.peers.read().await.iter() {
            mesh.rtt_ms.insert(
                peer.node_id.to_ascii_lowercase(),
                PeerProbe {
                    rtt_ms: 30,
                    probed_at: Instant::now(),
                    consecutive_failures: 0,
                },
            );
        }
        mesh
    }

    #[tokio::test]
    async fn strong_privacy_mix_scheduler_preserves_flow_order_across_batches() {
        let (mix_tx, mix_rx) = tokio::sync::mpsc::channel(8);
        let (local_tx, mut local_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(run_mix_scheduler(mix_rx));
        let cancel = CancellationToken::new();

        for value in [1u8, 2] {
            mix_tx
                .send(MixPacket {
                    flow_id: "flow-a".into(),
                    target: MixTarget::Local(local_tx.clone()),
                    stream_id: 0,
                    payload: bytes::Bytes::from(vec![value]),
                    is_udp: false,
                    cancel: cancel.clone(),
                })
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        mix_tx
            .send(MixPacket {
                flow_id: "flow-a".into(),
                target: MixTarget::Local(local_tx),
                stream_id: 0,
                payload: bytes::Bytes::from_static(&[3]),
                is_udp: false,
                cancel,
            })
            .await
            .unwrap();

        for expected in [1u8, 2, 3] {
            let payload = tokio::time::timeout(Duration::from_secs(2), local_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload.as_ref(), &[expected]);
        }
    }

    #[test]
    fn strong_privacy_batch_interleaves_flows_without_changing_routes_or_order() {
        let (youtube_tx, _youtube_rx) = tokio::sync::mpsc::channel(32);
        let (other_tx, _other_rx) = tokio::sync::mpsc::channel(32);
        let cancel = CancellationToken::new();
        let mut batch = Vec::new();
        for sequence in 0..16u8 {
            batch.push(MixPacket {
                flow_id: "youtube-flow".into(),
                target: MixTarget::Local(youtube_tx.clone()),
                stream_id: 101,
                payload: bytes::Bytes::from(vec![b'Y', sequence]),
                is_udp: true,
                cancel: cancel.clone(),
            });
            batch.push(MixPacket {
                flow_id: "other-flow".into(),
                target: MixTarget::Local(other_tx.clone()),
                stream_id: 202,
                payload: bytes::Bytes::from(vec![b'O', sequence]),
                is_udp: false,
                cancel: cancel.clone(),
            });
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        batch.push(MixPacket {
            flow_id: "cancelled-flow".into(),
            target: MixTarget::Local(other_tx.clone()),
            stream_id: 303,
            payload: bytes::Bytes::from_static(b"X"),
            is_udp: false,
            cancel: cancelled,
        });

        let (schedule, flow_count) = interleave_mix_batch(batch);
        assert_eq!(flow_count, 2);
        assert_eq!(schedule.len(), 32);

        let mut youtube_sequences = Vec::new();
        let mut other_sequences = Vec::new();
        for round in schedule.chunks_exact(2) {
            assert_ne!(round[0].flow_id, round[1].flow_id);
            for packet in round {
                let tag = packet.payload[0];
                let sequence = packet.payload[1];
                match tag {
                    b'Y' => {
                        assert_eq!(packet.flow_id, "youtube-flow");
                        assert_eq!(packet.stream_id, 101);
                        assert!(packet.is_udp);
                        assert!(matches!(
                            &packet.target,
                            MixTarget::Local(target) if target.same_channel(&youtube_tx)
                        ));
                        youtube_sequences.push(sequence);
                    }
                    b'O' => {
                        assert_eq!(packet.flow_id, "other-flow");
                        assert_eq!(packet.stream_id, 202);
                        assert!(!packet.is_udp);
                        assert!(matches!(
                            &packet.target,
                            MixTarget::Local(target) if target.same_channel(&other_tx)
                        ));
                        other_sequences.push(sequence);
                    }
                    _ => panic!("unexpected packet payload"),
                }
            }
        }
        assert_eq!(youtube_sequences, (0..16).collect::<Vec<_>>());
        assert_eq!(other_sequences, (0..16).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn strong_privacy_scheduler_keeps_packets_on_their_original_targets() {
        let (mix_tx, mix_rx) = tokio::sync::mpsc::channel(32);
        let (youtube_tx, mut youtube_rx) = tokio::sync::mpsc::channel(8);
        let (other_tx, mut other_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(run_mix_scheduler(mix_rx));
        let cancel = CancellationToken::new();

        for sequence in 0..4u8 {
            mix_tx
                .send(MixPacket {
                    flow_id: "youtube-flow".into(),
                    target: MixTarget::Local(youtube_tx.clone()),
                    stream_id: 11,
                    payload: bytes::Bytes::from(vec![b'Y', sequence]),
                    is_udp: false,
                    cancel: cancel.clone(),
                })
                .await
                .unwrap();
            mix_tx
                .send(MixPacket {
                    flow_id: "other-flow".into(),
                    target: MixTarget::Local(other_tx.clone()),
                    stream_id: 22,
                    payload: bytes::Bytes::from(vec![b'O', sequence]),
                    is_udp: false,
                    cancel: cancel.clone(),
                })
                .await
                .unwrap();
        }
        drop(mix_tx);

        for sequence in 0..4u8 {
            let youtube = tokio::time::timeout(Duration::from_secs(2), youtube_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let other = tokio::time::timeout(Duration::from_secs(2), other_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(youtube.as_ref(), &[b'Y', sequence]);
            assert_eq!(other.as_ref(), &[b'O', sequence]);
        }
    }

    #[tokio::test]
    async fn strong_privacy_mixer_interleaves_shared_peer_lane_without_crossing_streams() {
        let muxer = std::sync::Arc::new(crate::net::connection::Muxer::new(
            false,
            "shared-peer-session".into(),
        ));
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(32);
        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel(32);
        muxer.add_leg(0, control_tx, data_tx);

        let (mix_tx, mix_rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(run_mix_scheduler(mix_rx));
        let cancel = CancellationToken::new();
        for sequence in 0..8u8 {
            for (flow_id, stream_id, tag) in
                [("youtube-flow", 101, b'Y'), ("other-flow", 202, b'O')]
            {
                mix_tx
                    .send(MixPacket {
                        flow_id: flow_id.into(),
                        target: MixTarget::Tunnel(muxer.clone()),
                        stream_id,
                        payload: bytes::Bytes::from(vec![tag, sequence]),
                        is_udp: false,
                        cancel: cancel.clone(),
                    })
                    .await
                    .unwrap();
            }
        }
        drop(mix_tx);

        let mut youtube_sequences = Vec::new();
        let mut other_sequences = Vec::new();
        let mut observed_streams = Vec::new();
        for _ in 0..16 {
            let message = tokio::time::timeout(Duration::from_secs(2), data_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(message.frame_type, crate::nrxp::FrameType::Data);
            let tag = message.data[0];
            let sequence = message.data[1];
            match (tag, message.stream_id) {
                (b'Y', 101) => youtube_sequences.push(sequence),
                (b'O', 202) => other_sequences.push(sequence),
                _ => panic!("packet was delivered with another flow's stream id"),
            }
            observed_streams.push(message.stream_id);
        }

        assert_eq!(youtube_sequences, (0..8).collect::<Vec<_>>());
        assert_eq!(other_sequences, (0..8).collect::<Vec<_>>());
        for round in observed_streams.chunks_exact(2) {
            assert_ne!(round[0], round[1]);
        }
    }

    #[tokio::test]
    async fn peer_directory_excludes_self_invalid_entries_and_duplicates() {
        let mesh = NodeMesh::new("ingress".into(), "node-secret".into());
        mesh.update_peers(vec![
            peer("INGRESS", "192.0.2.1", 443),
            peer("peer-a", "192.0.2.2", 443),
            peer("peer-a", "192.0.2.3", 443),
            peer("peer-b", "192.0.2.2", 443),
            peer("peer-c", "   ", 443),
            peer("peer-d", "192.0.2.4", 0),
        ])
        .await;

        let peers = mesh.ordered_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "peer-a");
        assert_ne!(peers[0].node_id, mesh.local_node_id());
    }

    #[tokio::test]
    async fn two_hop_routes_rotate_over_unique_healthy_egress_ips() {
        let mesh = mesh_with_healthy_peers(
            2,
            vec![
                peer("peer-a", "192.0.2.1", 443),
                peer("peer-a-alt", "192.0.2.1", 8443),
                peer("peer-b", "192.0.2.2", 443),
                peer("peer-c", "192.0.2.3", 443),
            ],
        )
        .await;
        let initial = mesh.initial_route().unwrap();
        let mut selected_ips = Vec::new();

        for _ in 0..3 {
            let flow = mesh.route_for_flow(&initial).await.unwrap();
            assert_eq!(flow.remaining_hops, 2);
            assert_eq!(flow.selection, MeshRouteSelection::WeightedRandom);
            assert!(!flow
                .egress_node_id
                .as_deref()
                .unwrap()
                .eq_ignore_ascii_case("ingress"));
            let peer = mesh
                .peers_for_route(&flow)
                .await
                .into_iter()
                .find(|peer| Some(peer.node_id.as_str()) == flow.egress_node_id.as_deref())
                .unwrap();
            selected_ips.push(peer.host);
        }

        assert_eq!(selected_ips.iter().collect::<HashSet<_>>().len(), 3);
    }

    #[tokio::test]
    async fn x_hop_route_pins_a_healthy_egress_and_preserves_the_path_claim() {
        let peers = vec![
            peer("peer-a", "192.0.2.1", 443),
            peer("peer-b", "192.0.2.2", 443),
            peer("peer-c", "192.0.2.3", 443),
            peer("peer-d", "192.0.2.4", 443),
        ];
        let mesh = mesh_with_healthy_peers(5, peers.clone()).await;
        let initial = mesh.initial_route().unwrap();
        let flow = mesh.route_for_flow(&initial).await.unwrap();
        assert!((3..=5).contains(&flow.remaining_hops));
        let egress = flow.egress_node_id.as_deref().unwrap();
        assert!(peers.iter().any(|peer| peer.node_id == egress));

        let relay = peers.iter().find(|peer| peer.node_id != egress).unwrap();
        let next = mesh.route_via_peer(&flow, &relay.node_id).unwrap();
        assert_eq!(next.remaining_hops, flow.remaining_hops - 1);
        assert_eq!(
            next.visited,
            vec!["ingress".to_owned(), relay.node_id.clone()]
        );
        assert_eq!(next.egress_node_id.as_deref(), Some(egress));

        let token = mesh.auth_token_for_route(&next);
        let parsed = crate::net::parse_mesh_auth_token(&token).unwrap().unwrap();
        let parsed_route = parsed.route.unwrap();
        assert_eq!(parsed_route.egress_node_id.as_deref(), Some(egress));
        assert_eq!(parsed_route.visited, next.visited);
    }

    #[tokio::test]
    async fn stale_rtt_samples_fall_back_to_a_two_hop_route() {
        let mesh = mesh_with_healthy_peers(2, vec![peer("peer-a", "192.0.2.1", 443)]).await;
        mesh.rtt_ms.insert(
            "peer-a".into(),
            PeerProbe {
                rtt_ms: 30,
                probed_at: Instant::now() - PEER_PROBE_MAX_AGE - Duration::from_secs(1),
                consecutive_failures: 0,
            },
        );

        let route = mesh
            .route_for_flow(&mesh.initial_route().unwrap())
            .await
            .unwrap();
        assert_eq!(route.remaining_hops, 2);
        assert_eq!(route.selection, MeshRouteSelection::Nearest);
        assert!(route.egress_node_id.is_some());
    }

    #[tokio::test]
    async fn onion_route_is_preselected_loop_free_and_hides_the_exit_layer() {
        let mesh = NodeMesh::with_max_hops("ingress".into(), "node-secret".into(), 5);
        let mut peers = Vec::new();
        let mut identities = std::collections::HashMap::new();
        for index in 0..6 {
            let node_id = format!("peer-{index}");
            let (private, public) = X25519HkdfSha256::gen_keypair();
            peers.push(MeshPeer {
                node_id: node_id.clone(),
                host: format!("192.0.2.{}", index + 1),
                port: 443,
                decoy_sni: "www.example.org".into(),
                nrxp_secret: format!("secret-{index}"),
                nrxp_static_public: hex::encode(public.to_bytes().as_slice()),
            });
            identities.insert(
                node_id,
                crate::crypto::LocalIdentity::from_hex(
                    &hex::encode([index as u8 + 1; 32]),
                    &hex::encode(private.to_bytes()),
                    true,
                )
                .unwrap(),
            );
        }
        mesh.update_peers(peers).await;
        for peer in mesh.peers.read().await.iter() {
            mesh.rtt_ms.insert(
                peer.node_id.to_ascii_lowercase(),
                PeerProbe {
                    rtt_ms: 25,
                    probed_at: Instant::now(),
                    consecutive_failures: 0,
                },
            );
        }

        let (mut next_peer, mut capsule) = mesh
            .build_onion_route("example.com:443", true, true, &[])
            .await
            .expect("healthy peers should build an onion path");
        let mut visited = HashSet::from(["ingress".to_owned()]);
        let mut remote_hops = 0;
        loop {
            assert!(visited.insert(next_peer.node_id.to_ascii_lowercase()));
            remote_hops += 1;
            let identity = identities.get(&next_peer.node_id).unwrap();
            let layer =
                super::super::mesh_onion::open_capsule(&next_peer.node_id, identity, &capsule)
                    .unwrap();
            assert!(layer.is_udp);
            assert!(layer.strong_privacy);
            match layer.instruction {
                super::super::mesh_onion::OnionInstruction::Forward {
                    next_peer: following,
                    next_capsule,
                } => {
                    assert!(!following.node_id.eq_ignore_ascii_case("ingress"));
                    next_peer = following;
                    capsule = next_capsule;
                }
                super::super::mesh_onion::OnionInstruction::Exit { target } => {
                    assert_eq!(target, "example.com:443");
                    break;
                }
            }
        }
        assert!((2..=4).contains(&remote_hops));
    }

    #[tokio::test]
    async fn onion_capsules_are_single_use_and_expire() {
        let private = [7u8; 32];
        let identity = crate::crypto::LocalIdentity::from_hex(
            &hex::encode([8u8; 32]),
            &hex::encode(private),
            true,
        )
        .unwrap();
        let peer = MeshPeer {
            node_id: "local".into(),
            host: "192.0.2.1".into(),
            port: 443,
            decoy_sni: "www.example.org".into(),
            nrxp_secret: "secret".into(),
            nrxp_static_public: identity.public_key_hex(),
        };
        let mesh = NodeMesh::new("local".into(), "node-secret".into());
        mesh.set_onion_identity(identity);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let capsule = super::super::mesh_onion::seal_capsule(
            &peer,
            true,
            false,
            1,
            now + 30,
            [0x42; 16],
            super::super::mesh_onion::OnionInstruction::Exit {
                target: "example.com:443".into(),
            },
        )
        .unwrap();
        assert!(mesh.open_onion_capsule(&capsule).await.is_ok());
        assert!(mesh.open_onion_capsule(&capsule).await.is_err());

        let expired = super::super::mesh_onion::seal_capsule(
            &peer,
            false,
            false,
            1,
            now.saturating_sub(1),
            [0x43; 16],
            super::super::mesh_onion::OnionInstruction::Exit {
                target: "example.com:443".into(),
            },
        )
        .unwrap();
        assert!(mesh.open_onion_capsule(&expired).await.is_err());
    }

    #[tokio::test]
    async fn retry_selects_a_different_egress_and_route_extension_rejects_loops() {
        let mesh = mesh_with_healthy_peers(
            3,
            vec![
                peer("peer-a", "192.0.2.1", 443),
                peer("peer-b", "192.0.2.2", 443),
            ],
        )
        .await;
        let route = mesh
            .route_for_flow(&mesh.initial_route().unwrap())
            .await
            .unwrap();
        let failed = route.egress_node_id.clone().unwrap();
        let retry = mesh
            .retry_with_next_egress(&route, std::slice::from_ref(&failed))
            .await
            .unwrap();
        assert_ne!(retry.egress_node_id.as_deref(), Some(failed.as_str()));

        let direct = MeshRoute {
            remaining_hops: 2,
            selection: MeshRouteSelection::WeightedRandom,
            egress_node_id: Some("peer-a".into()),
            visited: vec!["ingress".into()],
        };
        let next = mesh.route_via_peer(&direct, "peer-a").unwrap();
        assert_eq!(next.remaining_hops, 1);
        assert!(mesh.route_via_peer(&next, "peer-a").is_none());
        assert!(mesh.route_via_peer(&next, "ingress").is_none());
    }
}
