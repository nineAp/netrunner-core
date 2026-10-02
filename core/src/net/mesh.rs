//! Peer directory and latency-aware routing across the node mesh.
//!
//! The control plane supplies peer metadata. This module keeps a short-lived
//! in-memory view and probes peers from this node. Flows select a bounded,
//! loop-free path and carry it through the NRXP mesh legs.

use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{AppError, ERR_INFRA_TIMEOUT};
use rand::RngExt;
use sha2::Digest;
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock, mpsc},
    time::timeout,
};

use super::connection::{ClientHandler, MeshPeerSession, Muxer, mesh_process_uptime_ms};
use super::{MAX_MESH_HOPS, MeshPeer, MeshRoute, MeshRouteSelection};
use crate::nrxp::FrameType;

// Mesh peers may have much higher latency than an app-to-ingress leg. Give a
// TCP reachability probe enough time to cross a slow inter-node path instead
// of misclassifying a working node as unhealthy.
const PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const PEER_PROBE_MAX_AGE: Duration = Duration::from_secs(90);
const PEER_PROBE_FAILURES_TO_EVICT: u8 = 3;
const MAX_CACHED_PEER_SESSIONS: usize = 256;
const IDLE_PEER_SESSION_RETENTION: Duration = Duration::from_secs(300);

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
    egress_rotation: Mutex<EgressRotation>,
    peer_sessions: Mutex<HashMap<PeerSessionKey, Arc<PeerSessionSlot>>>,
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
            egress_rotation: Mutex::new(EgressRotation::default()),
            peer_sessions: Mutex::new(HashMap::new()),
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
                let create_session = ClientHandler::connect_mesh_session(
                    peer,
                    auth_token,
                    self.mesh_quic_port,
                );
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

        let (stream_id, receiver) = session.open_stream(target, is_udp, cancel).await?;
        Ok((session, stream_id, receiver))
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
