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
use tokio::{
    net::TcpStream,
    sync::{mpsc, Mutex, RwLock},
    task::JoinHandle,
    time::timeout,
};

use super::connection::{ClientHandler, Muxer};
use super::{MeshPeer, MeshRoute, MeshRouteSelection, MAX_MESH_HOPS};
use crate::nrxp::FrameType;

const PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PEER_PROBE_MAX_AGE: Duration = Duration::from_secs(45);

#[derive(Clone, Copy)]
struct PeerProbe {
    rtt_ms: u32,
    probed_at: std::time::Instant,
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
    peers: RwLock<Vec<MeshPeer>>,
    rtt_ms: DashMap<String, PeerProbe>,
    egress_rotation: Mutex<EgressRotation>,
}

impl NodeMesh {
    pub fn new(local_node_id: String, local_node_secret: String) -> Self {
        Self::with_max_hops(local_node_id, local_node_secret, 2)
    }

    pub fn with_max_hops(local_node_id: String, local_node_secret: String, max_hops: u8) -> Self {
        Self {
            local_node_id,
            local_node_secret,
            max_hops: max_hops.clamp(1, MAX_MESH_HOPS),
            peers: RwLock::new(Vec::new()),
            rtt_ms: DashMap::new(),
            egress_rotation: Mutex::new(EgressRotation::default()),
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

        let active_ids: std::collections::HashSet<_> = peers
            .iter()
            .map(|peer| peer.node_id.to_ascii_lowercase())
            .collect();
        self.rtt_ms
            .retain(|node_id, _| active_ids.contains(node_id));
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
                        },
                    );
                } else {
                    rtt_ms.remove(&peer.node_id.to_ascii_lowercase());
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

    /// Select a healthy egress and path budget once per application flow.
    /// Intermediates preserve both choices from the encrypted mesh claim.
    pub async fn route_for_flow(&self, route: &MeshRoute) -> Option<MeshRoute> {
        if route.selection != MeshRouteSelection::WeightedRandom
            || route.visited.len() != 1
            || route.egress_node_id.is_some()
        {
            return Some(route.clone());
        }

        // Pick one healthy egress for every flow, including the ordinary
        // two-hop route. For max_hops > 2, also cap the randomized path length
        // to the current healthy directory so a small fleet cannot select an
        // impossible chain.
        let candidates = self.peers_for_route(route).await;
        if route.remaining_hops == 2 {
            let mut flow_route = route.clone();
            flow_route.egress_node_id = Some(
                self.next_healthy_egress(candidates, &[])
                    .await?
                    .node_id,
            );
            return Some(flow_route);
        }

        let max_available_hops = candidates
            .len()
            .saturating_add(1)
            .min(usize::from(route.remaining_hops));
        if max_available_hops < 3 {
            return None;
        }

        let mut flow_route = route.clone();
        flow_route.remaining_hops = rand::rng().random_range(3..=max_available_hops as u8);
        flow_route.egress_node_id = Some(
            self.next_healthy_egress(candidates, &[])
                .await?
                .node_id,
        );
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
        if route.selection != MeshRouteSelection::WeightedRandom
            || route.visited.len() != 1
            || route.egress_node_id.is_none()
            || route.remaining_hops < 2
        {
            return None;
        }

        let mut candidates_route = route.clone();
        candidates_route.egress_node_id = None;
        let candidates = self.peers_for_route(&candidates_route).await;
        let (next_egress, shorten_chain) = match self
            .next_healthy_egress(candidates.clone(), failed_egress_ids)
            .await
        {
            Some(peer) => (peer, false),
            None if route.remaining_hops > 2 => {
                (self.next_healthy_egress(candidates, &[]).await?, true)
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

    /// Rotate through a randomized, RTT-weighted permutation of healthy public
    /// peer addresses. Each distinct address is used once before the bag is
    /// reshuffled, so a fast peer cannot be selected repeatedly by chance.
    async fn next_healthy_egress(
        &self,
        peers: Vec<MeshPeer>,
        excluded_node_ids: &[String],
    ) -> Option<MeshPeer> {
        let mut by_address = HashMap::<String, (MeshPeer, u32)>::new();
        let mut candidate_signature = Vec::with_capacity(peers.len());
        for peer in peers {
            let Some(rtt) = self.recent_rtt_ms(&peer.node_id) else {
                continue;
            };
            let address_key = peer.host.trim().to_ascii_lowercase();
            candidate_signature.push(format!(
                "{address_key}={}",
                peer.node_id.to_ascii_lowercase()
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

    /// Return eligible next hops for a route. Weighted routes only use peers
    /// that passed the latest reachability probe; every mode excludes the
    /// originating ingress and all already visited nodes.
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
            .filter_map(|peer| {
                let rtt = self.recent_rtt_ms(&peer.node_id);
                if route.selection == MeshRouteSelection::WeightedRandom && rtt.is_none() {
                    return None;
                }
                Some((peer, rtt))
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
                let mut shuffled = Vec::with_capacity(candidates.len());
                let fastest_rtt = candidates
                    .iter()
                    .filter_map(|(_, rtt)| *rtt)
                    .min()
                    .unwrap_or(1)
                    .max(1);
                while !candidates.is_empty() {
                    let total_weight: u64 = candidates
                        .iter()
                        .map(|(_, rtt)| rtt_weight(fastest_rtt, rtt.unwrap_or(fastest_rtt)))
                        .sum();
                    let mut draw = rng.random_range(0..total_weight);
                    let index = candidates
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
                    shuffled.push(candidates.remove(index));
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
        let mut route = self.route_for_flow(&route).await.ok_or_else(|| {
            AppError::new(
                ERR_INFRA_TIMEOUT,
                "Mesh egress unavailable",
                "No eligible healthy egress path is available",
            )
        })?;
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
                match ClientHandler::connect_mesh_stream(&peer, &auth_token, target, is_udp).await {
                    Ok((muxer, rx, engine_task)) => {
                        return Ok(MeshTunnel {
                            sender: MeshTunnelSender {
                                muxer: muxer.clone(),
                                stream_id: 1,
                                is_udp,
                            },
                            receiver: rx,
                            muxer,
                            engine_task: Some(engine_task),
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
    muxer: Arc<Muxer>,
    engine_task: Option<JoinHandle<()>>,
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
        self.muxer.remove_stream(self.sender.stream_id);
        self.muxer.shutdown();
        if let Some(task) = self.engine_task.take() {
            task.abort();
        }
    }
}

impl Drop for MeshTunnel {
    fn drop(&mut self) {
        self.muxer.shutdown();
        if let Some(task) = self.engine_task.take() {
            task.abort();
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
        self.muxer.shutdown();
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
