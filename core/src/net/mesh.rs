//! Peer directory and latency-aware routing across the node mesh.
//!
//! The control plane supplies peer metadata. This module keeps a short-lived
//! in-memory view and probes peers from this node. Flows select a bounded,
//! loop-free path and carry it through the NRXP mesh legs.

use std::{cmp::Ordering, sync::Arc, time::Duration};

use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{AppError, ERR_INFRA_TIMEOUT};
use rand::RngExt;
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
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

pub struct NodeMesh {
    local_node_id: String,
    local_node_secret: String,
    max_hops: u8,
    peers: RwLock<Vec<MeshPeer>>,
    rtt_ms: DashMap<String, PeerProbe>,
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

    /// A max-hop value of one means direct output. Two preserves the existing
    /// nearest reachable egress behavior. Longer paths use weighted random
    /// selection among peers with a successful recent probe.
    pub fn initial_route(&self) -> Option<MeshRoute> {
        (self.max_hops > 1).then(|| MeshRoute {
            remaining_hops: self.max_hops,
            selection: if self.max_hops == 2 {
                MeshRouteSelection::Nearest
            } else {
                MeshRouteSelection::WeightedRandom
            },
            visited: vec![self.local_node_id.clone()],
        })
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
                while !candidates.is_empty() {
                    let total_weight: u64 = candidates
                        .iter()
                        .map(|(_, rtt)| 1_000_000_u64 / u64::from(rtt.unwrap_or(1).max(1)))
                        .map(|weight| weight.max(1))
                        .sum();
                    let mut draw = rng.random_range(0..total_weight);
                    let index = candidates
                        .iter()
                        .position(|(_, rtt)| {
                            let weight =
                                (1_000_000_u64 / u64::from(rtt.unwrap_or(1).max(1))).max(1);
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
        if route_size == 2 && route.selection == MeshRouteSelection::Nearest {
            // Preserve the original 2-hop auth shape so existing nodes can
            // keep acting as direct egresses during a rolling deployment.
            return self.auth_token();
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
                    // A failed peer must not expose the user's destination.
                    // Try another peer, then fail closed if none is reachable.
                    metrics::counter!("netrunner_mesh_egress_connect_failures_total").increment(1);
                }
            }
        }

        Err(AppError::new(
            ERR_INFRA_TIMEOUT,
            "Mesh egress unavailable",
            "No reachable mesh peer accepted the connection",
        ))
    }
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
