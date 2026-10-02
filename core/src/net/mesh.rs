//! Peer directory and latency ordering for two-hop node routing.
//!
//! The control plane supplies peer metadata. This module keeps a short-lived
//! in-memory view and orders peers by direct TCP reachability from this node;
//! application traffic is opened directly to the selected egress.

use std::{cmp::Ordering, sync::Arc, time::Duration};

use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{AppError, ERR_INFRA_TIMEOUT};
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
    task::JoinHandle,
    time::timeout,
};

use super::connection::{ClientHandler, Muxer};
use super::MeshPeer;
use crate::nrxp::FrameType;

const PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct NodeMesh {
    local_node_id: String,
    local_node_secret: String,
    peers: RwLock<Vec<MeshPeer>>,
    rtt_ms: DashMap<String, u32>,
}

impl NodeMesh {
    pub fn new(local_node_id: String, local_node_secret: String) -> Self {
        Self {
            local_node_id,
            local_node_secret,
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
        let peers: Vec<_> = peers
            .into_iter()
            .filter(|peer| peer.node_id != self.local_node_id)
            .filter(|peer| {
                !peer.host.trim().is_empty()
                    && peer.port != 0
                    && !peer.nrxp_secret.is_empty()
                    && !peer.nrxp_static_public.is_empty()
            })
            .collect();

        let active_ids: std::collections::HashSet<_> =
            peers.iter().map(|peer| peer.node_id.as_str()).collect();
        self.rtt_ms
            .retain(|node_id, _| active_ids.contains(node_id.as_str()));
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
                        peer.node_id,
                        start.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32,
                    );
                } else {
                    rtt_ms.remove(&peer.node_id);
                }
            });
        }

        while probes.join_next().await.is_some() {}
    }

    /// Lowest measured RTT first. Unprobed peers are retained after measured
    /// peers so a fresh node can still join the mesh before its first probe.
    pub async fn ordered_peers(&self) -> Vec<MeshPeer> {
        let mut peers = self.peers.read().await.clone();
        peers.sort_by(|left, right| {
            match (
                self.rtt_ms.get(&left.node_id),
                self.rtt_ms.get(&right.node_id),
            ) {
                (Some(left_rtt), Some(right_rtt)) => left_rtt.cmp(&right_rtt),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => left.node_id.cmp(&right.node_id),
            }
        });
        peers
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Open a destination stream through the lowest-latency reachable peer.
    /// Each peer receives the same user-independent node credential; the
    /// egress validates it with the control plane before accepting the flow.
    pub async fn connect_stream(&self, target: &str, is_udp: bool) -> Result<MeshTunnel, AppError> {
        let auth_token = self.auth_token();
        let peers = self.ordered_peers().await;
        for peer in peers {
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
