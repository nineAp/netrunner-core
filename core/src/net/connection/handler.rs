use bytes::Bytes;
use netrunner_logger::{debug, error, info, trace, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::net::{
    connection::{
        bridge::{run_tcp_bridge, run_udp_bridge},
        muxer::Muxer,
    },
    NetworkConfig,
};
use crate::nrxp::{Frame, FrameType};

pub struct RemoteOpener {
    pub muxer: Arc<Muxer>,
}

impl RemoteOpener {
    pub async fn open_tcp(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let muxer = self.muxer.clone();
        tokio::spawn(async move {
            info!(stream_id, "🌐 [Remote] Connecting to {}", target);
            let start = Instant::now();

            tokio::select! {
                _ = token.cancelled() => {
                    debug!(stream_id, "🔪 Target connection cancelled by Eviction");
                    return;
                }
                connect_res = tokio::time::timeout(Duration::from_secs(7), TcpStream::connect(&target)) => {
                    match connect_res {
                        Ok(Ok(stream)) => {
                            info!(stream_id, "✅ [Remote] Connected in {:?}", start.elapsed());
                            let (r, w) = stream.into_split();

                            // 🔥 Защищаем и сам мост токеном отмены
                            tokio::select! {
                                _ = token.cancelled() => { debug!(stream_id, "🔪 TCP bridge closed by Eviction"); }
                                _ = run_tcp_bridge(stream_id, r, w, muxer.clone(), v_rx) => {}
                            }
                        }
                        _ => {
                            error!(stream_id, "❌ [Remote] Target connection failed: {}", target);
                            let _ = muxer.send_control(stream_id, FrameType::Close, Bytes::new()).await;
                        }
                    }
                }
            }
            muxer.remove_stream(stream_id);
        });
    }

    pub async fn open_udp(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let muxer = self.muxer.clone();
        tokio::spawn(async move {
            info!(stream_id, "🚀 [Remote] Binding UDP for {}", target);
            tokio::select! {
                _ = token.cancelled() => { return; }
                _ = async {
                    let socket = UdpSocket::bind("0.0.0.0:0").await.ok();
                    if let Some(s) = socket {
                        if s.connect(&target).await.is_ok() {
                            run_udp_bridge(stream_id, s, muxer.clone(), v_rx).await;
                        }
                    }
                } => {}
            }
            muxer.remove_stream(stream_id);
        });
    }
}

pub(crate) struct StreamHandler {
    muxer: Arc<Muxer>,
    opener: Option<Arc<RemoteOpener>>,
}

impl StreamHandler {
    pub(crate) fn new(muxer: Arc<Muxer>, opener: Option<Arc<RemoteOpener>>) -> Self {
        Self { muxer, opener }
    }

    pub(crate) async fn handle(&self, frame: Frame) {
        let stream_id = frame.header.stream_id;

        match frame.header.frame_type {
            FrameType::Heartbeat => {
                let payload = frame.payload.as_ref();
                if payload == b"PING" {
                    trace!(stream_id, "🤝 [Tunnel] PING received, replying PONG");
                    let muxer = self.muxer.clone();
                    tokio::spawn(async move {
                        let _ = muxer
                            .send_control(stream_id, FrameType::Heartbeat, Bytes::from("PONG"))
                            .await;
                    });
                } else if payload == b"PONG" {
                    trace!(stream_id, "🤝 [Tunnel] PONG received");
                    self.muxer.dispatch_to_local(stream_id, frame.payload);
                } else {
                    if self.opener.is_some() {
                        trace!(
                            stream_id,
                            "💓 [Server] Standard Heartbeat received, sending reply"
                        );
                        let muxer = self.muxer.clone();
                        tokio::spawn(async move {
                            let _ = muxer
                                .send_control(stream_id, FrameType::Heartbeat, Bytes::new())
                                .await;
                        });
                    } else {
                        trace!(stream_id, "💓 [Client] Standard Heartbeat reply received");
                    }
                }
            }

            FrameType::Connect => {
                self.handle_conn_request(stream_id, frame.payload, false)
                    .await
            }
            FrameType::UdpConnect => {
                self.handle_conn_request(stream_id, frame.payload, true)
                    .await
            }

            FrameType::Data | FrameType::UdpData => {
                // Полностью синхронный вызов
                self.muxer.dispatch_to_local(stream_id, frame.payload);
            }

            FrameType::Close => {
                debug!(stream_id, "🏁 [Tunnel] Peer closed stream");
                self.muxer.remove_stream(stream_id);
            }
        }
    }

    async fn handle_conn_request(&self, stream_id: u32, payload: Bytes, is_udp: bool) {
        let target = String::from_utf8_lossy(&payload).to_string();

        if let Some(opener) = &self.opener {
            let cap = NetworkConfig::global().channel_capacity;
            let (v_tx, v_rx) = mpsc::channel::<Bytes>(cap);

            // 🔥 Собираем токен для мгновенного обрыва связи при Eviction
            let cancel_token = self.muxer.register_stream(stream_id, v_tx);

            if is_udp {
                opener.open_udp(stream_id, target, v_rx, cancel_token).await;
            } else {
                opener.open_tcp(stream_id, target, v_rx, cancel_token).await;
            }
        } else {
            warn!(
                stream_id,
                "⚠️ [Tunnel] Rejected incoming connection to {} (Client mode)", target
            );
            let muxer = self.muxer.clone();
            tokio::spawn(async move {
                let _ = muxer
                    .send_control(stream_id, FrameType::Close, Bytes::new())
                    .await;
            });
        }
    }
}
