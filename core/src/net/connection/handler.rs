use std::sync::Arc;

use bytes::Bytes;
use netrunner_logger::{debug, error, info, warn};

use crate::{
    net::{
        connection::{
            bridge::{run_tcp_bridge, run_udp_bridge},
            connection::ConnectionRole,
            muxer::Muxer,
        },
        network::NetworkConfig,
    },
    nrxp::{Frame, FrameType},
};

pub(crate) struct StreamHandler {
    muxer: Arc<Muxer>,
    role: ConnectionRole,
}

impl StreamHandler {
    pub(crate) fn new(muxer: Arc<Muxer>, role: ConnectionRole) -> Self {
        Self { muxer, role }
    }

    pub(crate) async fn handle(&self, frame: Frame) {
        let stream_id = frame.header.stream_id;

        info!(
            stream_id,
            "📥 [Tunnel] Received frame: {:?}", frame.header.frame_type
        );

        match frame.header.frame_type {
            FrameType::Connect => self.on_connect(stream_id, frame.payload).await,
            FrameType::UdpConnect => self.on_udp_connect(stream_id, frame.payload).await,
            FrameType::Data => self.on_data(stream_id, frame.payload).await,
            FrameType::UdpData => self.on_udp_data(stream_id, frame.payload).await,
            FrameType::Close => self.on_close(stream_id).await,
            _ => debug!(stream_id, "Unhandled frame type"),
        }
    }
    async fn on_connect(&self, stream_id: u32, payload: Bytes) {
        let target_str = String::from_utf8_lossy(&payload).to_string();

        if self.role == ConnectionRole::Server {
            info!(stream_id, target = %target_str, "🌐 [TCP] Request to establish remote connection");
            let muxer = self.muxer.clone();

            let (v_tx, v_rx) =
                tokio::sync::mpsc::channel(NetworkConfig::global().tcp_stream_capacity);
            muxer.register_stream(stream_id, v_tx);

            tokio::spawn(async move {
                let start = std::time::Instant::now();
                info!(
                    stream_id,
                    "⏳ [TCP Worker] Attempting connection to {}", target_str
                );

                let connect_res = tokio::time::timeout(
                    std::time::Duration::from_secs(7),
                    tokio::net::TcpStream::connect(&target_str),
                )
                .await;

                match connect_res {
                    Ok(Ok(stream)) => {
                        let elapsed = start.elapsed();
                        info!(stream_id, target = %target_str, "✅ [TCP] Established in {:?}. Starting bridge.", elapsed);
                        let (r, w) = stream.into_split();
                        run_tcp_bridge(stream_id, r, w, muxer.clone(), v_rx).await;
                        info!(stream_id, "🔚 [TCP Worker] Bridge task finished");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                    Ok(Err(e)) => {
                        error!(stream_id, target = %target_str, error = %e, "❌ [TCP] Connection failed");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                    Err(_) => {
                        error!(stream_id, target = %target_str, "⏰ [TCP] Connection timeout (DNS or IP unreachable)");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                }
            });
        } else {
            info!(stream_id, "📲 [TCP] Dispatching payload to local stack");
            self.muxer.dispatch_to_local(stream_id, payload);
        }
    }

    async fn on_udp_connect(&self, stream_id: u32, payload: Bytes) {
        let target_str = String::from_utf8_lossy(&payload).to_string();

        if self.role == ConnectionRole::Server {
            info!(stream_id, target = %target_str, "🚀 [UDP] Request to establish remote bridge");
            let muxer = self.muxer.clone();

            let (v_tx, v_rx) =
                tokio::sync::mpsc::channel(NetworkConfig::global().udp_stream_capacity);
            muxer.register_stream(stream_id, v_tx);

            tokio::spawn(async move {
                info!(
                    stream_id,
                    "⏳ [UDP Worker] Binding socket for {}", target_str
                );

                let socket_res = tokio::net::UdpSocket::bind("[::]:0").await;
                let socket = match socket_res {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            stream_id,
                            "⚠️ [UDP] IPv6 bind failed, falling back to IPv4: {}", e
                        );
                        tokio::net::UdpSocket::bind("0.0.0.0:0")
                            .await
                            .expect("UDP bind fail")
                    }
                };

                match socket.connect(&target_str).await {
                    Ok(_) => {
                        let local = socket.local_addr().unwrap();
                        let remote = socket.peer_addr().unwrap();
                        info!(
                            "✅ [UDP {}] Socket ready. Local: {}, Remote: {}. Starting bridge.",
                            stream_id, local, remote
                        );
                        run_udp_bridge(stream_id, socket, muxer, v_rx).await;
                        info!(stream_id, "🔚 [UDP Worker] Bridge task finished");
                    }
                    Err(e) => {
                        error!(stream_id, target = %target_str, error = %e, "❌ [UDP] Target connect failed");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                }
            });
        } else {
            info!(
                stream_id,
                "📲 [UDP] Dispatching connection payload to local stack"
            );
            self.muxer.dispatch_to_local(stream_id, payload);
        }
    }

    async fn on_data(&self, stream_id: u32, payload: Bytes) {
        // Здесь info может быть избыточным при большой нагрузке, но для отладки полезно
        debug!(stream_id, "📦 [TCP Data] Size: {} bytes", payload.len());
        self.muxer.dispatch_to_local(stream_id, payload);
    }

    async fn on_udp_data(&self, stream_id: u32, payload: Bytes) {
        debug!(stream_id, "📦 [UDP Data] Size: {} bytes", payload.len());
        self.muxer.dispatch_to_local(stream_id, payload);
    }

    async fn on_close(&self, stream_id: u32) {
        info!(stream_id, "🏁 [Close] Received close signal for stream");
        self.muxer.remove_stream(stream_id);
    }

    async fn close_stream(muxer: &Muxer, stream_id: u32) {
        info!(
            stream_id,
            "📡 [Control] Sending CLOSE signal to remote peer"
        );
        let _ = muxer.send_control(stream_id, FrameType::Close, Bytes::new());
        muxer.remove_stream(stream_id);
    }
}
