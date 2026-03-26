use bytes::Bytes;
use netrunner_logger::{debug, error, info};

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
    muxer: Muxer,
    role: ConnectionRole,
}

impl StreamHandler {
    pub(crate) fn new(muxer: Muxer, role: ConnectionRole) -> Self {
        Self { muxer, role }
    }

    pub(crate) async fn handle(&self, frame: Frame) {
        let stream_id = frame.header.stream_id;

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
        if self.role == ConnectionRole::Server {
            let target_str = String::from_utf8_lossy(&payload).to_string();
            let muxer = self.muxer.clone();

            let (v_tx, v_rx) = tokio::sync::mpsc::channel(NetworkConfig::global().stream_capacity);
            muxer.register_stream(stream_id, v_tx);

            tokio::spawn(async move {
                let start = std::time::Instant::now();
                info!(stream_id, target = %target_str, "Attempting remote TCP connection");

                let connect_timeout = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&target_str),
                )
                .await;

                match connect_timeout {
                    Ok(Ok(stream)) => {
                        let elapsed = start.elapsed();
                        info!(stream_id, target = %target_str, latency_ms = elapsed.as_millis(), "Remote TCP connection established");

                        // Больше никаких ответов (Reply), просто прокидываем байты!
                        let (r, w) = stream.into_split();
                        run_tcp_bridge(stream_id, r, w, muxer, v_rx).await;
                    }
                    Ok(Err(e)) => {
                        error!(stream_id, target = %target_str, error = %e, "TCP connection failed");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                    Err(_) => {
                        error!(stream_id, target = %target_str, "Connection timed out (DNS/TCP)");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                }
            });
        } else {
            self.muxer.dispatch_to_local(stream_id, payload).await;
        }
    }

    async fn on_udp_connect(&self, stream_id: u32, payload: Bytes) {
        if self.role == ConnectionRole::Server {
            let target_str = String::from_utf8_lossy(&payload).to_string();
            let muxer = self.muxer.clone();

            let (v_tx, v_rx) = tokio::sync::mpsc::channel(NetworkConfig::global().stream_capacity);
            muxer.register_stream(stream_id, v_tx);

            tokio::spawn(async move {
                info!(stream_id, target = %target_str, "Attempting remote UDP connection");

                match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        if let Err(e) = socket.connect(&target_str).await {
                            error!(stream_id, target = %target_str, error = %e, "UDP connect failed");
                            Self::close_stream(&muxer, stream_id).await;
                            return;
                        }

                        // Успех - просто начинаем слушать UDP и слать в туннель
                        run_udp_bridge(stream_id, socket, muxer, v_rx).await;
                    }
                    Err(e) => {
                        error!(stream_id, target = %target_str, error = %e, "UDP bind failed");
                        Self::close_stream(&muxer, stream_id).await;
                    }
                }
            });
        } else {
            self.muxer.dispatch_to_local(stream_id, payload).await;
        }
    }

    async fn on_udp_data(&self, stream_id: u32, payload: Bytes) {
        self.muxer.dispatch_to_local(stream_id, payload).await;
    }

    // Вспомогательная функция вместо send_error_reply
    async fn close_stream(muxer: &Muxer, stream_id: u32) {
        let _ = muxer
            .send_control(stream_id, FrameType::Close, Bytes::new())
            .await;
        muxer.remove_stream(stream_id);
    }

    async fn on_data(&self, stream_id: u32, payload: Bytes) {
        self.muxer.dispatch_to_local(stream_id, payload).await;
    }

    async fn on_close(&self, stream_id: u32) {
        self.muxer.dispatch_to_local(stream_id, Bytes::new()).await;
        self.muxer.remove_stream(stream_id);
    }
}
