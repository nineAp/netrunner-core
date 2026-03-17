use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error, info};

use crate::{
    protocol::codec::{
        frame::{Frame, FrameType},
        socks::SocksReply,
    },
    proxy::connection::{bridge::run_proxy_bridge, connection::ConnectionRole, muxer::Muxer},
};

pub struct StreamHandler {
    muxer: Muxer,
    role: ConnectionRole,
}

impl StreamHandler {
    pub fn new(muxer: Muxer, role: ConnectionRole) -> Self {
        Self { muxer, role }
    }

    pub async fn handle(&self, frame: Frame) {
        let stream_id = frame.header.stream_id;

        match frame.header.frame_type {
            FrameType::Connect => self.on_connect(stream_id, frame.payload).await,
            FrameType::Data => self.on_data(stream_id, frame.payload).await,
            FrameType::Close => self.on_close(stream_id).await,
            _ => debug!(stream_id, "Unhandled frame type"),
        }
    }

    async fn on_connect(&self, stream_id: u32, payload: Bytes) {
        if self.role == ConnectionRole::Server {
            let target_str = String::from_utf8_lossy(&payload).to_string();
            let muxer = self.muxer.clone();

            // Канал для передачи данных из мультиплексора в мост (bridge)
            let (v_tx, v_rx) = tokio::sync::mpsc::channel(2048);
            muxer.register_stream(stream_id, v_tx).await;

            tokio::spawn(async move {
                let start = std::time::Instant::now();
                info!(stream_id, target = %target_str, "Attempting remote connection");

                // Обертываем коннект в таймаут, чтобы не плодить зомби-таски
                let connect_timeout = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tokio::net::TcpStream::connect(&target_str),
                )
                .await;

                match connect_timeout {
                    Ok(Ok(stream)) => {
                        let elapsed = start.elapsed();
                        info!(
                            stream_id,
                            target = %target_str,
                            latency_ms = elapsed.as_millis(),
                            "Remote connection established"
                        );

                        let mut reply_buf = BytesMut::with_capacity(10);
                        let reply = SocksReply::ConnectResult {
                            reply_code: 0x00, // Success
                            atyp: 0x01,
                            addr: [0, 0, 0, 0],
                            port: 0,
                        };
                        reply.write_to(&mut reply_buf);

                        let _ = muxer
                            .send_control(stream_id, FrameType::Connect, reply_buf.freeze())
                            .await;

                        let (r, w) = stream.into_split();
                        run_proxy_bridge(stream_id, r, w, muxer, v_rx).await;
                    }
                    Ok(Err(e)) => {
                        error!(stream_id, target = %target_str, error = %e, "TCP connection failed");
                        Self::send_error_reply(&muxer, stream_id, 0x01).await; // 0x01 = General failure
                    }
                    Err(_) => {
                        error!(stream_id, target = %target_str, "Connection timed out (DNS/TCP)");
                        Self::send_error_reply(&muxer, stream_id, 0x04).await; // 0x04 = Host unreachable
                    }
                }
            });
        } else {
            self.muxer.dispatch_to_local(stream_id, payload).await;
        }
    }
    async fn send_error_reply(muxer: &Muxer, stream_id: u32, code: u8) {
        muxer.remove_stream(stream_id).await;
        let mut reply_buf = BytesMut::with_capacity(10);
        let reply = SocksReply::ConnectResult {
            reply_code: code,
            atyp: 0x01,
            addr: [0, 0, 0, 0],
            port: 0,
        };
        reply.write_to(&mut reply_buf);
        let _ = muxer
            .send_control(stream_id, FrameType::Connect, reply_buf.freeze())
            .await;
    }

    async fn on_data(&self, stream_id: u32, payload: Bytes) {
        self.muxer.dispatch_to_local(stream_id, payload).await;
    }

    async fn on_close(&self, stream_id: u32) {
        self.muxer.dispatch_to_local(stream_id, Bytes::new()).await;
        self.muxer.remove_stream(stream_id).await;
    }
}
