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

            let (v_tx, v_rx) = tokio::sync::mpsc::channel(1024);
            muxer.register_stream(stream_id, v_tx).await;

            tokio::spawn(async move {
                info!(stream_id, target = %target_str, "Attempting remote connection");

                match tokio::net::TcpStream::connect(&target_str).await {
                    Ok(stream) => {
                        let mut reply_buf = BytesMut::with_capacity(10);
                        let reply = SocksReply::ConnectResult {
                            reply_code: 0x00,
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
                    Err(e) => {
                        error!(stream_id, error = %e, "Connection failed");

                        muxer.remove_stream(stream_id).await;

                        let mut reply_buf = BytesMut::with_capacity(10);
                        let reply = SocksReply::ConnectResult {
                            reply_code: 0x01,
                            atyp: 0x01,
                            addr: [0, 0, 0, 0],
                            port: 0,
                        };
                        reply.write_to(&mut reply_buf);
                        let _ = muxer
                            .send_control(stream_id, FrameType::Connect, reply_buf.freeze())
                            .await;
                    }
                }
            });
        } else {
            self.muxer.dispatch_to_local(stream_id, payload).await;
        }
    }

    async fn on_data(&self, stream_id: u32, payload: Bytes) {
        self.muxer.dispatch_to_local(stream_id, payload).await;
    }

    async fn on_close(&self, stream_id: u32) {
        self.muxer.dispatch_to_local(stream_id, Bytes::new()).await;
        self.muxer.remove_stream(stream_id).await;
    }
}
