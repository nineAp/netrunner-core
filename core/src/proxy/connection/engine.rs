use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::Receiver,
};
use tokio_util::sync::CancellationToken;

use crate::{
    protocol::{
        codec::{codec::Codec, frame::FrameType},
        errors::ErrorAction,
    },
    proxy::connection::{handler::StreamHandler, muxer::MuxMessage},
};

pub struct TunnelEngine {
    pub inbound: OwnedReadHalf,
    pub outbound: OwnedWriteHalf,
    pub codec: Codec,
    pub read_buf: BytesMut,
    pub mux_rx: Receiver<MuxMessage>,
    pub handler: Arc<StreamHandler>,
    pub token: CancellationToken,
}

impl TunnelEngine {
    pub async fn run(self) -> Result<(), String> {
        let mut inbound = self.inbound;
        let mut outbound = self.outbound;
        let mut codec = self.codec;
        let mut read_buf = self.read_buf;
        let mut mux_rx = self.mux_rx;
        let handler = self.handler;

        let token = self.token;
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("TunnelEngine: Shutdown signal received. Closing...");
                    return Ok(());
                }

                res = Self::process_inbound(&mut inbound, &mut codec, &mut read_buf, &handler) => {
                    res?
                }

                _ = heartbeat.tick() => {
                    let msg = MuxMessage { stream_id: 0, frame_type: FrameType::Heartbeat, data: Bytes::new() };
                    Self::handle_outbound(&mut outbound, &mut codec, msg).await?;
                }

                msg_opt = mux_rx.recv() => {
                    if let Some(msg) = msg_opt {
                        Self::handle_outbound(&mut outbound, &mut codec, msg).await?;
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_inbound(
        inbound: &mut OwnedReadHalf,
        codec: &mut Codec,
        read_buf: &mut BytesMut,
        handler: &Arc<StreamHandler>,
    ) -> Result<(), String> {
        let n = inbound
            .read_buf(read_buf)
            .await
            .map_err(|e| e.to_string())?;

        if n == 0 && read_buf.is_empty() {
            netrunner_logger::info!("Connection closed by peer (EOF detected)");
            return Err("EOF".into());
        }

        loop {
            match codec.inbound(read_buf) {
                Ok(Some(frame)) => {
                    handler.handle(frame).await;
                }

                Ok(None) => break,

                Err(e) => {
                    if e.action == ErrorAction::Wait {
                        break;
                    }

                    if e.action == ErrorAction::Drop {
                        // ТСПУ подмешал мусор ИЛИ ключи не совпали.
                        // Мгновенный выход с ошибкой приведет к обрыву TCP-соединения.
                        netrunner_logger::error!(
                            "CRITICAL: Crypto tampering or sync lost. Hard dropping tunnel!"
                        );
                        return Err("Crypto drop".into());
                    }

                    error!(error = ?e, "Codec inbound failed");
                    return Err(format!("Codec error: {:?}", e));
                }
            }
        }
        Ok(())
    }

    async fn handle_outbound(
        outbound: &mut OwnedWriteHalf,
        codec: &mut Codec,
        msg: MuxMessage,
    ) -> Result<(), String> {
        const MAX_CHUNK_SIZE: usize = 16000;

        let mut data = msg.data;
        let stream_id = msg.stream_id;
        let frame_type = msg.frame_type;

        if data.is_empty() {
            match codec.encrypt_data(stream_id, frame_type.clone(), Bytes::new()) {
                Ok(pkt) => {
                    outbound.write_all(&pkt).await.map_err(|e| e.to_string())?;
                }
                Err(e) => {
                    error!(stream_id, error = ?e, "Encryption failed for empty message");
                    return Err(format!("Encryption error: {:?}", e));
                }
            }
            return Ok(());
        }

        while !data.is_empty() {
            let chunk_size = std::cmp::min(data.len(), MAX_CHUNK_SIZE);

            let chunk = data.split_to(chunk_size);

            match codec.encrypt_data(stream_id, frame_type.clone(), chunk) {
                Ok(pkt) => {
                    outbound.write_all(&pkt).await.map_err(|e| {
                        error!(stream_id, error = %e, "Failed to write encrypted data to network");
                        e.to_string()
                    })?;
                }
                Err(e) => {
                    error!(stream_id, error = ?e, "Encryption failed for chunked message");
                    return Err(format!("Encryption error: {:?}", e));
                }
            }
        }

        debug!(stream_id, "Outbound packet sent successfully");
        Ok(())
    }
}
