use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{mpsc::Receiver, Mutex},
};
use tokio_util::sync::CancellationToken;

use crate::{
    net::{
        connection::{handler::StreamHandler, muxer::MuxMessage},
        NetworkConfig, HEALTH_CHECK_INTERVAL,
    },
    nrxp::{Codec, ErrorAction, FrameType},
};

pub(crate) struct TunnelEngine {
    pub inbound: OwnedReadHalf,
    pub outbound: OwnedWriteHalf,
    pub codec: Codec,
    pub read_buf: BytesMut,
    pub control_rx: Receiver<MuxMessage>,
    pub data_rx: Receiver<MuxMessage>,
    pub handler: Arc<StreamHandler>,
    pub leg_id: u32,
    pub muxer: Arc<crate::net::connection::muxer::Muxer>,
}

impl TunnelEngine {
    pub async fn run(self) -> Result<(), String> {
        let inbound = self.inbound;
        let outbound = self.outbound;

        let codec = Arc::new(Mutex::new(self.codec));
        let read_buf = self.read_buf;

        let control_rx = self.control_rx;
        let data_rx = self.data_rx;
        let handler = self.handler;

        let leg_id = self.leg_id;
        let muxer = self.muxer.clone();

        let muxer_pong = muxer.clone();

        let token = CancellationToken::new();

        let codec_reader = codec.clone();
        let codec_writer = codec.clone();

        let token_reader = token.clone();
        let token_writer = token.clone();

        let reader_handle = tokio::spawn(async move {
            let mut read_buf = read_buf;
            let mut inbound = inbound;

            loop {
                tokio::select! {
                    _ = token_reader.cancelled() => {
                        info!("Reader Task: Shutdown signal received.");
                        break;
                    }
                    res = inbound.read_buf(&mut read_buf) => {
                        let n = res.map_err(|e| e.to_string())?;

                        if n == 0 {
                            if read_buf.is_empty() {
                                info!("Connection closed by peer (Clean EOF)");
                            } else {
                                error!("Connection abruptly closed by peer (Incomplete frame: {} bytes left)", read_buf.len());
                            }

                            return Err::<(), String>("EOF".into());
                        }


                        muxer.record_leg_rx(leg_id, n as u64);

                        let mut frames = Vec::new();

                        {
                            let mut c = codec_reader.lock().await;
                            loop {
                                match c.inbound(&mut read_buf) {
                                    Ok(Some(frame)) => frames.push(frame),
                                    Ok(None) => break,
                                    Err(e) => {
                                        if e.action == ErrorAction::Wait {
                                            break;
                                        }
                                        if e.action == ErrorAction::Drop {
                                            error!("CRITICAL: Crypto tampering or sync lost. Hard dropping tunnel!");
                                            return Err("Crypto drop".into());
                                        }
                                        error!(error = ?e, "Codec inbound failed");
                                        return Err(format!("Codec error: {:?}", e));
                                    }
                                }
                            }
                        }

                        for frame in frames {
                            if frame.header.frame_type == FrameType::Heartbeat {
                                muxer.record_pong(leg_id).await;
                                continue;
                            }
                            handler.handle(frame).await;
                        }
                    }
                }
            }
            Ok::<(), String>(())
        });

        let writer_handle = tokio::spawn(async move {
            let mut outbound = outbound;
            let mut control_rx = control_rx;
            let mut data_rx = data_rx;
            let mut heartbeat = tokio::time::interval(HEALTH_CHECK_INTERVAL);

            loop {
                tokio::select! {
                    biased;

                    _ = token_writer.cancelled() => {
                        info!("Writer Task: Shutdown signal received.");
                        break;
                    }

                    msg_opt = control_rx.recv() => {
                        if let Some(msg) = msg_opt {
                            Self::handle_outbound(&mut outbound, &codec_writer, msg).await?;
                        } else {
                            break;
                        }
                    }

                    _ = heartbeat.tick() => {
                        // 1. Фиксируем время
                        muxer_pong.record_ping_sent(leg_id);
                        // 2. Шлем пакет
                        let msg = MuxMessage { stream_id: 0, frame_type: FrameType::Heartbeat, data: Bytes::new() };
                        Self::handle_outbound(&mut outbound, &codec_writer, msg).await?;
                    }

                    msg_opt = data_rx.recv() => {
                        if let Some(msg) = msg_opt {
                            Self::handle_outbound(&mut outbound, &codec_writer, msg).await?;
                        } else {
                            break;
                        }
                    }
                }
            }
            Ok::<(), String>(())
        });

        let res = tokio::select! {
            res = reader_handle => res.unwrap_or_else(|e| Err(format!("Reader panic: {}", e))),
            res = writer_handle => res.unwrap_or_else(|e| Err(format!("Writer panic: {}", e))),
        };

        if let Err(e) = &res {
            error!("TunnelEngine critical failure: {}", e);
        }

        res
    }

    async fn handle_outbound(
        outbound: &mut OwnedWriteHalf,
        codec: &Arc<Mutex<Codec>>,
        msg: MuxMessage,
    ) -> Result<(), String> {
        let mut data = msg.data;
        let stream_id = msg.stream_id;
        let frame_type = msg.frame_type;

        let mut packets = Vec::new();

        {
            let mut c = codec.lock().await;

            if frame_type == FrameType::UdpData {
                match c.encrypt_data(stream_id, frame_type.clone(), data) {
                    Ok(pkt) => packets.push(pkt),
                    Err(e) => {
                        error!(stream_id, error = ?e, "Encryption failed for UDP datagram");
                        return Err(format!("Encryption error: {:?}", e));
                    }
                }
            } else {
                while !data.is_empty() {
                    let chunk_size =
                        std::cmp::min(data.len(), NetworkConfig::global().tcp_chunk_size);
                    let chunk = data.split_to(chunk_size);

                    match c.encrypt_data(stream_id, frame_type.clone(), chunk) {
                        Ok(pkt) => packets.push(pkt),
                        Err(e) => {
                            error!(stream_id, error = ?e, "Encryption failed for TCP chunk");
                            return Err(format!("Encryption error: {:?}", e));
                        }
                    }
                }
            }
        }

        for pkt in packets {
            outbound.write_all(&pkt).await.map_err(|e| {
                error!(stream_id, error = %e, "Failed to write encrypted data to network");
                e.to_string()
            })?;
            tokio::task::yield_now().await;
        }

        debug!(stream_id, "Outbound packet sent successfully");
        Ok(())
    }
}
