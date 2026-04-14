use std::sync::Arc;
use std::time::Duration;

use crate::net::connection::muxer::{MuxMessage, Muxer};
use crate::net::{NetworkConfig, BRIDGE_IDLE_TIMEOUT};
use crate::nrxp::FrameType;
use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

struct StreamGuard {
    stream_id: u32,
    muxer: Arc<Muxer>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        debug!(self.stream_id, "StreamGuard: Cleaning up resources");
        self.muxer.remove_stream(self.stream_id);
    }
}

pub(crate) async fn run_tcp_bridge<R, W>(
    stream_id: u32,
    mut reader: R,
    mut writer: W,
    muxer: Arc<Muxer>,
    mut v_rx: mpsc::Receiver<Bytes>,
) where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let _guard = StreamGuard {
        stream_id,
        muxer: muxer.clone(),
    };

    let mut buf = BytesMut::with_capacity(NetworkConfig::global().tcp_buffer_size);

    loop {
        buf.reserve(NetworkConfig::global().tcp_buffer_size);
        let select_res = timeout(BRIDGE_IDLE_TIMEOUT, async {
            tokio::select! {
                res = reader.read_buf(&mut buf) => {
                    match res {
                        Ok(0) => {
                            debug!(stream_id, "TCP Socket reached EOF");
                            return Ok(false);
                        }
                        Ok(_) => {
                            let msg = MuxMessage {
                                stream_id,
                                frame_type: FrameType::Data,
                                data: buf.split().freeze(),
                            };

                            if muxer.send_to_network(msg).await.is_err() {
                                // 🔥 ФИКС: Если нет живых ног туннеля — просто дропаем пакет!
                                // Мы НЕ закрываем мост (return Ok(false)), 
                                // TCP-стек на клиенте сам сделает ретрансмиссию
                                warn!(stream_id, "All tunnel legs dead. Dropping packet. TCP will retransmit.");
                            }
                            Ok(true)
                        }
                        Err(e) => {
                            error!(stream_id, error = %e, "TCP Socket read error");
                            Err(e.to_string())
                        }
                    }
                }

                maybe_data = v_rx.recv() => {
                    match maybe_data {
                        Some(data) => {
                            if data.is_empty() { return Ok(true); }
                            if let Err(e) = writer.write_all(&data).await {
                                error!(stream_id, error = %e, "TCP Socket write error");
                                return Err(e.to_string());
                            }
                            Ok(true)
                        }
                        None => {
                            debug!(stream_id, "Virtual channel closed (Muxer removed stream)");
                            Ok(false)
                        }
                    }
                }
            }
        })
        .await;

        match select_res {
            Ok(Ok(true)) => continue,
            Ok(Ok(false)) => break,
            Ok(Err(e)) => {
                debug!(stream_id, "Bridge closing due to error: {}", e);
                break;
            }
            Err(_) => {
                warn!(stream_id, "TCP Bridge IDLE timeout reached. Evicting task.");
                break;
            }
        }
    }

    let _ = muxer
        .send_to_network(MuxMessage {
            stream_id,
            frame_type: FrameType::Close,
            data: Bytes::new(),
        })
        .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
}

pub(crate) async fn run_udp_bridge(
    stream_id: u32,
    socket: UdpSocket,
    muxer: Arc<Muxer>,
    mut v_rx: mpsc::Receiver<Bytes>,
) {
    let _guard = StreamGuard {
        stream_id,
        muxer: muxer.clone(),
    };

    let config = NetworkConfig::global();
    let mut buf = vec![0u8; config.udp_buffer_size];

    info!(stream_id, "🌉 UDP Bridge active");

    loop {
        let select_res = timeout(BRIDGE_IDLE_TIMEOUT, async {
            tokio::select! {
                res = socket.recv(&mut buf) => {
                    match res {
                        Ok(n) if n > 0 => {
                            let data = Bytes::copy_from_slice(&buf[..n]);
                            if let Err(e) = muxer.send_data_safe(stream_id, data, true).await {
                                warn!(stream_id, "UDP Tunnel legs dead. Dropping packet: {}", e);
                                // 🔥 ФИКС: Опять же, не обрываем стрим из-за мертвого туннеля!
                            }
                            Ok(true)
                        }
                        Ok(_) => Ok(false),
                        Err(e) => {
                            error!(stream_id, "UDP Socket read error: {}", e);
                            Err(e.to_string())
                        }
                    }
                }

                maybe_data = v_rx.recv() => {
                    match maybe_data {
                        Some(data) => {
                            if let Err(e) = socket.send(&data).await {
                                error!(stream_id, "UDP Internet write error: {}", e);
                                return Err(e.to_string());
                            }
                            Ok(true)
                        }
                        None => Ok(false),
                    }
                }
            }
        })
        .await;

        match select_res {
            Ok(Ok(true)) => continue,
            _ => break,
        }
    }

    debug!(stream_id, "🔌 UDP Bridge closed");
}
