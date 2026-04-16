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
    let buf_size = NetworkConfig::global().tcp_buffer_size;

    // Создаем отдельный канал для упорядоченной отправки в туннель
    let (tx_to_mux, mut rx_from_bridge) = mpsc::channel::<Bytes>(16);

    // Задача-отправщик: гарантирует порядок и не блокирует основной цикл моста
    let m_clone = muxer.clone();
    tokio::spawn(async move {
        while let Some(data) = rx_from_bridge.recv().await {
            if let Err(_) = m_clone.send_data_safe(stream_id, data, false).await {
                break;
            }
        }
    });

    let mut buf = BytesMut::with_capacity(buf_size);
    loop {
        if buf.capacity() < 16384 {
            buf.reserve(buf_size);
        }

        tokio::select! {
            // Читаем из Интернета -> В очередь отправки (Upload)
            res = reader.read_buf(&mut buf) => {
                match res {
                    Ok(0) => break,
                    Ok(_) => {
                        let data = buf.split().freeze();
                        if tx_to_mux.send(data).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }
            // Читаем из Туннеля -> В Интернет (Download)
            maybe_data = v_rx.recv() => {
                match maybe_data {
                    Some(data) => {
                        if data.is_empty() { continue; }
                        if writer.write_all(&data).await.is_err() { break; }
                    }
                    None => break,
                }
            }
        }
    }
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
