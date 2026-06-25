use std::sync::Arc;

use crate::net::connection::muxer::Muxer;
use crate::net::{NetworkConfig, BRIDGE_IDLE_TIMEOUT};
use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

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
    reader: R,
    writer: W,
    muxer: Arc<Muxer>,
    v_rx: mpsc::Receiver<Bytes>,
) where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let _guard = StreamGuard {
        stream_id,
        muxer: muxer.clone(),
    };
    let buf_size = NetworkConfig::global().tcp_buffer_size;
    let token = CancellationToken::new();

    // Upload: internet → tunnel.
    // Runs concurrently with download so a congested muxer path does not
    // prevent downstream data from being delivered.
    let upload = {
        let muxer = muxer.clone();
        let token = token.clone();
        async move {
            let mut reader = reader;
            let mut buf = BytesMut::with_capacity(buf_size);
            loop {
                if buf.capacity() < 16384 {
                    buf.reserve(buf_size);
                }
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    res = reader.read_buf(&mut buf) => match res {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let data = buf.split().freeze();
                            if muxer.send_data_safe(stream_id, data, false).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            token.cancel();
        }
    };

    // Download: tunnel → internet.
    // write_all has a hard timeout so a slow local app (full socket buffer)
    // does not block the pipeline indefinitely and starve other streams on
    // the same tunnel leg.
    let download = {
        let token = token.clone();
        async move {
            let mut writer = writer;
            let mut v_rx = v_rx;
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    maybe_data = v_rx.recv() => match maybe_data {
                        None => break,
                        Some(data) => {
                            if data.is_empty() { continue; }
                            match timeout(crate::net::BRIDGE_STREAM_WRITE_TIMEOUT, writer.write_all(&data)).await {
                                Ok(Ok(_)) => {}
                                _ => break,
                            }
                        }
                    }
                }
            }
            token.cancel();
        }
    };

    // Both halves run concurrently via the outer select. When either half
    // finishes (connection closed, error, or write timeout), the token
    // cancels the other half so cleanup is prompt.
    tokio::select! {
        _ = upload => {}
        _ = download => {}
    }
    token.cancel();
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
