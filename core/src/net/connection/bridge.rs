use std::sync::Arc;

use crate::net::connection::muxer::{adaptive_write_timeout, Muxer};
use crate::net::{
    NetworkConfig, BRIDGE_IDLE_TIMEOUT, BRIDGE_READ_CHUNK, BRIDGE_STREAM_WRITE_TIMEOUT,
    STREAM_PAUSE_BUDGET, STREAM_PAUSE_RETRY,
};
use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error, info, warn};
use std::time::Instant;
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
    let token = CancellationToken::new();

    // Upload: internet → tunnel.
    // Runs concurrently with download so a congested muxer path does not
    // prevent downstream data from being delivered.
    let upload = {
        let muxer = muxer.clone();
        let token = token.clone();
        async move {
            let mut reader = reader;
            // Read in ≤ BRIDGE_READ_CHUNK (one-frame) units so a single data
            // message can't be huge. Combined with CHANNEL_PACKETS this byte-bounds
            // the per-leg queue and keeps post-speedtest bufferbloat small.
            let mut buf = BytesMut::with_capacity(BRIDGE_READ_CHUNK);
            loop {
                if buf.capacity() - buf.len() < BRIDGE_READ_CHUNK {
                    buf.reserve(BRIDGE_READ_CHUNK);
                }
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    res = reader.read_buf(&mut buf) => match res {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let data = buf.split().freeze();
                            // 🔥 GRACEFUL PAUSE (anti-domino).
                            // send_data_safe already fails over between live legs;
                            // it only errors when EVERY leg is down. In that case we
                            // do NOT close the stream — we hold this chunk and retry
                            // while the engine reconnects, bounded by STREAM_PAUSE_BUDGET.
                            // Because we stop reading meanwhile, TCP back-pressure
                            // naturally pauses the source instead of dropping data.
                            let deadline = Instant::now() + STREAM_PAUSE_BUDGET;
                            let mut delivered = false;
                            loop {
                                if muxer.send_data_safe(stream_id, data.clone(), false).await.is_ok() {
                                    delivered = true;
                                    break;
                                }
                                if Instant::now() >= deadline {
                                    warn!(stream_id, "Stream pause budget exceeded — no leg recovered, closing");
                                    break;
                                }
                                tokio::select! {
                                    biased;
                                    _ = token.cancelled() => break,
                                    _ = tokio::time::sleep(STREAM_PAUSE_RETRY) => {}
                                }
                            }
                            if !delivered {
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
                            // Adaptive: BRIDGE_STREAM_WRITE_TIMEOUT is the floor, but
                            // under high RTT we grant the slow local socket more drain
                            // time before declaring it stuck and closing the stream.
                            let write_timeout = adaptive_write_timeout(BRIDGE_STREAM_WRITE_TIMEOUT);
                            match timeout(write_timeout, writer.write_all(&data)).await {
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
    let dgram_cap = config.udp_buffer_size;
    // 🔥 ZERO-COPY: receive directly into BytesMut spare capacity and hand the
    // datagram downstream via split().freeze() (ownership transfer, no memcpy).
    // Replaces `vec![0u8; N]` + `Bytes::copy_from_slice` (one full copy/datagram).
    let mut buf = BytesMut::with_capacity(dgram_cap);

    info!(stream_id, "🌉 UDP Bridge active");

    loop {
        // Guarantee room for a whole datagram so recv_buf never truncates it.
        if buf.capacity() - buf.len() < dgram_cap {
            buf.reserve(dgram_cap);
        }
        let select_res = timeout(BRIDGE_IDLE_TIMEOUT, async {
            tokio::select! {
                res = socket.recv_buf(&mut buf) => {
                    match res {
                        Ok(n) if n > 0 => {
                            // Ownership transfer: the just-received bytes are moved
                            // out with no copy; buf is left empty for the next reserve.
                            let data = buf.split().freeze();
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
