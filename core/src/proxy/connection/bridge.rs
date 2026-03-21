use crate::protocol::codec::frame::FrameType;
use crate::proxy::connection::muxer::{MuxMessage, Muxer};
use crate::proxy::connection::BUF_SIZE;
use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub async fn run_proxy_bridge<R, W>(
    stream_id: u32,
    mut reader: R,
    mut writer: W,
    muxer: Muxer,
    mut v_rx: mpsc::Receiver<Bytes>,
) where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let mut buf = BytesMut::with_capacity(BUF_SIZE);

    loop {
        tokio::select! {
            res = reader.read_buf(&mut buf) => {
                match res {
                    Ok(0) => {
                        debug!(stream_id, "Socket closed (EOF)");
                        break;
                    }
                    Ok(_) => {
                        let msg = MuxMessage {
                            stream_id,
                            frame_type: FrameType::Data,
                            data: buf.split().freeze(),
                        };
                        if muxer.send_to_netwrok(msg).await.is_err() { break; }
                    }
                    Err(e) => {
                        error!(stream_id, error = %e, "Socket read error");
                        break;
                    }
                }
            }

            maybe_data = v_rx.recv() => {
                match maybe_data {
                    Some(data) => {
                        if data.is_empty() { break; }
                        if let Err(e) = writer.write_all(&data).await {
                            error!(stream_id, error = %e, "Socket write error");
                            break;
                        }
                    }
                    None => {
                        debug!(stream_id, "Virtual channel closed");
                        break;
                    }
                }
            }
        }
    }

    // Отправляем Close фрейм перед выходом
    let _ = muxer
        .send_to_netwrok(MuxMessage {
            stream_id,
            frame_type: FrameType::Close,
            data: Bytes::new(),
        })
        .await;

    // Небольшая пауза, чтобы Close фрейм успел уйти в сеть
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ИЗМЕНЕНИЕ: remove_stream теперь синхронный
    muxer.remove_stream(stream_id);
}

pub async fn run_udp_bridge(
    stream_id: u32,
    socket: UdpSocket,
    muxer: Muxer,
    mut v_rx: mpsc::Receiver<Bytes>,
) {
    let mut buf = [0u8; 65536];

    loop {
        tokio::select! {
            res = socket.recv(&mut buf) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        let msg = MuxMessage {
                            stream_id,
                            frame_type: FrameType::UdpData,
                            data: Bytes::copy_from_slice(&buf[..n]),
                        };
                        if muxer.send_to_netwrok(msg).await.is_err() { break; }
                    }
                    Err(e) => {
                        error!(stream_id, error = %e, "UDP socket read error");
                        break;
                    }
                }
            }

            maybe_data = v_rx.recv() => {
                match maybe_data {
                    Some(data) => {
                        if data.is_empty() { break; }
                        if let Err(e) = socket.send(&data).await {
                            error!(stream_id, error = %e, "UDP socket write error");
                            break;
                        }
                    }
                    None => {
                        debug!(stream_id, "Virtual channel closed (UDP)");
                        break;
                    }
                }
            }
        }
    }

    let _ = muxer
        .send_to_netwrok(MuxMessage {
            stream_id,
            frame_type: FrameType::Close,
            data: Bytes::new(),
        })
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ИЗМЕНЕНИЕ: remove_stream теперь синхронный
    muxer.remove_stream(stream_id);
}
