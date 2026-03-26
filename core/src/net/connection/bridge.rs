use crate::net::connection::muxer::{MuxMessage, Muxer};
use crate::net::network::NetworkConfig;
use crate::nrxp::FrameType;
use bytes::{Bytes, BytesMut};
use netrunner_logger::{debug, error};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub(crate) async fn run_tcp_bridge<R, W>(
    stream_id: u32,
    mut reader: R,
    mut writer: W,
    muxer: Muxer,
    mut v_rx: mpsc::Receiver<Bytes>,
) where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let mut buf = BytesMut::with_capacity(NetworkConfig::global().tcp_buffer_size);

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
                        if muxer.send_to_network(msg).await.is_err() { break; }
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
                        if data.is_empty() { continue; }
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

    let _ = muxer
        .send_to_network(MuxMessage {
            stream_id,
            frame_type: FrameType::Close,
            data: Bytes::new(),
        })
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    muxer.remove_stream(stream_id);
}

pub(crate) async fn run_udp_bridge(
    stream_id: u32,
    socket: UdpSocket,
    muxer: Muxer,
    mut v_rx: mpsc::Receiver<Bytes>,
) {
    let mut buf = BytesMut::with_capacity(NetworkConfig::global().udp_buffer_size);

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
                        if muxer.send_to_network(msg).await.is_err() { break; }
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
        .send_to_network(MuxMessage {
            stream_id,
            frame_type: FrameType::Close,
            data: Bytes::new(),
        })
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    muxer.remove_stream(stream_id);
}
