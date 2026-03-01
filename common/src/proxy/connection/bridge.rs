use crate::protocol::codec::frame::FrameType;
use crate::proxy::connection::connection::BUF_SIZE;
use crate::proxy::connection::muxer::{MuxMessage, Muxer};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tracing::{debug, error};
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
                        if muxer.to_network.send(msg).await.is_err() { break; }
                    }
                    Err(e) => {
                        error!(stream_id, error = %e, "Socket read error");
                        break;
                    }
                }
            }
            // Читаем из туннеля (v_rx) -> шлем в сокет
            maybe_data = v_rx.recv() => {
                match maybe_data {
                    Some(data) => {
                        if data.is_empty() { break; } // EOF от другой стороны
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

    // Финализация (общая для всех)
    let _ = muxer
        .to_network
        .send(MuxMessage {
            stream_id,
            frame_type: FrameType::Close,
            data: Bytes::new(),
        })
        .await;

    muxer.remove_stream(stream_id).await;
}
