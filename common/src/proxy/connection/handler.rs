use crate::protocol::codec::frame::FrameType;
use crate::protocol::codec::socks::{SocksReply, ATYP_IPV4, REPLY_SUCCESS};
use crate::proxy::connection::muxer::{MuxMessage, Muxer};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

pub fn spawn_client_local_handler_with_rx(
    stream_id: u32,
    mut r: OwnedReadHalf,
    mut w: OwnedWriteHalf,
    muxer: Muxer,
    mut v_rx: mpsc::Receiver<Bytes>, // Используем эту читалку, она уже зарегистрирована!
) {
    // ВНИМАНИЕ: Здесь больше не создаем канал и не вызываем register_stream,
    // так как это уже сделал handle_socks_client до вызова этой функции.

    tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(8192);
        debug!(
            stream_id,
            "Spawned client local handler with existing receiver"
        );

        loop {
            tokio::select! {
                // 1. Читаем из браузера -> Шлем в общий туннель
                res = r.read_buf(&mut buf) => {
                    match res {
                        Ok(0) => {
                            debug!(stream_id, "Browser closed connection (EOF)");
                            break;
                        }
                        Err(e) => {
                            error!(stream_id, error = %e, "Read error from browser");
                            break;
                        }
                        Ok(n) => {
                            let msg = MuxMessage {
                                stream_id,
                                frame_type: FrameType::Data,
                                data: buf.split().freeze(),
                            };
                            if muxer.to_network.send(msg).await.is_err() { break; }
                        }
                    }
                }
                // 2. Читаем из виртуального канала (данные из туннеля) -> Шлем браузеру
                maybe_data = v_rx.recv() => {
                    match maybe_data {
                        Some(data) => {
                            if let Err(e) = w.write_all(&data).await {
                                error!(stream_id, error = %e, "Write error to browser");
                                break;
                            }
                        }
                        None => {
                            debug!(stream_id, "Virtual channel closed by Muxer");
                            break;
                        }
                    }
                }
            }
        }

        // КРИТИЧНО: Сообщаем серверу, что мы закрываем этот конкретный стрим
        let _ = muxer
            .to_network
            .send(MuxMessage {
                stream_id,
                frame_type: FrameType::Close,
                data: Bytes::new(),
            })
            .await;

        // Чистим за собой в таблице стримов
        muxer.remove_stream(stream_id).await;
        info!(stream_id, "Client handler terminated");
    });
}
pub async fn spawn_server_target_handler(stream_id: u32, target_raw: Bytes, muxer: Muxer) {
    let addr = String::from_utf8_lossy(&target_raw).to_string();
    let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(100);
    muxer.register_stream(stream_id, v_tx).await;

    tokio::spawn(async move {
        info!(stream_id, target = %addr, "Attempting to connect to target");

        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                // Формируем SOCKS5 Success Reply используя структуру
                let mut reply_buf = BytesMut::with_capacity(10);
                let reply = SocksReply::ConnectResult {
                    reply_code: REPLY_SUCCESS,
                    atyp: ATYP_IPV4,
                    addr: [0, 0, 0, 0],
                    port: 0,
                };
                reply.write_to(&mut reply_buf);

                // Отправляем подтверждение в сеть
                let _ = muxer
                    .to_network
                    .send(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Connect,
                        data: reply_buf.freeze(),
                    })
                    .await;

                info!(stream_id, target = %addr, "Connected to target host, SOCKS reply sent");

                let (mut r, mut w) = stream.into_split();
                let mut buf = BytesMut::with_capacity(8192);

                loop {
                    tokio::select! {
                        // Сеть -> Прокси -> Интернет (Запись в целевой хост)
                        Some(data) = v_rx.recv() => {
                            if data.is_empty() { break; } // EOF от локального клиента
                            if let Err(e) = w.write_all(&data).await {
                                warn!(stream_id, error = ?e, "Target write failed");
                                break;
                            }
                        }
                        // Интернет -> Прокси -> Сеть (Чтение из целевого хоста)
                        res = r.read_buf(&mut buf) => {
                            match res {
                                Ok(0) => {
                                    debug!(stream_id, "Target host closed connection (EOF)");
                                    break;
                                }
                                Ok(n) => {
                                    let msg = MuxMessage {
                                        stream_id,
                                        frame_type: FrameType::Data,
                                        data: buf.split().freeze(),
                                    };
                                    if muxer.to_network.send(msg).await.is_err() { break; }
                                }
                                Err(e) => {
                                    error!(stream_id, error = %e, "Target read error");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!(stream_id, target = %addr, error = %e, "Connection to target failed");

                // Формируем SOCKS5 Failure Reply (0x01 - General failure)
                let mut reply_buf = BytesMut::with_capacity(10);
                let reply = SocksReply::ConnectResult {
                    reply_code: 0x01,
                    atyp: ATYP_IPV4,
                    addr: [0, 0, 0, 0],
                    port: 0,
                };
                reply.write_to(&mut reply_buf);

                let _ = muxer
                    .to_network
                    .send(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Connect,
                        data: reply_buf.freeze(),
                    })
                    .await;
            }
        }

        // Финализация: уведомляем сеть о закрытии и чистим муксер
        let _ = muxer
            .to_network
            .send(MuxMessage {
                stream_id,
                frame_type: FrameType::Close,
                data: Bytes::new(),
            })
            .await;

        muxer.remove_stream(stream_id).await;
        info!(stream_id, "Server target handler closed");
    });
}
