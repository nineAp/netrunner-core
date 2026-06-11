use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use netrunner_logger::{
    error, info, AppError, ERR_INFRA_TIMEOUT, ERR_NET_TLS_TAMPER, ERR_SYS_PANIC,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::Receiver,
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    net::{
        connection::{handler::StreamHandler, muxer::MuxMessage},
        NetworkConfig, HEALTH_CHECK_INTERVAL,
    },
    nrxp::{ErrorAction, FrameType, RxCodec, TxCodec},
};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LegStatus {
    Active,
    Reconnecting,
}

pub(crate) struct TunnelEngine {
    pub inbound: Option<OwnedReadHalf>,
    pub outbound: Option<OwnedWriteHalf>,
    pub remote_addr: String,
    pub session_id: String,
    pub leg_status: LegStatus,
    // 💡 ИЗМЕНЕНО: Кодеки теперь хранятся как Option без Arc/Mutex
    pub rx_codec: Option<RxCodec>,
    pub tx_codec: Option<TxCodec>,
    pub read_buf: BytesMut,
    pub control_rx: Option<Receiver<MuxMessage>>,
    pub data_rx: Option<Receiver<MuxMessage>>,
    pub handler: Arc<StreamHandler>,
    pub leg_id: u32,
    pub muxer: Arc<crate::net::connection::muxer::Muxer>,
}

impl TunnelEngine {
    pub async fn attempt_reconnect(
        &mut self,
    ) -> Result<(OwnedReadHalf, OwnedWriteHalf, RxCodec, TxCodec), AppError> {
        info!("🔄 Attempting reconnect to {}", self.remote_addr);
        let stream = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(&self.remote_addr),
        )
        .await
        .map_err(|_| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", "Reconnect timeout"))?
        .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", e.to_string()))?;

        crate::net::ClientHandler::perform_handshake(stream, &self.session_id, self.leg_id).await
    }

    #[instrument(skip_all, fields(leg_id = self.leg_id))]
    pub async fn run(mut self) -> Result<(), AppError> {
        loop {
            // Проверяем наличие всех необходимых ресурсов
            if self.inbound.is_none()
                || self.outbound.is_none()
                || self.rx_codec.is_none()
                || self.tx_codec.is_none()
            {
                // 💡 ИСПРАВЛЕНИЕ 2: Если это Сервер (remote_addr пуст), он НЕ должен делать реконнект.
                // Мертвая лега должна просто завершиться и удалиться из памяти.
                if self.remote_addr.is_empty() {
                    info!(
                        "Server leg {} dropped, shutting down engine task",
                        self.leg_id
                    );
                    return Ok(());
                }

                self.leg_status = LegStatus::Reconnecting;
                match self.attempt_reconnect().await {
                    Ok((new_in, new_out, new_rx, new_tx)) => {
                        self.inbound = Some(new_in);
                        self.outbound = Some(new_out);
                        self.rx_codec = Some(new_rx);
                        self.tx_codec = Some(new_tx);
                        self.leg_status = LegStatus::Active;
                        info!("✅ Leg {} reconnected successfully", self.leg_id);
                    }
                    Err(e) => {
                        error!("Reconnect failed for leg {}: {}", self.leg_id, e);
                        let jitter = rand::random::<u64>() % 1000;
                        tokio::time::sleep(tokio::time::Duration::from_millis(2000 + jitter)).await;
                        continue;
                    }
                }
            }

            let inbound = self.inbound.take().unwrap();
            let outbound = self.outbound.take().unwrap();
            let read_buf = std::mem::take(&mut self.read_buf);

            let mut rx_codec = self.rx_codec.take().unwrap();
            let mut tx_codec = self.tx_codec.take().unwrap();
            let mut control_rx = self.control_rx.take().expect("control_rx is missing");
            let mut data_rx = self.data_rx.take().expect("data_rx is missing");

            let handler = self.handler.clone();
            let leg_id = self.leg_id;
            let muxer = self.muxer.clone();
            let muxer_pong = self.muxer.clone();

            let token = CancellationToken::new();
            let token_reader = token.clone();
            let token_writer = token.clone();

            // ЧИТАЮЩАЯ ЗАДАЧА (Остается без изменений)
            let mut reader_handle = tokio::spawn(async move {
                let mut read_buf = read_buf;
                let mut inbound = inbound;
                const MAX_BUFFER_SIZE: usize = 1024 * 1024; // 1 MB

                loop {
                    if read_buf.len() > MAX_BUFFER_SIZE {
                        error!("CRITICAL: Read buffer exceeded 1MB (OOM Protection). Dropping connection!");
                        return Err(AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Переполнение буфера",
                            "OOM Protection",
                        ));
                    }

                    if read_buf.is_empty() {
                        read_buf.clear();
                    }
                    read_buf.reserve(16384);

                    tokio::select! {
                        _ = token_reader.cancelled() => {
                            info!("Reader Task: Shutdown signal received.");
                            break;
                        }
                        res = inbound.read_buf(&mut read_buf) => {
                            let n = res.map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", e.to_string()))?;
                            if n == 0 {
                                info!("Connection closed by peer (Clean EOF)");
                                return Ok::<_, AppError>((true, read_buf, rx_codec));
                            }

                            muxer.record_leg_rx(leg_id, n as u64);
                            let mut frames = Vec::new();

                            loop {
                                match rx_codec.decode_inbound(&mut read_buf) {
                                    Ok(Some(frame)) => frames.push(frame),
                                    Ok(None) => break,
                                    Err(e) => {
                                        if e.action == ErrorAction::Wait { break; }
                                        if e.action == ErrorAction::Drop {
                                            return Err(AppError::new(ERR_NET_TLS_TAMPER, "Ошибка шифрования", "Crypto drop"));
                                        }
                                        return Err(AppError::new(ERR_NET_TLS_TAMPER, "Сбой кодека", format!("{:?}", e)));
                                    }
                                }
                            }

                            for frame in frames {
                                if frame.header.frame_type == FrameType::Heartbeat {
                                    let m = muxer.clone();
                                    tokio::spawn(async move { m.record_pong(leg_id).await; });
                                }
                                handler.handle(frame).await;
                            }
                        }
                    }
                }
                Ok::<_, AppError>((false, read_buf, rx_codec))
            });

            // ПИШУЩАЯ ЗАДАЧА
            let mut writer_handle = tokio::spawn(async move {
                let mut outbound = outbound;
                let mut heartbeat = tokio::time::interval(HEALTH_CHECK_INTERVAL);

                let mut pending_data: Option<MuxMessage> = None;
                const INTERLEAVE_CHUNK: usize = 16384;

                loop {
                    tokio::select! {
                        biased;

                        _ = token_writer.cancelled() => break,

                        _ = heartbeat.tick() => {
                            muxer_pong.record_ping_sent(leg_id);
                            let msg = MuxMessage { stream_id: 0, frame_type: FrameType::Heartbeat, data: Bytes::new() };
                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, msg).await {
                                return Err((e, control_rx, data_rx, tx_codec));
                            }
                        }

                        msg_opt = control_rx.recv() => {
                            if let Some(msg) = msg_opt {
                                if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, msg).await {
                                    return Err((e, control_rx, data_rx, tx_codec));
                                }
                            } else { break; }
                        }

                        // 💡 ИСПРАВЛЕНИЕ 1: Мгновенно заходим в эту ветку, если есть данные
                        _ = std::future::ready(()), if pending_data.is_some() => {
                            let mut msg = pending_data.take().unwrap();

                            let chunk_size = std::cmp::min(msg.data.len(), INTERLEAVE_CHUNK);
                            let chunk_data = msg.data.split_to(chunk_size);

                            let chunk_msg = MuxMessage {
                                stream_id: msg.stream_id,
                                frame_type: msg.frame_type.clone(),
                                data: chunk_data,
                            };

                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, chunk_msg).await {
                                return Err((e, control_rx, data_rx, tx_codec));
                            }

                            if !msg.data.is_empty() {
                                pending_data = Some(msg);
                            }

                            // 💡 ИСПРАВЛЕНИЕ 1.2: Вызываем yield ЗДЕСЬ. Это заставит планировщик
                            // проверить пинги и контрольные пакеты перед отправкой следующего куска.
                            tokio::task::yield_now().await;
                        }

                        msg_opt = data_rx.recv(), if pending_data.is_none() => {
                            if let Some(msg) = msg_opt {
                                pending_data = Some(msg);
                            } else { break; }
                        }
                    }
                }
                Ok::<
                    _,
                    (
                        AppError,
                        Receiver<MuxMessage>,
                        Receiver<MuxMessage>,
                        TxCodec,
                    ),
                >((control_rx, data_rx, tx_codec))
            });

            let res: Result<(), AppError> = tokio::select! {
                res_reader = &mut reader_handle => {
                    match res_reader {
                        Ok(Ok((is_eof, r_buf, returned_rx_codec))) => {
                            self.read_buf = r_buf;
                            self.rx_codec = Some(returned_rx_codec);
                            if is_eof {
                                token.cancel();
                                let w_res = writer_handle.await.unwrap();
                                let (c_rx, d_rx, returned_tx_codec) = match w_res {
                                    Ok((c, d, t)) => (c, d, t),
                                    Err((_, c, d, t)) => (c, d, t),
                                };
                                self.control_rx = Some(c_rx);
                                self.data_rx = Some(d_rx);
                                self.tx_codec = Some(returned_tx_codec);

                                self.inbound = None;
                                self.outbound = None;
                                continue;
                            }
                            Ok(())
                        },
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(AppError::new(ERR_SYS_PANIC, "Сбой", format!("Reader panic: {}", e))),
                    }
                },
                res_writer = &mut writer_handle => {
                    match res_writer {
                        Ok(Ok((c_rx, d_rx, returned_tx_codec))) => {
                            self.control_rx = Some(c_rx);
                            self.data_rx = Some(d_rx);
                            self.tx_codec = Some(returned_tx_codec);
                            Ok(())
                        }
                        Ok(Err((e, c_rx, d_rx, returned_tx_codec))) => {
                            self.control_rx = Some(c_rx);
                            self.data_rx = Some(d_rx);
                            self.tx_codec = Some(returned_tx_codec);
                            Err(e)
                        }
                        Err(e) => Err(AppError::new(ERR_SYS_PANIC, "Сбой", format!("Writer panic: {}", e))),
                    }
                }
            };

            token.cancel();
            reader_handle.abort();
            writer_handle.abort();

            if let Err(e) = res {
                error!("TunnelEngine critical failure: {}", e);
                return Err(e);
            }

            // 💡 ИСПРАВЛЕНИЕ 2.2: И здесь тоже, если сервер словил EOF, он не должен идти на реконнект.
            if self.remote_addr.is_empty() {
                return Ok(());
            }

            info!("Tunnel iteration finished, preparing to reconnect...");
            continue;
        }
    }

    // 💡 ИЗМЕНЕНО: Принимает &mut TxCodec, синхронное и сверхбыстрое шифрование
    async fn handle_outbound(
        outbound: &mut OwnedWriteHalf,
        tx_codec: &mut TxCodec,
        msg: MuxMessage,
    ) -> Result<(), AppError> {
        let mut data = msg.data;
        let stream_id = msg.stream_id;
        let frame_type = msg.frame_type;
        let mut packets = Vec::new();

        if frame_type == FrameType::Data {
            while !data.is_empty() {
                let chunk_size = std::cmp::min(data.len(), NetworkConfig::global().tcp_chunk_size);
                let chunk = data.split_to(chunk_size);

                match tx_codec.encode_frame(stream_id, frame_type.clone(), chunk) {
                    Ok(pkt) => packets.push(pkt),
                    Err(e) => {
                        error!(stream_id, error = ?e, "Encryption failed for TCP chunk");
                        return Err(AppError::new(
                            ERR_NET_TLS_TAMPER,
                            "Ошибка шифрования пакета",
                            format!("Encryption error: {:?}", e),
                        ));
                    }
                }
            }
        } else {
            match tx_codec.encode_frame(stream_id, frame_type.clone(), data) {
                Ok(pkt) => packets.push(pkt),
                Err(e) => {
                    error!(stream_id, error = ?e, "Encryption failed for control/udp frame");
                    return Err(AppError::new(
                        ERR_NET_TLS_TAMPER,
                        "Ошибка шифрования пакета",
                        format!("Encryption error: {:?}", e),
                    ));
                }
            }
        }

        for pkt in packets {
            let write_future = outbound.write_all(&pkt);
            // 💡 ИЗМЕНЕНО: Увеличен таймаут отправки до 20 секунд для совместимости с агрессивным BBR
            if let Err(_) =
                tokio::time::timeout(std::time::Duration::from_secs(20), write_future).await
            {
                error!(stream_id, "🔥 Physical leg STUCK on write. Killing leg.");
                return Err(AppError::new(
                    ERR_INFRA_TIMEOUT,
                    "Таймаут отправки",
                    "Physical leg STUCK on write",
                ));
            }
        }
        Ok(())
    }
}
