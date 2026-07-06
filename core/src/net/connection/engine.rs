//! Движок одной ноги туннеля: жизненный цикл TCP-соединения и его reader/writer.
//!
//! [`TunnelEngine`] владеет одним физическим TCP+TLS-соединением и крутит его в
//! [`run`](TunnelEngine::run), пока нога жива. Внутри одной итерации соединение
//! расщепляется на две параллельные задачи tokio:
//!
//! - **Reader** — читает байты из сокета, прогоняет через [`RxCodec`]
//!   (расшифровка + сборка кадров), PONG'и инлайн обновляют RTT, остальные кадры
//!   уходят в [`StreamHandler`].
//! - **Writer** — `biased`-`select!` по приоритету: heartbeat → control → data.
//!   Данные режутся на interleave-чанки (адаптивно под RTT) и шифруются
//!   [`TxCodec`] в [`handle_outbound`](TunnelEngine::handle_outbound); несколько
//!   кадров коалесятся в один `write_all` (экономия syscalls).
//!
//! При обрыве (EOF/ошибка) задачи останавливаются, их состояние (кодеки,
//! приёмники, буфер) возвращается в `self`, и — если это клиент — нога идёт на
//! переподключение с экспоненциальным backoff+jitter. Сервер (`remote_addr`
//! пуст) при обрыве просто завершает задачу: реконнект инициирует клиент.

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
        FALLBACK_CONNECT_TIMEOUT, HEALTH_CHECK_INTERVAL, MAX_INTERNAL_RECONNECT_ATTEMPTS,
        MAX_RECONNECT_BACKOFF_MS, RECONNECT_BACKOFF_BASE, RECONNECT_BACKOFF_JITTER_MS,
        TUNNEL_INTERLEAVE_CHUNK, TUNNEL_MAX_BUFFER_SIZE, TUNNEL_READ_RESERVE,
    },
    nrxp::{ErrorAction, FrameType, RxCodec, TxCodec, MAX_FRAME_PAYLOAD},
};

/// Состояние ноги: работает или в процессе переподключения.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LegStatus {
    Active,
    Reconnecting,
}

/// Состояние и ресурсы одной ноги туннеля.
///
/// Половинки сокета, кодеки, приёмники каналов и буфер чтения хранятся в
/// [`Option`], потому что на время работы reader/writer они «выдаются» в задачи
/// через `take()`, а по завершении итерации возвращаются обратно — это позволяет
/// переиспользовать кодеки (с их счётчиками nonce) между итерациями без Arc/Mutex.
pub(crate) struct TunnelEngine {
    /// Читающая половина TCP-сокета (выдаётся reader-задаче).
    pub inbound: Option<OwnedReadHalf>,
    /// Пишущая половина TCP-сокета (выдаётся writer-задаче).
    pub outbound: Option<OwnedWriteHalf>,
    /// Адрес удалённой стороны; **пустой у сервера** (сервер не реконнектит).
    pub remote_addr: String,
    /// Идентификатор сессии (для логов и хендшейка реконнекта).
    pub session_id: String,
    /// Текущий статус ноги.
    pub leg_status: LegStatus,
    /// Кодек расшифровки входящего потока.
    pub rx_codec: Option<RxCodec>,
    /// Кодек шифрования исходящего потока.
    pub tx_codec: Option<TxCodec>,
    /// Накопительный буфер чтения из сокета.
    pub read_buf: BytesMut,
    /// Приёмник управляющих сообщений от muxer (Close/Heartbeat).
    pub control_rx: Option<Receiver<MuxMessage>>,
    /// Приёмник сообщений данных от muxer.
    pub data_rx: Option<Receiver<MuxMessage>>,
    /// Обработчик входящих кадров.
    pub handler: Arc<StreamHandler>,
    /// Идентификатор этой ноги.
    pub leg_id: u32,
    /// Общий мультиплексор туннеля.
    pub muxer: Arc<crate::net::connection::muxer::Muxer>,
    /// SNI поддельного `ClientHello` (атрибут, задаётся снаружи —
    /// [`ClientHandler::connect`](crate::net::connection::ClientHandler::connect));
    /// нужен для внутреннего реконнекта в [`attempt_reconnect`](Self::attempt_reconnect).
    pub decoy_sni: Arc<str>,
}

impl TunnelEngine {
    /// Переподключает ногу: заново резолвит хост (подхватывает смену IP/DNS),
    /// создаёт TCP-сокет с тюнингом буферов и проводит хендшейк заново. Возвращает
    /// свежие половинки сокета и кодеки.
    ///
    /// Профиль браузера выбирается через [`BrowserProfile::for_session`] по
    /// `self.session_id` — тот же стабильный отпечаток, что и при первичном
    /// установлении ноги в
    /// [`ClientHandler::establish_leg`](crate::net::connection::ClientHandler::establish_leg),
    /// а не новый на каждую попытку реконнекта (см. doc на `for_session`).
    pub async fn attempt_reconnect(
        &mut self,
    ) -> Result<(OwnedReadHalf, OwnedWriteHalf, RxCodec, TxCodec), AppError> {
        info!("🔄 Attempting reconnect to {}", self.remote_addr);

        // Re-resolve the hostname each time so a server IP change or DNS
        // failover is picked up automatically.
        let mut addrs = tokio::net::lookup_host(&self.remote_addr)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "DNS при реконнекте", e.to_string()))?;
        let addr = addrs.next().ok_or_else(|| {
            AppError::new(ERR_INFRA_TIMEOUT, "Нет IP", "No IPs for reconnect addr")
        })?;

        let socket = (if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        })
        .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сокет", e.to_string()))?;
        let _ = socket.set_send_buffer_size(crate::net::TUNNEL_SOCKET_SNDBUF);
        let _ = socket.set_recv_buffer_size(crate::net::TUNNEL_SOCKET_RCVBUF);

        let stream = tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, socket.connect(addr))
            .await
            .map_err(|_| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", "Reconnect timeout"))?
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", e.to_string()))?;

        let profile = crate::tlseng::BrowserProfile::for_session(&self.session_id);
        crate::net::ClientHandler::perform_handshake(
            stream,
            &self.session_id,
            self.leg_id,
            profile,
            &self.decoy_sni,
        )
        .await
    }

    /// Главный цикл ноги: переподключение (при нужде) → запуск reader/writer →
    /// ожидание завершения одной из задач → сбор состояния обратно → повтор.
    ///
    /// Возвращает `Ok(())` при штатном завершении (например, сервер словил EOF);
    /// `Err` — когда исчерпан внутренний лимит реконнектов
    /// ([`MAX_INTERNAL_RECONNECT_ATTEMPTS`]) и управление надо вернуть внешнему
    /// циклу `establish_leg` (он перерезолвит DNS и сбросит счётчики).
    #[instrument(skip_all, fields(leg_id = self.leg_id))]
    pub async fn run(mut self) -> Result<(), AppError> {
        // Tracks consecutive internal reconnect failures.  Resets to 0 on
        // success.  When it reaches MAX_INTERNAL_RECONNECT_ATTEMPTS the engine
        // returns Err so the outer establish_leg loop gets control: it re-runs
        // DNS, resets its own counters, and emits proper diagnostic events.
        let mut internal_attempt: u32 = 0;

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
                        internal_attempt = 0; // successful reconnect — reset counter

                        let cap = crate::net::NetworkConfig::global().channel_capacity;
                        let (control_tx, control_rx) =
                            tokio::sync::mpsc::channel::<MuxMessage>(cap);
                        let (data_tx, data_rx) = tokio::sync::mpsc::channel::<MuxMessage>(cap);
                        self.muxer.add_leg(self.leg_id, control_tx, data_tx);
                        self.control_rx = Some(control_rx);
                        self.data_rx = Some(data_rx);

                        self.inbound = Some(new_in);
                        self.outbound = Some(new_out);
                        self.rx_codec = Some(new_rx);
                        self.tx_codec = Some(new_tx);
                        self.leg_status = LegStatus::Active;
                        info!("✅ Leg {} reconnected successfully", self.leg_id);
                    }
                    Err(e) => {
                        internal_attempt += 1;

                        // Emit a diagnostic event so the snapshot system (and
                        // operator dashboards) can see we're stuck, even though
                        // the outer establish_leg loop hasn't returned yet.
                        crate::net::diagnostics::send_diag_event(
                            crate::net::diagnostics::DiagnosticsEvent::LegReconnecting {
                                leg_id: self.leg_id,
                                attempt: internal_attempt,
                            },
                        );

                        if internal_attempt >= MAX_INTERNAL_RECONNECT_ATTEMPTS {
                            // Give up so the outer loop re-runs DNS, resets
                            // its state, and records the failure in counters.
                            error!(
                                "Leg {} giving up after {} consecutive reconnect failures — handing off to outer loop",
                                self.leg_id, internal_attempt
                            );
                            return Err(e);
                        }

                        error!(
                            "Reconnect failed for leg {} (attempt {}/{}): {}",
                            self.leg_id, internal_attempt, MAX_INTERNAL_RECONNECT_ATTEMPTS, e
                        );

                        // Exponential back-off: 2 s, 4 s, 8 s, 16 s, 30 s (cap).
                        // The shift is capped at 4 to avoid overflow (2^4 = 16).
                        let exp_ms = RECONNECT_BACKOFF_BASE.as_millis() as u64
                            * (1u64 << internal_attempt.saturating_sub(1).min(4));
                        let jitter = rand::random::<u64>() % RECONNECT_BACKOFF_JITTER_MS;
                        let backoff_ms = (exp_ms + jitter).min(MAX_RECONNECT_BACKOFF_MS);
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
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
                loop {
                    if read_buf.len() > TUNNEL_MAX_BUFFER_SIZE {
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
                    read_buf.reserve(TUNNEL_READ_RESERVE);

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
                                    // record_pong does no .await internally, so run it inline:
                                    // a spawn+Arc-clone per PONG was pure scheduler churn.
                                    muxer.record_pong(leg_id).await;
                                }
                                let _ = handler.handle(frame).await;
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

                loop {
                    tokio::select! {
                        biased;

                        _ = token_writer.cancelled() => break,

                        _ = heartbeat.tick() => {
                            muxer_pong.record_ping_sent(leg_id);
                            let msg = MuxMessage { stream_id: 0, frame_type: FrameType::Heartbeat, data: Bytes::new() };
                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, msg).await {
                                crate::net::diagnostics::send_diag_event(
                                    crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                        leg_id, stream_id: 0,
                                    },
                                );
                                return Err((e, control_rx, data_rx, tx_codec));
                            }
                        }

                        msg_opt = control_rx.recv() => {
                            if let Some(msg) = msg_opt {
                                let sid = msg.stream_id;
                                if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, msg).await {
                                    crate::net::diagnostics::send_diag_event(
                                        crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                            leg_id, stream_id: sid,
                                        },
                                    );
                                    return Err((e, control_rx, data_rx, tx_codec));
                                }
                            } else { break; }
                        }

                        // 💡 ИСПРАВЛЕНИЕ 1: Мгновенно заходим в эту ветку, если есть данные
                        _ = std::future::ready(()), if pending_data.is_some() => {
                            let mut msg = pending_data.take().unwrap();

                            // #4 Adaptive batch: under high RTT take a bigger interleave
                            // chunk so more frames coalesce into one write in
                            // handle_outbound (#3); at low RTT stay small for fairness.
                            let interleave_chunk = crate::net::connection::muxer::adaptive_batch_chunk(
                                TUNNEL_INTERLEAVE_CHUNK,
                            );
                            let chunk_size = std::cmp::min(msg.data.len(), interleave_chunk);
                            let chunk_data = msg.data.split_to(chunk_size);

                            let chunk_msg = MuxMessage {
                                stream_id: msg.stream_id,
                                frame_type: msg.frame_type.clone(),
                                data: chunk_data,
                            };
                            let chunk_sid = chunk_msg.stream_id;

                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, chunk_msg).await {
                                crate::net::diagnostics::send_diag_event(
                                    crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                        leg_id, stream_id: chunk_sid,
                                    },
                                );
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

    /// Шифрует сообщение в один или несколько кадров и пишет их в сокет.
    ///
    /// `Data` режется на кадры по [`MAX_FRAME_PAYLOAD`]; управляющие/UDP идут одним
    /// кадром. Срабатывает адаптивный по RTT дедлайн записи
    /// ([`adaptive_write_timeout`](super::muxer::adaptive_write_timeout)) — чтобы
    /// медленная, но живая нога не убивалась по жёсткому тайм-ауту. Несколько
    /// кадров коалесятся в один `write_all` (аналог sendmmsg для байт-потока:
    /// меньше syscalls); одиночный кадр пишется напрямую без лишней копии.
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
                let chunk_size = std::cmp::min(data.len(), MAX_FRAME_PAYLOAD);
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

        // Adaptive write deadline: floor of 20 s (BBR-friendly), but scales with
        // the live RTT so a high-latency path (RTT > 2.5 s) doesn't trip a flat
        // timeout on a leg that is slow rather than dead. Killing such a leg is
        // what set off the leg-drop → stream-close cascade.
        let write_timeout = crate::net::connection::muxer::adaptive_write_timeout(
            std::time::Duration::from_secs(20),
        );
        // #3 Syscall batching (sendmmsg-analog for a TCP byte stream): when a Data
        // message produced several MAX_FRAME_PAYLOAD frames, coalesce them into ONE
        // contiguous buffer and issue a single write_all instead of N — fewer
        // User→Kernel transitions under exactly the high-throughput conditions that
        // were producing tunnel_write_stuck. The single-frame case (control/UDP and
        // ≤16 KB payloads) keeps the zero-copy direct write with no extra copy.
        let stuck = || -> AppError {
            error!(stream_id, "🔥 Physical leg STUCK on write. Killing leg.");
            // Increment counter; the call site in run() emits the full event
            // with the correct leg_id since handle_outbound is a static fn.
            crate::net::diagnostics::DIAG_COUNTERS
                .tunnel_write_stalls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            AppError::new(
                ERR_INFRA_TIMEOUT,
                "Таймаут отправки",
                "Physical leg STUCK on write",
            )
        };

        if packets.len() == 1 {
            let write_future = outbound.write_all(&packets[0]);
            if tokio::time::timeout(write_timeout, write_future)
                .await
                .is_err()
            {
                return Err(stuck());
            }
        } else if !packets.is_empty() {
            let total: usize = packets.iter().map(|p| p.len()).sum();
            let mut batch = BytesMut::with_capacity(total);
            for pkt in &packets {
                batch.extend_from_slice(pkt);
            }
            let write_future = outbound.write_all(&batch);
            if tokio::time::timeout(write_timeout, write_future)
                .await
                .is_err()
            {
                return Err(stuck());
            }
        }
        Ok(())
    }
}
