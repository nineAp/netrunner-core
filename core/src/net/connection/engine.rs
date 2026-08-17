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

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};
use netrunner_logger::{
    AppError, ERR_INFRA_TIMEOUT, ERR_NET_TLS_TAMPER, ERR_SYS_PANIC, error, info,
};
use rand::RngExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::Receiver,
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{
    net::{
        FALLBACK_CONNECT_TIMEOUT, HEALTH_CHECK_INTERVAL, MAX_INTERNAL_RECONNECT_ATTEMPTS,
        MAX_RECONNECT_BACKOFF_MS, RECONNECT_BACKOFF_BASE, RECONNECT_BACKOFF_JITTER_MS,
        TUNNEL_INTERLEAVE_CHUNK, TUNNEL_MAX_BUFFER_SIZE, TUNNEL_READ_RESERVE,
        connection::{
            handler::StreamHandler,
            muxer::{MuxMessage, TcpSocketStats},
        },
    },
    nrxp::{ErrorAction, FrameType, MAX_FRAME_PAYLOAD, RxCodec, TxCodec},
};

/// Per-leg userspace flow queue.  The mpsc channel remains the bounded ingress
/// and backpressure mechanism; once messages reach the writer they are split by
/// `stream_id` so a bulk stream cannot monopolise every dequeue opportunity.
///
/// Streams that have just become active live in `new_streams`; a stream that
/// still has data after one quantum moves to `old_streams`.  This is the useful
/// latency property of FQ-CoDel/DRR without packet dropping: sparse interactive
/// flows get one prompt turn, while continuously-backlogged flows round-robin.
#[derive(Default)]
struct FairDataQueue {
    streams: HashMap<u32, VecDeque<MuxMessage>>,
    new_streams: VecDeque<u32>,
    old_streams: VecDeque<u32>,
    queued_messages: usize,
}

impl FairDataQueue {
    fn push(&mut self, message: MuxMessage) {
        let stream_id = message.stream_id;
        if let Some(queue) = self.streams.get_mut(&stream_id) {
            queue.push_back(message);
        } else {
            let mut queue = VecDeque::new();
            queue.push_back(message);
            self.streams.insert(stream_id, queue);
            self.new_streams.push_back(stream_id);
        }
        self.queued_messages += 1;
    }

    fn is_empty(&self) -> bool {
        self.queued_messages == 0
    }

    fn queued_messages(&self) -> usize {
        self.queued_messages
    }

    fn active_streams(&self) -> usize {
        self.streams.len()
    }

    /// Returns at most `quantum` bytes for stream-oriented Data.  UDP datagrams
    /// are never split because their message boundary is semantic.
    fn pop_chunk(&mut self, quantum: usize) -> Option<MuxMessage> {
        let stream_id = self
            .new_streams
            .pop_front()
            .or_else(|| self.old_streams.pop_front())?;
        let quantum = quantum.max(1);

        let (chunk, stream_empty) = {
            let queue = self.streams.get_mut(&stream_id)?;
            let front = queue.front_mut()?;
            let chunk = if front.frame_type == FrameType::Data && front.data.len() > quantum {
                MuxMessage {
                    stream_id,
                    frame_type: front.frame_type,
                    data: front.data.split_to(quantum),
                }
            } else {
                self.queued_messages = self.queued_messages.saturating_sub(1);
                queue.pop_front().expect("fair queue front disappeared")
            };
            (chunk, queue.is_empty())
        };

        if stream_empty {
            self.streams.remove(&stream_id);
        } else {
            self.old_streams.push_back(stream_id);
        }
        Some(chunk)
    }
}

#[cfg(target_os = "linux")]
fn read_tcp_socket_stats(outbound: &OwnedWriteHalf) -> Option<TcpSocketStats> {
    use std::os::fd::AsRawFd;

    let fd = outbound.as_ref().as_raw_fd();
    let mut info = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };

    // Linux exposes bytes accepted by the socket but not yet handed to TCP via
    // SIOCOUTQNSD.  This is the queue that channel capacity alone cannot see.
    let mut notsent_bytes: libc::c_int = 0;
    let notsent_rc =
        unsafe { libc::ioctl(fd, libc::SIOCOUTQNSD as libc::Ioctl, &mut notsent_bytes) };
    if notsent_rc != 0 {
        notsent_bytes = 0;
    }

    // Older libc releases stop `tcp_info` at `tcpi_total_retrans`, so estimate
    // the current delivery ceiling from cwnd / RTT instead of depending on the
    // newer `tcpi_delivery_rate` tail field.  RTT is expressed in microseconds.
    let delivery_rate = if info.tcpi_rtt == 0 {
        0
    } else {
        (info.tcpi_snd_cwnd as u64)
            .saturating_mul(info.tcpi_snd_mss.max(1) as u64)
            .saturating_mul(1_000_000)
            / info.tcpi_rtt as u64
    };
    Some(TcpSocketStats {
        notsent_bytes: notsent_bytes.max(0) as u64,
        unacked_bytes: info.tcpi_unacked as u64 * info.tcpi_snd_mss.max(1) as u64,
        delivery_rate,
        total_retrans: info.tcpi_total_retrans,
    })
}

#[cfg(target_os = "android")]
fn read_tcp_socket_stats(outbound: &OwnedWriteHalf) -> Option<TcpSocketStats> {
    use std::os::fd::AsRawFd;

    // Android's libc bindings omit `tcp_info`, but the kernel still exposes the
    // not-yet-sent byte count that matters most for avoiding a queued leg.
    let fd = outbound.as_ref().as_raw_fd();
    let mut notsent_bytes: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(fd, libc::SIOCOUTQNSD as libc::Ioctl, &mut notsent_bytes) };
    (rc == 0).then_some(TcpSocketStats {
        notsent_bytes: notsent_bytes.max(0) as u64,
        ..TcpSocketStats::default()
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_tcp_socket_stats(_outbound: &OwnedWriteHalf) -> Option<TcpSocketStats> {
    None
}

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
    /// Bearer-токен клиента (пусто — авторизация выключена/не залогинен),
    /// нужен для того же внутреннего реконнекта, что и `decoy_sni` выше.
    pub auth_token: Arc<str>,
    /// Учётные данные ноды (см. [`crate::crypto::identity`]) — по той же
    /// причине, что и два поля выше: реконнект проводит хендшейк заново и
    /// обязан пройти его по той же схеме, что и первичное подключение.
    /// Молчаливый откат на анонимную схему при реконнекте означал бы, что
    /// достаточно оборвать ноге TCP, чтобы снять с неё аутентификацию.
    pub identity: Option<crate::Identity>,
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
    ) -> Result<(OwnedReadHalf, OwnedWriteHalf, RxCodec, TxCodec, BytesMut), AppError> {
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
            &self.auth_token,
            self.identity.as_ref(),
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
                    Ok((new_in, new_out, new_rx, new_tx, new_tail)) => {
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
                        // Остаток буфера хендшейка: сервер шлёт cover-flight
                        // сразу за ServerHello, и эти записи обычно уже лежат
                        // здесь. Потерять их — рассинхронизировать nonce.
                        self.read_buf = new_tail;
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
                        error!(
                            "CRITICAL: Read buffer exceeded 1MB (OOM Protection). Dropping connection!"
                        );
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

                // Heartbeat: интервал с джиттером и отступом на простое —
                // см. `next_heartbeat_delay`. Раньше здесь был
                // `tokio::time::interval(HEALTH_CHECK_INTERVAL)`, то есть
                // ровно 3,000 с без разброса, вечно и на каждой из ног.
                let mut hb_idle_streak: u32 = 0;
                let mut wrote_since_hb = false;
                let mut hb_deadline = tokio::time::Instant::now() + Self::next_heartbeat_delay(0);

                let mut fair_data = FairDataQueue::default();
                // Do not turn the writer-local fair queues into an unbounded
                // second buffer.  At most one channel's worth is classified at
                // a time; the original mpsc channel keeps applying backpressure.
                let fair_queue_cap = data_rx.max_capacity().max(1);
                let mut data_closed = false;
                let mut tcp_info_tick =
                    tokio::time::interval(std::time::Duration::from_millis(250));
                tcp_info_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    // Pull a bounded snapshot of currently waiting streams before
                    // choosing the next one.  Without this drain, a continuously
                    // ready bulk stream would keep the `biased` select branch hot
                    // and newly-arrived sparse streams would remain invisible.
                    while fair_data.queued_messages() < fair_queue_cap && !data_closed {
                        match data_rx.try_recv() {
                            Ok(msg) => fair_data.push(msg),
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                data_closed = true;
                            }
                        }
                    }
                    tokio::select! {
                        biased;

                        _ = token_writer.cancelled() => break,

                        _ = tokio::time::sleep_until(hb_deadline) => {
                            hb_idle_streak = if wrote_since_hb {
                                0
                            } else {
                                hb_idle_streak.saturating_add(1)
                            };
                            wrote_since_hb = false;
                            hb_deadline = tokio::time::Instant::now()
                                + Self::next_heartbeat_delay(hb_idle_streak);

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

                        _ = tcp_info_tick.tick() => {
                            if let Some(sample) = read_tcp_socket_stats(&outbound) {
                                muxer_pong.record_tcp_socket_stats(leg_id, sample);
                            }
                        }

                        msg_opt = control_rx.recv() => {
                            if let Some(msg) = msg_opt {
                                let sid = msg.stream_id;
                                wrote_since_hb = true;
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

                        _ = std::future::ready(()), if !fair_data.is_empty() => {
                            wrote_since_hb = true;

                            // With competing streams, one turn is exactly one full
                            // TLS/NRXP record.  A lone bulk stream retains the old
                            // RTT-adaptive batching and therefore its throughput.
                            let quantum = if fair_data.active_streams() > 1 {
                                TUNNEL_INTERLEAVE_CHUNK
                            } else {
                                crate::net::connection::muxer::adaptive_batch_chunk(
                                    TUNNEL_INTERLEAVE_CHUNK,
                                )
                            };
                            let chunk_msg = fair_data
                                .pop_chunk(quantum)
                                .expect("fair data queue became empty during dequeue");
                            let chunk_sid = chunk_msg.stream_id;
                            let chunk_len = chunk_msg.data.len() as u64;

                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, chunk_msg).await {
                                crate::net::diagnostics::send_diag_event(
                                    crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                        leg_id, stream_id: chunk_sid,
                                    },
                                );
                                return Err((e, control_rx, data_rx, tx_codec));
                            }
                            muxer_pong.record_leg_data_drained(leg_id, chunk_len);

                            // Give heartbeat/control and newly-arrived sparse data
                            // a chance before the next flow-queue quantum.
                            tokio::task::yield_now().await;
                        }

                        msg_opt = data_rx.recv(), if !data_closed && fair_data.queued_messages() < fair_queue_cap => {
                            if let Some(msg) = msg_opt {
                                fair_data.push(msg);
                            } else {
                                data_closed = true;
                            }
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

    /// Задержка до следующего heartbeat'а: база с джиттером плюс отступ на простое.
    ///
    /// Раньше heartbeat висел на `tokio::time::interval(HEALTH_CHECK_INTERVAL)` —
    /// ровно 3,000 с, бесконечно, на каждой из ног. Два следствия:
    ///
    /// 1. Автокорреляция межпакетных интервалов на лаге 3 с давала узкий пик,
    ///    которого не бывает у браузера: HTTP/2 PING он шлёт по необходимости,
    ///    а на простое молчит.
    /// 2. Пустая сессия стоила порядка мегабайта в час в каждую сторону
    ///    (4 ноги × 1200 записей в час), а на мобильном клиенте — ещё и 1200
    ///    пробуждений радио на ногу.
    ///
    /// `idle_streak` — сколько интервалов подряд по ноге не проехало ни одного
    /// полезного кадра. Множитель ограничен восемью (до ~24 с при базе 3 с);
    /// вместе с [`LEG_PONG_FRESHNESS`](crate::net::LEG_PONG_FRESHNESS) это и
    /// даёт основное сокращение холостого трафика: health-check видит свежий
    /// PONG от heartbeat'а и свою пробу не отправляет вовсе.
    ///
    /// Верхняя граница выбрана так, чтобы самый медленный heartbeat с джиттером
    /// (3 с × 8 × 1,3 ≈ 31 с) оставался внутри окна свежести (45 с) — иначе
    /// health-check начал бы добивать пробами ровно то, что здесь экономится.
    fn next_heartbeat_delay(idle_streak: u32) -> std::time::Duration {
        const MAX_IDLE_MULTIPLIER: u32 = 8;
        /// Разброс вокруг базы, в процентах.
        const JITTER_PCT: u64 = 30;

        let multiplier = (1 + idle_streak).min(MAX_IDLE_MULTIPLIER) as u64;
        let base_ms = HEALTH_CHECK_INTERVAL.as_millis() as u64 * multiplier;
        let jitter_ms = base_ms * JITTER_PCT / 100;

        std::time::Duration::from_millis(
            base_ms - jitter_ms + rand::rng().random_range(0..=jitter_ms * 2),
        )
    }

    /// Шифрует сообщение в один или несколько кадров и пишет их в сокет.
    ///
    /// `Data` режется на кадры по [`MAX_FRAME_PAYLOAD`]; управляющие/UDP идут одним
    /// кадром. Вся пачка уходит в [`TxCodec::encode_batch`] одним вызовом: кадры
    /// укладываются в минимальное число TLS-записей (несколько кадров на запись,
    /// если помещаются), и на выходе получается один непрерывный буфер — то есть
    /// один `write_all` вместо N (аналог sendmmsg для байт-потока: меньше
    /// syscalls) и меньше заголовков записей на проводе.
    ///
    /// Срабатывает адаптивный по RTT дедлайн записи
    /// ([`adaptive_write_timeout`](super::muxer::adaptive_write_timeout)) — чтобы
    /// медленная, но живая нога не убивалась по жёсткому тайм-ауту.
    async fn handle_outbound(
        outbound: &mut OwnedWriteHalf,
        tx_codec: &mut TxCodec,
        msg: MuxMessage,
    ) -> Result<(), AppError> {
        let mut data = msg.data;
        let stream_id = msg.stream_id;
        let frame_type = msg.frame_type;
        let mut frames = Vec::new();

        if frame_type == FrameType::Data {
            while !data.is_empty() {
                let chunk_size = std::cmp::min(data.len(), MAX_FRAME_PAYLOAD);
                frames.push((stream_id, frame_type, data.split_to(chunk_size)));
            }
        } else {
            frames.push((stream_id, frame_type, data));
        }

        let wire = tx_codec.encode_batch(frames).map_err(|e| {
            error!(stream_id, error = ?e, "Encryption failed for outbound batch");
            AppError::new(
                ERR_NET_TLS_TAMPER,
                "Ошибка шифрования пакета",
                format!("Encryption error: {:?}", e),
            )
        })?;

        // Adaptive write deadline: floor of 20 s (BBR-friendly), but scales with
        // the live RTT so a high-latency path (RTT > 2.5 s) doesn't trip a flat
        // timeout on a leg that is slow rather than dead. Killing such a leg is
        // what set off the leg-drop → stream-close cascade.
        let write_timeout = crate::net::connection::muxer::adaptive_write_timeout(
            std::time::Duration::from_secs(20),
        );
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

        if !wire.is_empty() {
            let write_future = outbound.write_all(&wire);
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

#[cfg(test)]
mod fair_data_queue_tests {
    use super::*;

    fn message(stream_id: u32, frame_type: FrameType, data: &'static [u8]) -> MuxMessage {
        MuxMessage {
            stream_id,
            frame_type,
            data: Bytes::from_static(data),
        }
    }

    #[test]
    fn sparse_stream_preempts_an_already_backlogged_stream() {
        let mut queue = FairDataQueue::default();
        queue.push(message(1, FrameType::Data, b"abcdefgh"));

        let first = queue.pop_chunk(4).unwrap();
        assert_eq!(first.stream_id, 1);
        assert_eq!(&first.data[..], b"abcd");

        queue.push(message(3, FrameType::Data, b"x"));
        let sparse = queue.pop_chunk(4).unwrap();
        assert_eq!(sparse.stream_id, 3);
        assert_eq!(&sparse.data[..], b"x");

        let bulk = queue.pop_chunk(4).unwrap();
        assert_eq!(bulk.stream_id, 1);
        assert_eq!(&bulk.data[..], b"efgh");
        assert!(queue.is_empty());
    }

    #[test]
    fn competing_streams_rotate_by_one_quantum() {
        let mut queue = FairDataQueue::default();
        queue.push(message(1, FrameType::Data, b"abcdefgh"));
        queue.push(message(3, FrameType::Data, b"ABCDEFGH"));

        let turns: Vec<u32> = (0..4)
            .map(|_| queue.pop_chunk(4).unwrap().stream_id)
            .collect();

        assert_eq!(turns, vec![1, 3, 1, 3]);
        assert!(queue.is_empty());
    }

    #[test]
    fn messages_keep_fifo_order_within_one_stream() {
        let mut queue = FairDataQueue::default();
        queue.push(message(7, FrameType::Data, b"first"));
        queue.push(message(7, FrameType::Data, b"second"));

        assert_eq!(&queue.pop_chunk(64).unwrap().data[..], b"first");
        assert_eq!(&queue.pop_chunk(64).unwrap().data[..], b"second");
        assert!(queue.is_empty());
    }

    #[test]
    fn udp_datagram_is_never_split_by_the_fair_quantum() {
        let mut queue = FairDataQueue::default();
        queue.push(message(9, FrameType::UdpData, b"one-datagram"));

        let datagram = queue.pop_chunk(2).unwrap();
        assert_eq!(datagram.frame_type, FrameType::UdpData);
        assert_eq!(&datagram.data[..], b"one-datagram");
        assert!(queue.is_empty());
    }
}
