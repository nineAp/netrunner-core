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
    error, info, warn, AppError, ERR_INFRA_TIMEOUT, ERR_NET_TLS_TAMPER, ERR_SYS_PANIC,
};
use rand::RngExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Receiver,
};
use tracing::instrument;

use super::buftune::{self, BufTuner, Dir as BufDir};

use crate::{
    net::{
        connection::{
            connection::{TunnelReadHalf, TunnelWriteHalf},
            handler::StreamHandler,
            muxer::{MuxMessage, TcpSocketStats},
        },
        FALLBACK_CONNECT_TIMEOUT, HEALTH_CHECK_INTERVAL, LEG_FLAP_WINDOW,
        MAX_INTERNAL_RECONNECT_ATTEMPTS, MAX_RECONNECT_BACKOFF_MS, RECONNECT_BACKOFF_BASE,
        RECONNECT_BACKOFF_JITTER_MS, TUNNEL_INTERLEAVE_CHUNK, TUNNEL_MAX_BUFFER_SIZE,
        TUNNEL_READ_RESERVE,
    },
    nrxp::{ErrorAction, FrameType, RxCodec, TxCodec, MAX_FRAME_PAYLOAD},
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

    /// Empties the whole queue, preserving per-stream FIFO order (cross-stream
    /// order is irrelevant here — this only runs on the leg-death/shutdown path,
    /// never on the hot loop).  Used to hand back everything a dying leg's
    /// writer had already pulled off the mpsc channel but not yet written to
    /// the socket, so the caller can requeue it onto a surviving leg instead of
    /// silently dropping it with the writer task — see `TunnelEngine::run`.
    fn drain_all(&mut self) -> Vec<MuxMessage> {
        let mut out = Vec::with_capacity(self.queued_messages);
        let stream_ids: Vec<u32> = self
            .new_streams
            .drain(..)
            .chain(self.old_streams.drain(..))
            .collect();
        for stream_id in stream_ids {
            if let Some(queue) = self.streams.remove(&stream_id) {
                out.extend(queue);
            }
        }
        self.queued_messages = 0;
        out
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
fn read_tcp_socket_stats(outbound: &TunnelWriteHalf) -> Option<TcpSocketStats> {
    use std::os::fd::AsRawFd;

    let fd = outbound.tcp_owned()?.as_ref().as_raw_fd();
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
fn read_tcp_socket_stats(outbound: &TunnelWriteHalf) -> Option<TcpSocketStats> {
    use std::os::fd::AsRawFd;

    // Android's libc bindings omit `tcp_info`, but the kernel still exposes the
    // not-yet-sent byte count that matters most for avoiding a queued leg.
    let fd = outbound.tcp_owned()?.as_ref().as_raw_fd();
    let mut notsent_bytes: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(fd, libc::SIOCOUTQNSD as libc::Ioctl, &mut notsent_bytes) };
    (rc == 0).then_some(TcpSocketStats {
        notsent_bytes: notsent_bytes.max(0) as u64,
        ..TcpSocketStats::default()
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_tcp_socket_stats(_outbound: &TunnelWriteHalf) -> Option<TcpSocketStats> {
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
    pub inbound: Option<TunnelReadHalf>,
    /// Пишущая половина TCP-сокета (выдаётся writer-задаче).
    pub outbound: Option<TunnelWriteHalf>,
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
    /// User-selected cipher carried across reconnect handshakes.
    pub data_cipher_preference: crate::DataCipherPreference,
    /// User-selected routing policy carried across reconnect handshakes.
    pub mesh_route_preference: crate::net::MeshRoutePreference,
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
    ) -> Result<
        (
            TunnelReadHalf,
            TunnelWriteHalf,
            RxCodec,
            TxCodec,
            BytesMut,
            crate::crypto::DatagramRoot,
        ),
        AppError,
    > {
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
        // Receive buffer at its ceiling BEFORE connect: the TCP window scale is fixed
        // at the handshake, so this is what lets the adaptive tuner (connection::
        // buftune) grow the window later. It is brought down to a small initial
        // value right after the handshake and then follows the measured BDP.
        let _ = socket.set_recv_buffer_size(crate::net::BUF_CAP as u32);

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
            self.data_cipher_preference,
            self.mesh_route_preference,
        )
        .await
    }

    /// Пере-поднимает физическую UDP-ногу после успешного реконнекта, если
    /// заявка на попытку свободна. Заявку снимает только смена сети
    /// (`remove_all_legs` → `Muxer::reset_datagram_leg_claim`), поэтому обычный
    /// реконнект одной ноги сюда не приводит (заявка занята → `try_claim`
    /// вернёт false), а смена сети — приводит: ровно одна переподключившаяся
    /// нога выигрывает заявку и поднимает попытку со свежим корнем ЭТОЙ ноги, а
    /// значит свежими ключами (bug #2).
    ///
    /// Только клиент: у сервера `remote_addr` пуст и до реконнекта дело не
    /// доходит (см. ветку `remote_addr.is_empty()` в [`run`](Self::run)).
    fn rearm_datagram_leg(&self, datagram_root: crate::crypto::DatagramRoot) {
        if self.remote_addr.is_empty() {
            return;
        }
        let claim =
            crate::crypto::DatagramKeyMaterial::derive_from_root(datagram_root, true).leg_token();
        if !self.muxer.try_claim_datagram_leg_token(claim) {
            return;
        }
        let muxer = self.muxer.clone();
        let remote_addr = self.remote_addr.clone();
        let decoy_sni = self.decoy_sni.clone();
        let session_id = self.session_id.clone();
        tokio::spawn(async move {
            // Тот же адрес, что и у пересобранной TCP-ноги — резолвим заново
            // (роуминг/DNS-failover мог сменить IP), как и `attempt_reconnect`.
            let addr = match tokio::net::lookup_host(&remote_addr).await {
                Ok(mut it) => match it.next() {
                    Some(a) => a,
                    None => return,
                },
                Err(_) => return,
            };
            crate::net::connection::dgram_engine::attempt_client_datagram_leg(
                muxer,
                addr,
                decoy_sni,
                session_id,
                datagram_root,
            )
            .await;
        });
    }

    /// Non-blocking drain of whatever is still sitting in a leg's own mpsc
    /// channel when the leg dies — separate from `FairDataQueue`, which only
    /// holds what the writer had already pulled *out* of the channel. Without
    /// this, anything still queued but not yet dequeued at the moment of
    /// death was invisible to the writer's own hand-back and would be lost
    /// the same way `fair_data` used to be.
    fn drain_channel(rx: Option<&mut Receiver<MuxMessage>>) -> Vec<MuxMessage> {
        let mut out = Vec::new();
        if let Some(rx) = rx {
            while let Ok(msg) = rx.try_recv() {
                out.push(msg);
            }
        }
        out
    }

    /// Hands back everything a just-died leg was still holding — the
    /// writer's `FairDataQueue` plus its unconsumed channel tail — onto a
    /// surviving leg, via the same anti-domino failover
    /// [`Muxer::send_to_network`](super::muxer::Muxer::send_to_network)
    /// already uses when a channel send fails outright. Before this, that
    /// data (up to a full channel's worth — ~4 MB, see `CHANNEL_PACKETS`)
    /// was simply dropped with the dead leg's task: silently, with no error
    /// surfaced to the stream's sender or the client, corrupting whatever
    /// application response happened to be mid-flight (see docs/leg-death
    /// RCA — this is what turned a transient leg hiccup into a stream that
    /// hangs forever waiting for bytes that will never arrive).
    ///
    /// MUST run after `force_remove_leg` for this leg (it calls it itself,
    /// idempotently) so `select_leg` never hands these messages straight
    /// back to the leg they were just recovered from.
    async fn requeue_pending(&self, pending: Vec<MuxMessage>) {
        if pending.is_empty() {
            return;
        }
        self.muxer.force_remove_leg(self.leg_id);

        let mut recovered = 0u64;
        let mut lost = 0u64;
        for msg in pending {
            // Ephemeral — the next heartbeat on whichever leg picks up the
            // stream supersedes it, no point resending a stale one.
            if msg.frame_type == FrameType::Heartbeat {
                continue;
            }
            let stream_id = msg.stream_id;
            match self.muxer.send_to_network(msg).await {
                Ok(()) => {
                    recovered += 1;
                    crate::net::diagnostics::DIAG_COUNTERS
                        .leg_death_requeued
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    metrics::counter!("netrunner_leg_death_requeued_total").increment(1);
                }
                Err(_) => {
                    // No live leg anywhere in the session — physically
                    // nothing to hand this to. Clean up the stream's
                    // registration immediately rather than leaving a zombie
                    // entry for whatever idle-timeout would otherwise catch
                    // it, and let the client's own retry (once it notices
                    // the hang) start clean instead of finding stale state.
                    lost += 1;
                    self.muxer.remove_stream(stream_id);
                    crate::net::diagnostics::DIAG_COUNTERS
                        .leg_death_lost
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    metrics::counter!("netrunner_leg_death_lost_total").increment(1);
                }
            }
        }

        if lost > 0 {
            warn!(
                leg_id = self.leg_id,
                recovered,
                lost,
                "Leg death: some in-flight data could not be requeued — no live legs left in session"
            );
        } else {
            info!(
                leg_id = self.leg_id,
                recovered, "Leg death: in-flight data requeued onto surviving legs"
            );
        }
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
        // Сколько раз подряд нога умерла вскоре после «успешного» реконнекта.
        // Хендшейк на клиенте завершается ДО того, как сервер проверит токен,
        // поэтому отвергнутый токен (или нода, закрывающая соединение сразу)
        // выглядел как успех: счётчик выше обнулялся, и нога переподключалась
        // снова без всякой паузы — со скоростью RTT.
        let mut quick_deaths: u32 = 0;
        let mut last_reconnect: Option<std::time::Instant> = None;

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

                // Сессия закончена (сервер отверг токен или клиент её
                // остановил, см. `Muxer::shutdown`) — не переподключаемся.
                if self.muxer.is_fatal() {
                    info!("Leg {} stopping: session is over", self.leg_id);
                    self.muxer.force_remove_leg(self.leg_id);
                    return Ok(());
                }

                if last_reconnect.is_some_and(|t| t.elapsed() < LEG_FLAP_WINDOW) {
                    quick_deaths += 1;
                    let exp_ms = RECONNECT_BACKOFF_BASE.as_millis() as u64
                        * (1u64 << quick_deaths.saturating_sub(1).min(4));
                    let jitter = rand::random::<u64>() % RECONNECT_BACKOFF_JITTER_MS;
                    let backoff_ms = (exp_ms + jitter).min(MAX_RECONNECT_BACKOFF_MS);
                    warn!(
                        "Leg {} died {} time(s) in a row right after reconnect — backing off {} ms",
                        self.leg_id, quick_deaths, backoff_ms
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    if self.muxer.is_fatal() {
                        info!("Leg {} stopping: session is over", self.leg_id);
                        self.muxer.force_remove_leg(self.leg_id);
                        return Ok(());
                    }
                } else {
                    quick_deaths = 0;
                }

                self.leg_status = LegStatus::Reconnecting;
                // Снимаем ногу с учёта на время переподключения. Регистрация
                // в муксере означает «сюда можно писать», а писать сюда сейчас
                // некуда: сокета нет. Пока этого не делали, счётчик живых ног
                // показывал 4 при полностью мёртвом туннеле, и детектор
                // `TUNNEL_DEAD_AFTER` в клиентском движке не срабатывал в
                // единственном случае, ради которого писался (проверено
                // локально: сервер убит, клиент минутами считает ноги живыми).
                // Обратно нога встаёт после успешного хендшейка — `add_leg` в
                // ветке `Ok` ниже.
                self.muxer.force_remove_leg(self.leg_id);
                match self.attempt_reconnect().await {
                    Ok((new_in, new_out, new_rx, new_tx, new_tail, new_datagram_root)) => {
                        internal_attempt = 0; // successful reconnect — reset counter
                        last_reconnect = Some(std::time::Instant::now());

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

                        // Пере-поднять UDP-ногу, если заявка свободна. При смене
                        // сети `remove_all_legs` снимает её (`reset_datagram_leg_claim`),
                        // и ровно одна переподключившаяся нога выигрывает заявку
                        // заново и поднимает НОВУЮ попытку — со свежим корнем
                        // ЭТОЙ ноги, а значит свежими ключами (bug #2). Обычный
                        // реконнект одной ноги (не смена сети) заявку не снимал,
                        // поэтому здесь `try_claim` вернёт false и лишней попытки
                        // не будет — UDP-нога не рвётся на каждом реконнекте.
                        self.rearm_datagram_leg(new_datagram_root);
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
                        // Jitter grows with the step (up to half of it) so a fleet that
                        // lost the same server does not retry in lockstep.
                        let jitter =
                            rand::random::<u64>() % RECONNECT_BACKOFF_JITTER_MS.max(exp_ms / 2);
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

            // Дочерний от эпохи сети: при смене сети муксер отменяет эпоху, и
            // reader/writer этой ноги обрываются мгновенно, не дожидаясь
            // таймаута мёртвого сокета (см. `Muxer::network_epoch_token`).
            // Собственная отмена ноги при этом продолжает работать как раньше.
            let token = self.muxer.network_epoch_token().child_token();
            let token_reader = token.clone();
            let token_writer = token.clone();

            // ЧИТАЮЩАЯ ЗАДАЧА (Остается без изменений)
            let mut reader_handle = tokio::spawn(async move {
                let mut read_buf = read_buf;
                let mut inbound = inbound;
                let mut rcv_tuner = BufTuner::new(BufDir::Recv);
                if let Some(tcp) = inbound.tcp_stream() {
                    rcv_tuner.apply_initial(tcp);
                }
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
                            rcv_tuner.on_bytes(n);
                            let tune_now = std::time::Instant::now();
                            if rcv_tuner.due(tune_now) {
                                let rtt = inbound.tcp_stream().and_then(buftune::leg_rtt_ms);
                                if let Some(size) = rcv_tuner.tick(tune_now, rtt) {
                                    if let Some(tcp) = inbound.tcp_stream() {
                                        rcv_tuner.apply(tcp, size);
                                    }
                                }
                            }
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
                let mut snd_tuner = BufTuner::new(BufDir::Send);
                if let Some(tcp) = outbound.tcp_stream() {
                    snd_tuner.apply_initial(tcp);
                }
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
                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, msg, leg_id, &muxer_pong).await.map(|n| snd_tuner.on_bytes(n)) {
                                crate::net::diagnostics::send_diag_event(
                                    crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                        leg_id, stream_id: 0,
                                    },
                                );
                                // Heartbeat carries no application data — nothing to
                                // requeue, but whatever real Data/Control the fair
                                // queue was still holding for OTHER streams must not
                                // be thrown away with this leg. See the Data arm
                                // below for why this hand-back exists at all.
                                let pending = fair_data.drain_all();
                                return Err((e, control_rx, data_rx, tx_codec, pending));
                            }
                        }

                        _ = tcp_info_tick.tick() => {
                            if let Some(sample) = read_tcp_socket_stats(&outbound) {
                                muxer_pong.record_tcp_socket_stats(leg_id, sample);
                            }
                            let tune_now = std::time::Instant::now();
                            if snd_tuner.due(tune_now) {
                                let rtt = outbound.tcp_stream().and_then(buftune::leg_rtt_ms);
                                if let Some(size) = snd_tuner.tick(tune_now, rtt) {
                                    if let Some(tcp) = outbound.tcp_stream() {
                                        snd_tuner.apply(tcp, size);
                                    }
                                }
                            }
                        }

                        msg_opt = control_rx.recv() => {
                            if let Some(msg) = msg_opt {
                                let sid = msg.stream_id;
                                wrote_since_hb = true;
                                // Cheap: MuxMessage's payload is Bytes (refcounted),
                                // so this is a pointer/len copy, not a memcpy. Kept
                                // so a Close/control frame lost to a dying leg can
                                // still be handed to a surviving one instead of
                                // vanishing with no signal to the peer.
                                let retry_msg = msg.clone();
                                if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, msg, leg_id, &muxer_pong).await.map(|n| snd_tuner.on_bytes(n)) {
                                    crate::net::diagnostics::send_diag_event(
                                        crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                            leg_id, stream_id: sid,
                                        },
                                    );
                                    let mut pending = vec![retry_msg];
                                    pending.extend(fair_data.drain_all());
                                    return Err((e, control_rx, data_rx, tx_codec, pending));
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
                            // See the control-frame arm above: kept so this exact
                            // chunk can be requeued onto a live leg instead of
                            // disappearing mid-stream if the write below stalls.
                            let retry_chunk = chunk_msg.clone();

                            if let Err(e) = Self::handle_outbound(&mut outbound, &mut tx_codec, chunk_msg, leg_id, &muxer_pong).await.map(|n| snd_tuner.on_bytes(n)) {
                                crate::net::diagnostics::send_diag_event(
                                    crate::net::diagnostics::DiagnosticsEvent::TunnelWriteStuck {
                                        leg_id, stream_id: chunk_sid,
                                    },
                                );
                                // `retry_chunk` is this stream's earliest unsent
                                // byte range; anything still in `fair_data` for the
                                // same stream (e.g. the rest of a split Data
                                // message) is strictly later, so it must follow —
                                // not precede — `retry_chunk` to keep per-stream
                                // order intact once requeued (see `run`'s caller).
                                let mut pending = vec![retry_chunk];
                                pending.extend(fair_data.drain_all());
                                return Err((e, control_rx, data_rx, tx_codec, pending));
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
                // The writer can also exit cleanly here (cancellation on leg
                // teardown/reconnect, or the channel closing) with data still
                // sitting in `fair_data` — that path used to drop it silently
                // same as the error path; hand it back here too so the caller
                // can requeue it regardless of which way the loop ended.
                let leftover = fair_data.drain_all();
                Ok::<
                    _,
                    (
                        AppError,
                        Receiver<MuxMessage>,
                        Receiver<MuxMessage>,
                        TxCodec,
                        Vec<MuxMessage>,
                    ),
                >((control_rx, data_rx, tx_codec, leftover))
            });

            // Second element of the tuple is whatever the losing side of this
            // select was still holding in flight — see `requeue_pending` doc
            // for why letting it fall on the floor here was the actual bug.
            let (res, mut pending): (Result<(), AppError>, Vec<MuxMessage>) = tokio::select! {
                res_reader = &mut reader_handle => {
                    match res_reader {
                        Ok(Ok((is_eof, r_buf, returned_rx_codec))) => {
                            self.read_buf = r_buf;
                            self.rx_codec = Some(returned_rx_codec);

                            // Reader ended first (EOF or error) — cancel the
                            // writer and let it exit through its own
                            // cancellation branch (checked first in its
                            // `select!`, so this is near-instant unless it's
                            // mid-write, in which case it's bounded by its
                            // own adaptive write timeout) instead of
                            // hard-aborting it and losing whatever it was
                            // still holding.
                            token.cancel();
                            let w_res = (&mut writer_handle).await.unwrap();
                            let (c_rx, d_rx, returned_tx_codec, leftover) = match w_res {
                                Ok((c, d, t, l)) => (c, d, t, l),
                                Err((_, c, d, t, l)) => (c, d, t, l),
                            };
                            self.control_rx = Some(c_rx);
                            self.data_rx = Some(d_rx);
                            self.tx_codec = Some(returned_tx_codec);

                            if is_eof {
                                self.inbound = None;
                                self.outbound = None;
                                let mut pending = leftover;
                                pending.extend(Self::drain_channel(self.control_rx.as_mut()));
                                pending.extend(Self::drain_channel(self.data_rx.as_mut()));
                                self.requeue_pending(pending).await;
                                continue;
                            }
                            (Ok(()), leftover)
                        },
                        Ok(Err(e)) => {
                            token.cancel();
                            let leftover = match (&mut writer_handle).await {
                                Ok(Ok((c, d, t, l))) => {
                                    self.control_rx = Some(c);
                                    self.data_rx = Some(d);
                                    self.tx_codec = Some(t);
                                    l
                                }
                                Ok(Err((_, c, d, t, l))) => {
                                    self.control_rx = Some(c);
                                    self.data_rx = Some(d);
                                    self.tx_codec = Some(t);
                                    l
                                }
                                Err(_) => Vec::new(),
                            };
                            (Err(e), leftover)
                        }
                        Err(e) => {
                            token.cancel();
                            let leftover = match (&mut writer_handle).await {
                                Ok(Ok((c, d, t, l))) => {
                                    self.control_rx = Some(c);
                                    self.data_rx = Some(d);
                                    self.tx_codec = Some(t);
                                    l
                                }
                                Ok(Err((_, c, d, t, l))) => {
                                    self.control_rx = Some(c);
                                    self.data_rx = Some(d);
                                    self.tx_codec = Some(t);
                                    l
                                }
                                Err(_) => Vec::new(),
                            };
                            (Err(AppError::new(ERR_SYS_PANIC, "Сбой", format!("Reader panic: {}", e))), leftover)
                        }
                    }
                },
                res_writer = &mut writer_handle => {
                    match res_writer {
                        Ok(Ok((c_rx, d_rx, returned_tx_codec, leftover))) => {
                            self.control_rx = Some(c_rx);
                            self.data_rx = Some(d_rx);
                            self.tx_codec = Some(returned_tx_codec);
                            (Ok(()), leftover)
                        }
                        Ok(Err((e, c_rx, d_rx, returned_tx_codec, leftover))) => {
                            self.control_rx = Some(c_rx);
                            self.data_rx = Some(d_rx);
                            self.tx_codec = Some(returned_tx_codec);
                            (Err(e), leftover)
                        }
                        Err(e) => (Err(AppError::new(ERR_SYS_PANIC, "Сбой", format!("Writer panic: {}", e))), Vec::new()),
                    }
                }
            };

            token.cancel();
            reader_handle.abort();
            writer_handle.abort();

            // Whatever never even made it out of this leg's own channels
            // (queued by `send_to_network`, never dequeued into `fair_data`)
            // is the same loss vector one step earlier — pick it up here too.
            pending.extend(Self::drain_channel(self.control_rx.as_mut()));
            pending.extend(Self::drain_channel(self.data_rx.as_mut()));
            self.requeue_pending(pending).await;

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
    /// ([`Muxer::adaptive_leg_write_timeout`](super::muxer::Muxer::adaptive_leg_write_timeout))
    /// — чтобы медленная, но живая нога не убивалась по жёсткому тайм-ауту.
    async fn handle_outbound(
        outbound: &mut TunnelWriteHalf,
        tx_codec: &mut TxCodec,
        msg: MuxMessage,
        leg_id: u32,
        muxer: &super::muxer::Muxer,
    ) -> Result<usize, AppError> {
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
        // THIS leg's own live RTT — not the fastest leg in the process — so a
        // high-latency path (RTT > 2.5 s) doesn't trip a flat timeout on a leg
        // that is slow rather than dead. Killing such a leg is what set off
        // the leg-drop → stream-close cascade; scoring it off some other,
        // faster leg's RTT (the previous behaviour) reintroduced exactly that
        // failure mode for any session with mixed-quality legs.
        let write_timeout =
            muxer.adaptive_leg_write_timeout(leg_id, std::time::Duration::from_secs(20));
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
        Ok(wire.len())
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

    #[test]
    fn drain_all_preserves_per_stream_order_and_empties_the_queue() {
        let mut queue = FairDataQueue::default();
        queue.push(message(1, FrameType::Data, b"a1"));
        queue.push(message(3, FrameType::Data, b"b1"));
        queue.push(message(1, FrameType::Data, b"a2"));
        queue.push(message(3, FrameType::Data, b"b2"));

        let drained = queue.drain_all();
        assert!(queue.is_empty());
        assert_eq!(queue.queued_messages(), 0);

        let stream1: Vec<&[u8]> = drained
            .iter()
            .filter(|m| m.stream_id == 1)
            .map(|m| &m.data[..])
            .collect();
        let stream3: Vec<&[u8]> = drained
            .iter()
            .filter(|m| m.stream_id == 3)
            .map(|m| &m.data[..])
            .collect();
        assert_eq!(stream1, vec![b"a1".as_slice(), b"a2".as_slice()]);
        assert_eq!(stream3, vec![b"b1".as_slice(), b"b2".as_slice()]);
    }

    #[test]
    fn drain_all_on_empty_queue_returns_empty_vec() {
        let mut queue = FairDataQueue::default();
        assert!(queue.drain_all().is_empty());
    }
}
