//! Главный движок клиента: poll-цикл smoltcp + мост TUN ⇄ туннель.
//!
//! [`Engine`] — это «сердце» клиентской стороны. В одной задаче `tokio` крутится
//! цикл [`run`](Engine::run), который на каждой итерации делает 7 шагов:
//! 1. download: туннель → локальные сокеты (с пер-сокетными бэклогами);
//! 2. upload: пакеты из TUN → устройство smoltcp;
//! 3. прогон стека smoltcp (`poll`);
//! 4. слив TX smoltcp → writer TUN;
//! 5. периодический лог статистики;
//! 6. обработка диагностических событий → снапшоты;
//! 7. адаптивный сон/пробуждение по событию (анти-spin).
//!
//! Принципиальная защита от bufferbloat и head-of-line: download раздаётся
//! **пер-сокетно** (`pending_download`), поэтому один застрявший потребитель не
//! морозит общий канал для остальных; оба направления делят одну задачу и ходят
//! по очереди с лимитом [`MAX_PACKETS_PER_TICK`] за тик.
//!
//! [`EngineBuilder`]/[`EngineConfig`] — сборка движка: DNS, маршрутизация,
//! установка туннеля ([`ClientHandler::connect`]) и параметры интерфейса.

use bytes::Bytes;
use netrunner_core::net::ClientHandler;
use netrunner_core::net::Muxer;
use netrunner_core::net::NetworkConfig;
use netrunner_core::net::diagnostics::{
    self, DiagnosisRx, DiagnosticsEvent, DiagnosticsSnapshot, DiagnosticsStore, EngineMetrics,
    SocketMetrics, current_timestamp_ms,
};
use netrunner_core::rawcast::{RawCastEvent, RawCastFrame};
use smoltcp::iface::PollResult;
use smoltcp::phy::ChannelDevice;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::DeviceCapabilities,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{sync::LazyLock, time::Instant as StdInstant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tun::{DeviceReader, DeviceWriter};

use netrunner_core::net::STATS_LOG_INTERVAL;
use netrunner_logger::{debug, error, info, warn};

use crate::net::connection_manager::ConnectionManager;
use crate::net::dns::DnsHandler;
use crate::net::socket_factory::{SmolSocketFactory, SocketProvider};
use crate::tun::device::TrafficCounter;
use crate::tun::routing::{TunnelMode, setup_platform_routing};
use crate::tun::tun::Tun;

pub static START_TIME: LazyLock<StdInstant> = LazyLock::new(StdInstant::now);

/// Inbound packet slots in the smoltcp device RX queue before backpressure.
/// At MTU 1500 B × 128 slots ≈ 192 KB peak queue depth.
const DEVICE_RX_CAP: usize = 128;
/// Outbound packet slots staged in the smoltcp device TX queue.
/// Must be ≥ the engine→TUN channel cap so we never pop without a slot.
const DEVICE_TX_CAP: usize = 128;
/// Bounded capacity of the TUN-reader → engine mpsc channel (packets).
const TUN_CHAN_CAP: usize = 128;
/// Maximum packets drained from the TUN channel per loop iteration before
/// yielding, to prevent upload traffic from starving download processing.
const MAX_PACKETS_PER_TICK: usize = 250;
/// Read buffer allocated by the TUN reader task (covers the maximum IP packet).
const TUN_READ_BUF_SIZE: usize = 65536;
/// Upper bound on the smoltcp poll-delay sleep to keep latency low.
/// 2 ms is a good balance: low enough for interactive traffic (<5ms added RTT),
/// high enough to avoid spinning the CPU under light load.
const MAX_POLL_SLEEP: Duration = Duration::from_millis(2);
/// Per-socket download backlog byte cap: a last-resort OOM guard only. The
/// end-to-end credit window already bounds what the server may have in flight per
/// stream, so a healthy (merely slow) consumer never gets near this.
///
/// This used to be a frame COUNT (64 frames), which killed perfectly live
/// downloads whenever the local smoltcp socket drained a little slower than the
/// tunnel delivered — a slow consumer is not a dead one.
const MAX_PENDING_BYTES_PER_SOCKET: usize = 16 * 1024 * 1024;
/// A socket is judged dead only when it has a backlog AND has accepted not a
/// single frame for this long (the app stopped reading entirely).
const PENDING_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Ordered backlog of download frames for one socket whose channel was full.
struct Backlog {
    q: std::collections::VecDeque<Bytes>,
    bytes: usize,
    /// Last time the consumer accepted a frame (or the backlog was created).
    last_progress: StdInstant,
}

impl Backlog {
    fn new(first: Bytes) -> Self {
        let bytes = first.len();
        let mut q = std::collections::VecDeque::with_capacity(8);
        q.push_back(first);
        Self {
            q,
            bytes,
            last_progress: StdInstant::now(),
        }
    }
}
/// Max diagnostics snapshots buffered locally awaiting upload to the server.
/// The most useful triggers (leg disconnect/reconnect) fire exactly when no leg
/// is up to carry them, so snapshots wait here and flush once a leg recovers.
/// Oldest is dropped past the cap — recent state matters more than ancient.
const DIAG_OUTBOX_CAP: usize = 128;
/// Max diagnostics events handled per engine loop iteration (each builds a snapshot).
const DIAG_EVENTS_PER_TICK: usize = 4;
/// Minimum spacing between snapshots of the same event kind.
const DIAG_MIN_INTERVAL_PER_KIND: Duration = Duration::from_secs(1);
/// Diagnostics snapshots flushed to the server per engine tick. Bounds the cold
/// path so a large backlog can't monopolise a loop iteration after reconnect.
const DIAG_FLUSH_PER_TICK: usize = 16;

/// Движок клиентского стека: интерфейс smoltcp, реестр сокетов, мост в туннель
/// и диагностика. Живёт в одной задаче `tokio` (см. [`run`](Engine::run)).
pub struct Engine {
    interface: Interface,
    socket_set: SocketSet<'static>,
    manager: ConnectionManager,
    device: ChannelDevice,
    /// Bounded channel from TUN reader task to engine loop.
    tun_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Bounded channel from engine loop to TUN writer task.
    tun_tx: mpsc::Sender<Vec<u8>>,
    rx_from_tunnel: Option<mpsc::Receiver<RawCastFrame>>,
    factory: Arc<dyn SocketProvider>,
    stats: TrafficCounter,
    /// Arc to the tunnel multiplexer — used to collect tunnel metrics in
    /// diagnostics snapshots.
    muxer: Option<Arc<Muxer>>,
    /// Receiver end of the diagnostics event channel.
    diag_rx: Option<DiagnosisRx>,
    /// Shared store that holds the last N snapshots (readable via public API).
    pub diag_store: Arc<DiagnosticsStore>,
    /// Snapshots serialized to JSON and queued for upload to the connected
    /// server (one `Diag` frame each). Filled on every trigger; drained whenever
    /// a tunnel leg is available so reports survive the disconnect that produced
    /// them. See [`DIAG_OUTBOX_CAP`] / [`DIAG_FLUSH_PER_TICK`].
    diag_outbox: std::collections::VecDeque<Bytes>,
    /// Last time a snapshot was built for each diagnostics event kind (coalescing).
    diag_last_by_kind:
        std::collections::HashMap<std::mem::Discriminant<DiagnosticsEvent>, StdInstant>,
    /// Per-socket backlog of download frames whose target channel was full.
    /// Keyed by socket_id so a single slow/dead consumer can NEVER stall the
    /// shared download pipe for other sockets — the old single global slot did
    /// exactly that: one stuck socket (e.g. an app that stopped reading after a
    /// speedtest) froze rx_tunnel draining for everyone, killing all download.
    /// Frames per socket stay in order; a socket is dropped only when its backlog
    /// exceeds MAX_PENDING_BYTES_PER_SOCKET or makes no progress for
    /// PENDING_STALL_TIMEOUT (the consumer is dead).
    pending_download: std::collections::HashMap<u64, Backlog>,
    /// Cumulative download diagnostics (logged every STATS_LOG_INTERVAL).
    dl_dispatched: u64,
    dl_dropped_stuck: u64,
    dl_recv_closed: u64,
}

/// Решение «туннель мёртв»: ни одной живой ноги дольше `TUNNEL_DEAD_AFTER`.
/// Пока ноги есть (или идёт окно после смены сети), дедлайн отодвигается.
fn tunnel_is_dead(
    legs: Option<usize>,
    now: tokio::time::Instant,
    alive_deadline: &mut tokio::time::Instant,
    in_network_grace: bool,
) -> bool {
    if legs == Some(0) && !in_network_grace {
        return now >= *alive_deadline;
    }
    *alive_deadline = now + netrunner_core::net::TUNNEL_DEAD_AFTER;
    false
}

/// Движок клиента живёт ровно столько, сколько сессия: его роняют и при
/// штатной остановке (`Session::stop` отменяет токен), и когда он завершился
/// сам (мёртвый туннель, отвергнутый токен). В обоих случаях ноги туннеля —
/// отдельные задачи — должны остановиться вместе с ним, иначе они остаются
/// «зомби» и продолжают переподключаться к ноде (см. `Muxer::shutdown`).
impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(muxer) = &self.muxer {
            muxer.shutdown();
        }
    }
}

impl Engine {
    pub fn new(
        config: Config,
        caps: DeviceCapabilities,
        dns_handler: DnsHandler,
        tx_to_tunnel: mpsc::Sender<RawCastFrame>,
        rx_from_tunnel: mpsc::Receiver<RawCastFrame>,
        factory: Arc<dyn SocketProvider>,
    ) -> Self {
        let now = Engine::current_time();

        let mut device = ChannelDevice::new(caps, DEVICE_RX_CAP, DEVICE_TX_CAP);
        let interface = Interface::new(config, &mut device, now);

        let socket_set = ConnectionManager::setup_sockets(factory.as_ref(), 2);
        let manager = ConnectionManager::new(dns_handler, tx_to_tunnel, factory.clone());

        // Bounded TUN writer channel — smoltcp's TCP window limits how many
        // outgoing packets can pile up, so a modest cap is enough.
        let (tun_tx, _placeholder) = mpsc::channel(DEVICE_TX_CAP * 2);

        Self {
            interface,
            socket_set,
            device,
            tun_rx: None,
            tun_tx,
            manager,
            rx_from_tunnel: Some(rx_from_tunnel),
            factory,
            stats: TrafficCounter::new(),
            muxer: None,
            diag_rx: None,
            diag_store: Arc::new(DiagnosticsStore::new(20)),
            diag_outbox: std::collections::VecDeque::new(),
            diag_last_by_kind: std::collections::HashMap::new(),
            pending_download: std::collections::HashMap::new(),
            dl_dispatched: 0,
            dl_dropped_stuck: 0,
            dl_recv_closed: 0,
        }
    }

    /// Запускает главный цикл движка (не возвращается, пока туннель/TUN живы).
    ///
    /// Поднимает reader/writer-задачи TUN и крутит 7-шаговый цикл из обзора
    /// модуля. `tun` забирается во владение и расщепляется на половины.
    pub async fn run(&mut self, tun: Tun) {
        info!("Current routes: {:?}", self.interface.routes());
        let (writer, reader) = match tun.split() {
            Ok(pair) => pair,
            Err(e) => {
                // panic=abort в release-профиле приложения превратил бы любой
                // panic здесь в падение всего процесса — выходим штатно.
                error!("Failed to split TUN device, aborting engine loop: {}", e);
                return;
            }
        };

        // Bounded: TUN reader blocks when engine is overloaded → kernel TUN
        // buffer fills → natural backpressure to the OS.
        let (tun_to_engine_tx, tun_to_engine_rx) = mpsc::channel::<Vec<u8>>(TUN_CHAN_CAP);
        // Bounded: engine drops TX packets if TUN writer is slow (TCP retransmits).
        let (engine_to_tun_tx, engine_to_tun_rx) = mpsc::channel::<Vec<u8>>(DEVICE_TX_CAP * 2);

        self.tun_tx = engine_to_tun_tx;
        self.tun_rx = Some(tun_to_engine_rx);

        Self::spawn_tun_reader(reader, tun_to_engine_tx);
        Self::spawn_tun_writer(writer, engine_to_tun_rx);

        let mut last_stats_log = StdInstant::now();

        let inbound_map = self.manager.tracker.inbound_tx.clone();
        let mut rx_tunnel = self.rx_from_tunnel.take().unwrap();
        let mut tun_rx = self.tun_rx.take().unwrap();

        // Local cache to avoid DashMap lookups on every frame.
        let mut local_cache: std::collections::HashMap<
            u64,
            (mpsc::Sender<Bytes>, Arc<std::sync::atomic::AtomicBool>),
        > = std::collections::HashMap::new();

        // Момент, после которого туннель считается мёртвым, если к нему так и
        // не поднялось ни одной ноги. Сдвигается вперёд каждый раз, когда
        // живая нога есть, поэтому штатный реконнект его не задевает.
        let mut alive_deadline =
            tokio::time::Instant::now() + netrunner_core::net::TUNNEL_DEAD_AFTER;

        loop {
            // Сервер безоговорочно отверг наш токен (см. `Muxer::mark_fatal`,
            // выставляется per-leg циклом в `ClientHandler::connect`, когда
            // сервер шлёт `auth_rejected` — например, аккаунт удалён/забанен).
            // Реконнект с тем же токеном не поможет, а бесконечный внутренний
            // ретрай раньше держал этот цикл живым вечно: приложение видело
            // `CONN_CONNECTED` и не подозревало, что трафик уходит в мёртвый
            // туннель. Выходим сами — вызывающий код (`spawn_session`) увидит
            // завершение `run()` и переведёт статус в idle, что уронит Session
            // (Drop) и откатит маршрутизацию/kill-switch.
            if self.muxer.as_ref().is_some_and(|m| m.is_fatal()) {
                error!("Session marked fatal (server rejected auth token) — shutting down engine");
                return;
            }

            // Туннель без единой живой ноги. Ноги переподключаются сами и
            // бесконечно, поэтому «нет ног» — не повод паниковать сразу: пауза
            // между попытками штатно занимает секунды. Но если это тянется
            // дольше TUNNEL_DEAD_AFTER, туннель мёртв по-настоящему, и
            // держать сессию — значит врать пользователю: он видит
            // «подключено», а трафик в лучшем случае никуда не идёт, в худшем
            // (Android, где закрытый TUN возвращает маршрутизацию системе)
            // уходит мимо VPN открытым текстом.
            //
            // Выходим сами: `spawn_session` увидит завершение `run()`,
            // переведёт статус в failed и уронит Session, а её Drop откатит
            // маршрутизацию и kill-switch.
            let legs = self.muxer.as_ref().map(|m| m.active_legs_count());
            // Сразу после смены сети все ноги сняты и переподключаются: новая сеть
            // бывает готова не сразу, и 30 с без ног там — норма. Android на отказе
            // движка гасит VPN-интерфейс, поэтому в этом окне не умираем.
            let in_network_grace = self
                .muxer
                .as_ref()
                .and_then(|m| m.ms_since_network_change())
                .is_some_and(|ms| {
                    ms < netrunner_core::net::NETWORK_CHANGE_DEAD_GRACE.as_millis() as u64
                });
            if tunnel_is_dead(
                legs,
                tokio::time::Instant::now(),
                &mut alive_deadline,
                in_network_grace,
            ) {
                error!(
                    "Туннель без живых ног дольше {:?} — сессия признана мёртвой",
                    netrunner_core::net::TUNNEL_DEAD_AFTER
                );
                return;
            }

            let now = Self::current_time();
            let mut work_done = false;

            // ── 1. Dispatch tunnel → local sockets (download) ────────────
            //
            // ORDERING CONTRACT: bytes for a given socket are never reordered.
            // A PER-SOCKET backlog (pending_download) preserves order WITHOUT
            // ever blocking other sockets: rx_tunnel is always fully drained, and
            // a frame that can't be delivered is queued for that one socket only.
            // (The old single global slot let one stuck socket freeze ALL download
            //  — after a speedtest, one app that stopped reading killed the pipe.)

            // — Flush per-socket backlogs first, in order, non-blocking —
            if !self.pending_download.is_empty() {
                let stuck_ids: Vec<u64> = self.pending_download.keys().copied().collect();
                for sid in stuck_ids {
                    let tx = match local_cache.get(&sid).map(|(t, _)| t.clone()) {
                        Some(t) => Some(t),
                        None => inbound_map.get(&sid).map(|r| {
                            let v = r.value().clone();
                            local_cache.insert(sid, v.clone());
                            v.0
                        }),
                    };
                    let tx = match tx {
                        Some(t) => t,
                        None => {
                            // Socket gone — drop its whole backlog.
                            self.pending_download.remove(&sid);
                            local_cache.remove(&sid);
                            continue;
                        }
                    };
                    let mut stalled = false;
                    if let Some(b) = self.pending_download.get_mut(&sid) {
                        while let Some(front) = b.q.pop_front() {
                            let len = front.len();
                            match tx.try_send(front) {
                                Ok(_) => {
                                    work_done = true;
                                    self.dl_dispatched += 1;
                                    b.bytes = b.bytes.saturating_sub(len);
                                    b.last_progress = StdInstant::now();
                                }
                                Err(mpsc::error::TrySendError::Full(p)) => {
                                    b.q.push_front(p);
                                    break;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    self.dl_recv_closed += 1;
                                    b.q.clear();
                                    b.bytes = 0;
                                    break;
                                }
                            }
                        }
                        stalled =
                            !b.q.is_empty() && b.last_progress.elapsed() > PENDING_STALL_TIMEOUT;
                    }
                    if stalled {
                        // The consumer accepted nothing for PENDING_STALL_TIMEOUT: the
                        // app really stopped reading. Free the pipe for other sockets.
                        self.dl_dropped_stuck += 1;
                        warn!(
                            "📥 Download: socket {} made no progress for {:?} — consumer dead, dropping",
                            sid, PENDING_STALL_TIMEOUT
                        );
                        self.pending_download.remove(&sid);
                        local_cache.remove(&sid);
                        inbound_map.remove(&sid);
                        continue;
                    }
                    // Drop the backlog entry once fully drained (borrow ended).
                    if self
                        .pending_download
                        .get(&sid)
                        .is_some_and(|b| b.q.is_empty())
                    {
                        self.pending_download.remove(&sid);
                    }
                }
            }

            // — Drain rx_tunnel (a stuck socket only queues its own frames) —
            // Bounded per iteration (symmetric to the upload-accept cap below) so a
            // download flood can't starve upload ingestion or the smoltcp poll: both
            // directions share this single engine task and must take turns. Leftover
            // frames are picked up next iteration (work_done forces a prompt re-loop).
            let mut dl_processed = 0;
            while let Ok(frame) = rx_tunnel.try_recv() {
                work_done = true;
                if frame.event == RawCastEvent::Close {
                    local_cache.remove(&frame.socket_id);
                    inbound_map.remove(&frame.socket_id);
                    self.pending_download.remove(&frame.socket_id);
                } else if frame.event == RawCastEvent::Data {
                    self.route_download(
                        frame.socket_id,
                        frame.payload,
                        &mut local_cache,
                        &inbound_map,
                    );
                }
                dl_processed += 1;
                if dl_processed >= MAX_PACKETS_PER_TICK {
                    break;
                }
            }

            // ── 2. Accept TUN packets → device (upload) ──────────────────
            // Stop reading when the device's RX queue is full (backpressure).
            let mut packets_read = 0;
            while !self.device.rx_full() {
                match tun_rx.try_recv() {
                    Ok(pkt) => {
                        self.stats.record_tx(pkt.len()); // upload: app → internet
                        self.manager
                            .try_create_socket_from_packet(&pkt, &mut self.socket_set);
                        self.device.push_rx(pkt);
                        work_done = true;
                        packets_read += 1;
                        if packets_read >= MAX_PACKETS_PER_TICK {
                            break; // Yield occasionally to prevent starvation.
                        }
                    }
                    Err(_) => break,
                }
            }

            // ── 3. Run smoltcp ───────────────────────────────────────────
            let mut repeat = true;
            while repeat {
                self.manager.process_sockets(&mut self.socket_set, now);
                let res = self.poll();
                self.manager.cleanup(&mut self.socket_set);
                repeat = matches!(res, PollResult::SocketStateChanged);
                if repeat {
                    work_done = true;
                }
            }

            // ── 4. Drain smoltcp TX → TUN writer ─────────────────────────
            // Check channel capacity BEFORE popping so we never consume a
            // packet from the device TX queue without a guaranteed slot to
            // send it.  Packets left in the queue are regenerated by smoltcp
            // on the next poll() call (TCP state machine handles retransmits,
            // ACKs, etc.).
            while self.tun_tx.capacity() > 0 {
                match self.device.pop_tx() {
                    Some(pkt) => {
                        self.stats.record_rx(pkt.len()); // download: internet → app
                        // capacity() > 0 guarantees this won't fail
                        let _ = self.tun_tx.try_send(pkt);
                        work_done = true;
                    }
                    None => break,
                }
            }

            // ── 5. Stats logging ─────────────────────────────────────────
            if last_stats_log.elapsed() >= STATS_LOG_INTERVAL {
                let stats = self.stats.get_stats();
                info!(
                    "TunDevice Traffic: ↓ {:.2} MB ({} pkts) | ↑ {:.2} MB ({} pkts) | Speed: ↓{:.2} MB/s, ↑{:.2} MB/s",
                    stats.rx_bytes as f64 / 1_048_576.0,
                    stats.rx_packets,
                    stats.tx_bytes as f64 / 1_048_576.0,
                    stats.tx_packets,
                    stats.rx_speed_mb_s,
                    stats.tx_speed_mb_s,
                );
                let manager_ref = &self.manager;
                self.factory
                    .log_stats(&self.socket_set, &|handle| manager_ref.get_buf_info(handle));

                // Download pipeline health: how many sockets are backlogged, total
                // queued frames, and cumulative dispatch outcomes. If pending_*
                // climb while TunDevice ↓ is flat, the stall is at the smoltcp/app
                // boundary; if they stay ~0, look upstream (muxer/leg dispatch).
                let pending_sockets = self.pending_download.len();
                let pending_frames: usize = self.pending_download.values().map(|b| b.q.len()).sum();
                let worst_backlog = self
                    .pending_download
                    .values()
                    .map(|b| b.q.len())
                    .max()
                    .unwrap_or(0);
                info!(
                    "📥 Download pipe: pending_sockets={} pending_frames={} worst_backlog={} | dispatched={} recv_closed={} stuck_dropped={} | tun_tx_free={}",
                    pending_sockets,
                    pending_frames,
                    worst_backlog,
                    self.dl_dispatched,
                    self.dl_recv_closed,
                    self.dl_dropped_stuck,
                    self.tun_tx.capacity(),
                );

                last_stats_log = StdInstant::now();
            }

            // ── 6. Diagnostics event processing ─────────────────────────
            // Take the receiver out (ends the borrow on self), drain events,
            // build snapshots (needs &mut self for stats), then put it back.
            if let Some(mut diag_rx) = self.diag_rx.take() {
                // Bounded and coalesced: building a snapshot walks every socket, and
                // this runs inside the one task that also moves all packets. An
                // unbounded drain of a post-outage event storm (tens of thousands of
                // events) froze the engine for seconds while the TUN stayed up.
                let mut diag_budget = DIAG_EVENTS_PER_TICK;
                while diag_budget > 0 {
                    let Ok(event) = diag_rx.try_recv() else { break };
                    diag_budget -= 1;
                    // One snapshot per event kind per interval; the rest are dropped
                    // (their counters live in DIAG_COUNTERS).
                    let kind = std::mem::discriminant(&event);
                    let now_std = StdInstant::now();
                    if let Some(prev) = self.diag_last_by_kind.get(&kind)
                        && now_std.duration_since(*prev) < DIAG_MIN_INTERVAL_PER_KIND
                    {
                        continue;
                    }
                    self.diag_last_by_kind.insert(kind, now_std);
                    let snap = self.build_snapshot(event);
                    // Queue a compact JSON copy for upload to the server,
                    // then keep the snapshot in the local ring buffer.
                    if self.diag_outbox.len() >= DIAG_OUTBOX_CAP {
                        self.diag_outbox.pop_front();
                    }
                    self.diag_outbox.push_back(Bytes::from(snap.to_json_line()));
                    self.diag_store.push(snap);
                }
                self.diag_rx = Some(diag_rx);
            }

            // ── 6b. Ship queued diagnostics to the server ────────────────
            // Best-effort, cold path: only runs when there's a backlog AND a leg
            // is up to carry it. send_diag_report is a non-blocking try_send under
            // the hood, so the await is cheap; on failure (no leg accepted it) we
            // re-queue the snapshot and retry on a later tick.
            if !self.diag_outbox.is_empty()
                && let Some(muxer) = self.muxer.clone()
                && muxer.active_legs_count() > 0
            {
                for _ in 0..DIAG_FLUSH_PER_TICK {
                    let Some(line) = self.diag_outbox.pop_front() else {
                        break;
                    };
                    if !muxer.send_diag_report(line.clone()).await {
                        self.diag_outbox.push_front(line);
                        break;
                    }
                }
            }

            // ── 7. Adaptive timing ───────────────────────────────────────
            if work_done {
                tokio::task::yield_now().await;
            } else {
                let delay = self
                    .interface
                    .poll_delay(Self::current_time(), &self.socket_set);

                let mut sleep_time = delay
                    .map(|d| Duration::from_micros(d.micros()).min(MAX_POLL_SLEEP))
                    .unwrap_or(MAX_POLL_SLEEP);
                // Backlogs are waiting on smoltcp to drain — re-poll soon to retry.
                if !self.pending_download.is_empty() {
                    sleep_time = sleep_time.min(Duration::from_millis(2));
                }

                tokio::select! {
                    _ = sleep(sleep_time) => {}

                    // Upload: wake immediately when the app sends data.
                    msg = tun_rx.recv() => {
                        match msg {
                            Some(pkt) => {
                                self.stats.record_tx(pkt.len());
                                self.manager.try_create_socket_from_packet(&pkt, &mut self.socket_set);
                                self.device.push_rx(pkt);
                            }
                            None => break,
                        }
                    }

                    // Download: wake immediately when tunnel data arrives.
                    // Routed per-socket; step 1 drains the rest next iteration.
                    frame = rx_tunnel.recv() => {
                        match frame {
                            None => break,
                            Some(f) => {
                                if f.event == RawCastEvent::Close {
                                    local_cache.remove(&f.socket_id);
                                    inbound_map.remove(&f.socket_id);
                                    self.pending_download.remove(&f.socket_id);
                                } else if f.event == RawCastEvent::Data {
                                    self.route_download(
                                        f.socket_id,
                                        f.payload,
                                        &mut local_cache,
                                        &inbound_map,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Deliver ONE download frame to its local socket without ever blocking
    /// other sockets. If the socket already has a backlog, the frame is appended
    /// (preserving in-order delivery). If the channel is full a per-socket
    /// backlog is started. A backlog past MAX_PENDING_BYTES_PER_SOCKET (or stalled for PENDING_STALL_TIMEOUT) means the
    /// consumer is dead → the socket is dropped so it can't stall the shared pipe.
    fn route_download(
        &mut self,
        socket_id: u64,
        payload: Bytes,
        local_cache: &mut std::collections::HashMap<
            u64,
            (mpsc::Sender<Bytes>, Arc<std::sync::atomic::AtomicBool>),
        >,
        inbound_map: &dashmap::DashMap<
            u64,
            (mpsc::Sender<Bytes>, Arc<std::sync::atomic::AtomicBool>),
        >,
    ) {
        // Preserve order: once a socket has a backlog, everything queues behind it.
        // (Borrow of `q` ends inside this block; the over-cap drop happens after,
        //  so we never re-borrow self.pending_download while `q` is live.)
        if let Some(b) = self.pending_download.get_mut(&socket_id) {
            if b.bytes + payload.len() <= MAX_PENDING_BYTES_PER_SOCKET {
                b.bytes += payload.len();
                b.q.push_back(payload);
                return;
            }
            // Over the byte cap → fall through to drop the socket (OOM guard).
        } else {
            // No backlog yet: resolve the sender (local cache → shared map).
            let tx = match local_cache.get(&socket_id).map(|(t, _)| t.clone()) {
                Some(t) => t,
                None => match inbound_map.get(&socket_id) {
                    Some(r) => {
                        let v = r.value().clone();
                        local_cache.insert(socket_id, v.clone());
                        v.0
                    }
                    None => return, // socket gone — drop
                },
            };

            match tx.try_send(payload) {
                Ok(_) => self.dl_dispatched += 1,
                Err(mpsc::error::TrySendError::Full(p)) => {
                    // Start a per-socket backlog; OTHER sockets stay unaffected.
                    self.pending_download.insert(socket_id, Backlog::new(p));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.dl_recv_closed += 1;
                    local_cache.remove(&socket_id);
                }
            }
            return;
        }

        // Reached only when an existing backlog would exceed the byte cap: the
        // consumer is far behind the credit window — drop the socket (OOM guard).
        self.dl_dropped_stuck += 1;
        warn!(
            "📥 Download: socket {} backlog byte cap ({} B) hit — dropping socket to bound memory",
            socket_id, MAX_PENDING_BYTES_PER_SOCKET
        );
        self.pending_download.remove(&socket_id);
        local_cache.remove(&socket_id);
        inbound_map.remove(&socket_id);
    }

    fn poll(&mut self) -> PollResult {
        let now = Self::current_time();
        self.interface
            .poll(now, &mut self.device, &mut self.socket_set)
    }

    /// Задача чтения из TUN: читает IP-пакеты и шлёт их в движок. `send().await`
    /// блокируется при полном канале → backpressure доходит до TUN-устройства ОС.
    fn spawn_tun_reader(mut reader: DeviceReader, to_engine: mpsc::Sender<Vec<u8>>) {
        tokio::spawn(async move {
            debug!("TUN Reader task started");
            let mut buf = vec![0u8; TUN_READ_BUF_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let pkt = buf[..n].to_vec();
                        // .send().await blocks when engine channel is full →
                        // backpressure propagates to OS TUN device.
                        if to_engine.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!("FATAL: TUN Reader task died: {}", e);
                        break;
                    }
                }
            }
        });
    }

    /// Задача записи в TUN: принимает готовые пакеты из движка и пишет их в
    /// устройство (отдаёт приложению то, что пришло из туннеля).
    fn spawn_tun_writer(mut writer: DeviceWriter, mut from_engine: mpsc::Receiver<Vec<u8>>) {
        tokio::spawn(async move {
            debug!("TUN Writer task started");
            while let Some(pkt) = from_engine.recv().await {
                if writer.write_all(&pkt).await.is_err() {
                    break;
                }
            }
            warn!("TUN Writer task stopped");
        });
    }

    pub fn current_time() -> Instant {
        let duration = StdInstant::now().duration_since(*START_TIME);
        Instant::from_micros(duration.as_micros() as i64)
    }

    // ── Diagnostics ──────────────────────────────────────────────────────────

    /// Returns all recent diagnostics snapshots as a pretty-printed JSON string.
    /// Snapshots are captured automatically whenever a network problem occurs
    /// (upload fail, download backpressure, leg disconnect, tunnel write stall).
    pub fn get_diagnostics_json(&self) -> String {
        self.diag_store.get_all_json()
    }

    /// Returns only the most recent snapshot as JSON, or `"null"` if none yet.
    pub fn get_latest_diagnostics_json(&self) -> String {
        self.diag_store.get_latest_json()
    }

    /// Builds a full diagnostics snapshot at this exact moment.
    /// Collects: traffic counters, device queue depths, channel free space,
    /// all active smoltcp socket states, and tunnel leg/stream metrics.
    fn build_snapshot(&mut self, trigger: DiagnosticsEvent) -> DiagnosticsSnapshot {
        let stats = self.stats.get_stats();

        let engine_metrics = EngineMetrics {
            rx_total_mb: stats.rx_bytes as f64 / 1_048_576.0,
            tx_total_mb: stats.tx_bytes as f64 / 1_048_576.0,
            rx_speed_mb_s: stats.rx_speed_mb_s,
            tx_speed_mb_s: stats.tx_speed_mb_s,
            rx_packets: stats.rx_packets,
            tx_packets: stats.tx_packets,
            device_rx_queue_depth: self.device.rx_len(),
            // ChannelDevice doesn't expose tx_len; use 0 (best-effort data only)
            device_tx_queue_depth: if self.device.has_tx() { 1 } else { 0 },
            tun_tx_channel_free: self.tun_tx.capacity(),
            // tun_rx is taken by `run()`; not available here
            tun_rx_channel_free: 0,
        };

        // Collect socket handles and their smoltcp state first (immutable borrow).
        struct SocketSnap {
            handle_str: String,
            state: String,
            send_queue: usize,
            send_cap: usize,
            recv_queue: usize,
            recv_cap: usize,
        }
        let snaps: Vec<SocketSnap> = self
            .socket_set
            .iter()
            .filter_map(|(handle, socket)| {
                if let smoltcp::socket::Socket::Tcp(tcp) = socket
                    && tcp.is_active()
                {
                    return Some(SocketSnap {
                        handle_str: format!("{}", handle),
                        state: format!("{:?}", tcp.state()),
                        send_queue: tcp.send_queue(),
                        send_cap: tcp.send_capacity(),
                        recv_queue: tcp.recv_queue(),
                        recv_cap: tcp.recv_capacity(),
                    });
                }
                None
            })
            .collect();

        // Collect pending_chunk sizes via manager (separate borrow).
        let sockets: Vec<SocketMetrics> = snaps
            .into_iter()
            .map(|s| {
                let stream_id: u32 = s.handle_str.parse().unwrap_or(0);
                SocketMetrics {
                    stream_id,
                    state: s.state,
                    send_queue_bytes: s.send_queue,
                    send_capacity_bytes: s.send_cap,
                    recv_queue_bytes: s.recv_queue,
                    recv_capacity_bytes: s.recv_cap,
                    // pending_chunk is connection-private; omit for now
                    pending_chunk_bytes: 0,
                    tx_congested: false,
                    total_up_bytes: 0,
                    total_down_bytes: 0,
                }
            })
            .collect();

        let tunnel = self
            .muxer
            .as_ref()
            .map(|m| m.snapshot_tunnel_metrics())
            .unwrap_or_else(|| diagnostics::TunnelMetrics {
                global_min_rtt_ms: 0,
                active_legs: vec![],
                total_streams: 0,
                session_count: 0,
            });

        DiagnosticsSnapshot {
            timestamp_ms: current_timestamp_ms(),
            trigger,
            engine: Some(engine_metrics),
            tunnel,
            sockets,
            error_totals: diagnostics::DIAG_COUNTERS.snapshot(),
        }
    }

    pub fn set_any_ip(&mut self, state: bool) {
        self.interface.set_any_ip(state)
    }

    pub fn set_transparent_mode(&mut self) {
        self.interface.update_ip_addrs(|addrs| {
            addrs.clear();
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });
        self.interface.routes_mut().remove_default_ipv4_route();
    }

    pub fn set_default_gateway(
        &mut self,
        gateway: smoltcp::wire::Ipv4Address,
    ) -> Result<(), String> {
        info!("Setting default IPv4 gateway to: {}", gateway);
        self.interface.routes_mut().remove_default_ipv4_route();
        self.interface
            .routes_mut()
            .add_default_ipv4_route(gateway)
            .map_err(|e| format!("Failed to set default gateway: {:?}", e))?;
        Ok(())
    }

    pub fn activate(&mut self) {
        let now = Self::current_time();
        self.interface
            .poll(now, &mut self.device, &mut self.socket_set);
        self.manager.start_listening(&mut self.socket_set);
    }
}

// ─── EngineConfig & EngineBuilder (unchanged API surface) ──────────────────

/// Параметры запуска движка (билдер-стайл через `with_*`).
#[derive(Clone)]
pub struct EngineConfig {
    /// Адрес прокси-сервера (`host:port`).
    pub remote_address: String,
    /// Путь к директории кэша (блок-лист DNS и т.п.).
    pub cache_path: String,
    /// MTU интерфейса.
    pub mtu: usize,
    /// Настраивать ли системную маршрутизацию (на мобильных — нет, это делает ОС).
    pub setup_routing: bool,
    /// Принимать пакеты на любой IP (`any_ip` интерфейса smoltcp).
    pub any_ip: bool,
    /// Прозрачный режим (стек как промежуточный узел, без своего «адреса»).
    pub transparent_mode: bool,
    /// Шлюз по умолчанию внутри стека.
    pub default_gateway: Ipv4Addr,
    /// Включён ли kill-switch (резать трафик мимо туннеля).
    pub killswitch_enabled: bool,
    /// Приложения в обход туннеля (split-tunneling).
    pub excluded_apps: Vec<String>,
    /// Домены в обход туннеля.
    pub excluded_domains: Vec<String>,
    /// Что заворачивать в туннель (см. [`TunnelMode`]). Для частного
    /// пользователя всегда `All` — прежнее поведение. `Resources` приходит
    /// только из политики организации (managed-режим).
    pub tunnel_mode: TunnelMode,
    /// Подсети ресурсов организации. Используются исключительно в
    /// [`TunnelMode::Resources`]; в остальных режимах игнорируются.
    pub routed_cidrs: Vec<String>,
    /// Перехватывать ли не только локальный `output`, но и IPv4-трафик,
    /// пришедший с LAN-интерфейсов роутера. Выключено для обычного desktop.
    pub router_mode: bool,
    /// LAN-интерфейсы для [`Self::router_mode`] (`br-lan` по умолчанию в
    /// OpenWrt-профиле CLI). Имена валидируются перед передачей в nftables.
    pub lan_interfaces: Vec<String>,
    /// SNI поддельного `ClientHello` (домен-декой, под который маскируется
    /// хендшейк). Пока статический атрибут конфигурации — раньше был
    /// захардкожен константой глубоко в TLS-слое ядра. В перспективе будет
    /// приходить динамически со списком серверов (вместе с их собственным
    /// `--decoy-host`), чтобы клиент и сервер не расходились в выборе decoy-хоста.
    pub decoy_sni: String,
    /// Bearer-токен клиента (JWT, выданный `netrunner-backend` при логине) —
    /// отправляется серверу в auth-кадре. `None`, если сервер не запущен с
    /// `--require-auth` или приложение ещё не залогинено (Ghost Protocol seed
    /// генерируется/логинится в фоне почти сразу, см. `netrunner-app/src/lib/api.ts`).
    pub auth_token: Option<String>,
    /// Учётные данные ноды из списка серверов, полученного от бэкенда:
    /// `nrxp_secret` и `nrxp_public_key`, оба hex по 64 символа.
    ///
    /// Заданы — хендшейк идёт по аутентифицированной схеме: клиент проверяемо
    /// отличает свою ноду от чужой, и активный посредник, подсунувший свой
    /// ключ, не выведет ключей сессии. Не заданы — старый анонимный хендшейк
    /// (нода, которой в админке ещё не завели ключи).
    ///
    /// Приходят по HTTPS от бэкенда, которому приложение уже доверяет по
    /// обычному PKI, — это и есть корень доверия, из которого растёт
    /// аутентификация туннеля.
    pub node_secret: Option<String>,
    pub node_public_key: Option<String>,
    /// Request opt-in strong privacy on all newly opened TCP/UDP flows.
    pub strong_privacy: bool,
}

impl EngineConfig {
    pub fn new(remote_address: impl Into<String>) -> Self {
        Self {
            remote_address: remote_address.into(),
            cache_path: ".".to_string(),
            mtu: 1380,
            setup_routing: true,
            any_ip: true,
            transparent_mode: true,
            default_gateway: Ipv4Addr::new(10, 0, 0, 2),
            killswitch_enabled: true,
            excluded_apps: Vec::new(),
            excluded_domains: Vec::new(),
            tunnel_mode: TunnelMode::All,
            routed_cidrs: Vec::new(),
            router_mode: false,
            lan_interfaces: Vec::new(),
            decoy_sni: netrunner_core::net::DEFAULT_DECOY_HOST.to_string(),
            auth_token: None,
            node_secret: None,
            node_public_key: None,
            strong_privacy: false,
        }
    }

    pub fn with_decoy_sni(mut self, decoy_sni: impl Into<String>) -> Self {
        self.decoy_sni = decoy_sni.into();
        self
    }

    /// Учётные данные ноды из списка серверов бэкенда. Оба значения — hex по
    /// 64 символа; любое отсутствует ⇒ работаем по старой анонимной схеме.
    pub fn with_node_credentials(
        mut self,
        node_secret: Option<String>,
        node_public_key: Option<String>,
    ) -> Self {
        self.node_secret = node_secret;
        self.node_public_key = node_public_key;
        self
    }

    pub fn with_auth_token(mut self, auth_token: Option<String>) -> Self {
        self.auth_token = auth_token;
        self
    }

    /// Enables onion-route mixing mode for future connections in this engine.
    pub fn with_strong_privacy(mut self, enabled: bool) -> Self {
        self.strong_privacy = enabled;
        self
    }

    pub fn with_cache_path(mut self, path: impl Into<String>) -> Self {
        self.cache_path = path.into();
        self
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn disable_routing(mut self) -> Self {
        self.setup_routing = false;
        self
    }

    pub fn with_killswitch(mut self, enabled: bool) -> Self {
        self.killswitch_enabled = enabled;
        self
    }

    pub fn with_excluded_apps(mut self, apps: Vec<String>) -> Self {
        self.excluded_apps = apps;
        self
    }

    pub fn with_excluded_domains(mut self, domains: Vec<String>) -> Self {
        self.excluded_domains = domains;
        self
    }

    /// Режим туннелирования и подсети ресурсов задаются одним вызовом:
    /// по отдельности их выставить нельзя, потому что `Resources` без списка
    /// подсетей означает «в туннель не идёт ничего» — состояние, в которое
    /// попасть по невнимательности не должно быть возможно.
    pub fn with_tunnel_mode(mut self, mode: TunnelMode, routed_cidrs: Vec<String>) -> Self {
        self.tunnel_mode = mode;
        self.routed_cidrs = routed_cidrs;
        self
    }

    /// Включает перехват транзитного трафика на Linux-роутере.
    pub fn with_router_mode(mut self, enabled: bool, lan_interfaces: Vec<String>) -> Self {
        self.router_mode = enabled;
        self.lan_interfaces = lan_interfaces;
        self
    }
}

/// Не выводим секреты узла/JWT через `{:?}`: конфиг логируется при каждом
/// запуске движка, а OpenWrt направляет stdout/stderr сервиса в системный лог.
impl std::fmt::Debug for EngineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineConfig")
            .field("remote_address", &self.remote_address)
            .field("cache_path", &self.cache_path)
            .field("mtu", &self.mtu)
            .field("setup_routing", &self.setup_routing)
            .field("any_ip", &self.any_ip)
            .field("transparent_mode", &self.transparent_mode)
            .field("default_gateway", &self.default_gateway)
            .field("killswitch_enabled", &self.killswitch_enabled)
            .field("excluded_apps", &self.excluded_apps)
            .field("excluded_domains", &self.excluded_domains)
            .field("tunnel_mode", &self.tunnel_mode)
            .field("routed_cidrs", &self.routed_cidrs)
            .field("router_mode", &self.router_mode)
            .field("lan_interfaces", &self.lan_interfaces)
            .field("decoy_sni", &self.decoy_sni)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "node_secret",
                &self.node_secret.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "node_public_key",
                &self.node_public_key.as_ref().map(|_| "[configured]"),
            )
            .field("strong_privacy", &self.strong_privacy)
            .finish()
    }
}

#[cfg(test)]
mod engine_config_tests {
    use super::*;

    #[test]
    fn debug_output_redacts_credentials() {
        let config = EngineConfig::new("198.51.100.10:443")
            .with_auth_token(Some("jwt-secret-value".to_owned()))
            .with_node_credentials(
                Some("node-secret-value".to_owned()),
                Some("node-public-value".to_owned()),
            );
        let debug = format!("{config:?}");

        assert!(!debug.contains("jwt-secret-value"));
        assert!(!debug.contains("node-secret-value"));
        assert!(!debug.contains("node-public-value"));
        assert!(debug.contains("[redacted]"));
    }
}

/// Сборщик [`Engine`]: подготавливает DNS, маршрутизацию, туннель и интерфейс.
pub struct EngineBuilder {
    config: EngineConfig,
    tun_device: Option<Tun>,
    socket_factory: Option<Arc<dyn SocketProvider>>,
}

impl EngineBuilder {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            tun_device: None,
            socket_factory: None,
        }
    }

    pub fn with_tun(mut self, tun: Tun) -> Self {
        self.tun_device = Some(tun);
        self
    }

    /// Собирает готовый к запуску движок.
    ///
    /// Инициализирует DNS-блоклист, при необходимости ставит системные маршруты,
    /// поднимает диагностику и **устанавливает туннель** ([`ClientHandler::connect`]),
    /// затем создаёт [`Engine`], настраивает интерфейс и добавляет маршруты-исключения
    /// для split-tunneling доменов. Возвращает движок и TUN для последующего `run`.
    pub async fn build(self) -> Result<(Engine, Tun), String> {
        let tun = self.tun_device.ok_or("TUN device is required")?;

        info!("Initializing Engine with config: {:?}", self.config);

        let mut dns_handler = DnsHandler::new(
            &self.config.cache_path,
            self.config.excluded_domains.clone(),
        );

        if let Err(e) = dns_handler.init().await {
            error!("Failed to initialize DNS blocklist: {}", e);
        }

        if self.config.setup_routing {
            info!(
                "Applying platform routing rules (Killswitch: {}, mode: {:?})...",
                self.config.killswitch_enabled, self.config.tunnel_mode
            );
            setup_platform_routing(
                &self.config.remote_address,
                self.config.killswitch_enabled,
                &self.config.excluded_apps,
                self.config.tunnel_mode,
                &self.config.routed_cidrs,
                self.config.router_mode,
                &self.config.lan_interfaces,
            )
            .map_err(|e| format!("Routing setup failed: {}", e))?;
        }

        let smol_config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.config.mtu;
        caps.medium = smoltcp::phy::Medium::Ip;

        // Initialise the diagnostics event channel before connecting so that
        // any events fired during leg establishment are captured.
        let diag_rx = diagnostics::init_diagnostics();

        let cap = NetworkConfig::global().channel_capacity;
        let (tx_to_tunnel, rx_for_client_handler) = mpsc::channel::<RawCastFrame>(cap);
        let (tx_for_client_handler, rx_from_tunnel) = mpsc::channel::<RawCastFrame>(cap);

        // Учётные данные ноды собираются только если бэкенд прислал ОБА
        // значения. Невалидный hex — не повод молча откатиться на анонимный
        // хендшейк: это тихо снимало бы аутентификацию сервера ровно тогда,
        // когда конфиг испорчен, поэтому подключение прерывается.
        let identity = match (
            self.config.node_secret.as_deref(),
            self.config.node_public_key.as_deref(),
        ) {
            (Some(secret), Some(public)) => Some(netrunner_core::Identity::Peer(
                netrunner_core::PeerIdentity::from_hex(secret, public)
                    .map_err(|e| format!("Bad node credentials: {}", e))?,
            )),
            _ => {
                warn!("Node credentials absent: анонимный хендшейк, сервер не аутентифицируется");
                None
            }
        };

        info!("Establishing secure tunnel to proxy server...");
        let muxer = ClientHandler::connect_with_privacy_mode(
            &self.config.remote_address,
            self.config.decoy_sni.clone(),
            self.config.auth_token.clone(),
            identity,
            rx_for_client_handler,
            tx_for_client_handler,
            self.config.strong_privacy,
        )
        .await
        .map_err(|e| format!("Failed to establish secure tunnel: {}", e))?;

        let factory = self.socket_factory.unwrap_or_else(|| {
            let config_owned = (*NetworkConfig::global()).clone();
            let config = Arc::new(config_owned);
            Arc::new(SmolSocketFactory::new(config))
        });

        let excluded_domains = self.config.excluded_domains.clone();
        if !excluded_domains.is_empty() {
            // Карта, куда пишем результат резолва — тот же `Arc`, который
            // синхронно читает `handle_query` при ответе на DNS-запросы
            // исключённых доменов (см. dns.rs). Клонируем `Arc` ДО того,
            // как `dns_handler` ниже уйдёт по значению в `Engine::new`.
            let resolved_excluded = dns_handler.resolved_excluded_map();
            tokio::spawn(async move {
                #[cfg(target_os = "linux")]
                let phys_gw = crate::tun::routing::get_default_gateway_linux()
                    .unwrap_or_else(|| "192.168.1.1".into());
                #[cfg(not(target_os = "linux"))]
                let phys_gw = "192.168.1.1";

                for domain in excluded_domains {
                    // Раньше здесь стоял `tokio::net::lookup_host` — но пока
                    // туннель активен, системный резолвер сам смотрит на
                    // тот же fake-DNS обработчик (см. `resolvectl domain
                    // netr0 ~.` в routing.rs), так что такой запрос уходил
                    // по кругу в этот же процесс и никогда не резолвился.
                    // `resolve_via_public_dns` обходит это, запрашивая
                    // публичный резолвер напрямую по UDP; сам этот резолвер
                    // явно выведен из-под захвата туннелем в routing.rs.
                    let Some(ipv4) = crate::net::dns::resolve_via_public_dns(&domain).await else {
                        warn!(
                            "Failed to resolve excluded domain {} via public DNS, bypass route not added",
                            domain
                        );
                        continue;
                    };

                    debug!(
                        "Adding exception route for domain {} -> IP {}",
                        domain, ipv4
                    );
                    resolved_excluded.insert(domain.to_lowercase(), ipv4);

                    #[cfg(target_os = "linux")]
                    {
                        let _ = crate::tun::routing::run_cmd_ext(
                            &format!("ip route add {} via {}", ipv4, phys_gw),
                            true,
                        );
                        crate::tun::routing::allow_excluded_ip_linux(&ipv4.to_string());
                    }
                    #[cfg(target_os = "windows")]
                    let _ = crate::tun::routing::run_cmd_ext(
                        &format!("route add {} mask 255.255.255.255 {}", ipv4, phys_gw),
                        true,
                    );
                }
            });
        }

        let mut engine = Engine::new(
            smol_config,
            caps,
            dns_handler,
            tx_to_tunnel,
            rx_from_tunnel,
            factory,
        );

        engine.muxer = Some(muxer);
        engine.diag_rx = Some(diag_rx);

        engine.set_any_ip(self.config.any_ip);
        if self.config.transparent_mode {
            engine.set_transparent_mode();
        }
        engine.set_default_gateway(self.config.default_gateway)?;
        engine.activate();

        info!(
            "Engine successfully built. Stack IP: {} | Killswitch: {}",
            self.config.default_gateway, self.config.killswitch_enabled
        );

        Ok((engine, tun))
    }
}

#[cfg(test)]
mod dead_tunnel_tests {
    use super::tunnel_is_dead;
    use netrunner_core::net::TUNNEL_DEAD_AFTER;
    use tokio::time::Instant;

    #[test]
    fn dies_only_after_the_deadline_with_zero_legs() {
        let t0 = Instant::now();
        let mut deadline = t0 + TUNNEL_DEAD_AFTER;
        assert!(!tunnel_is_dead(
            Some(0),
            t0 + TUNNEL_DEAD_AFTER / 2,
            &mut deadline,
            false
        ));
        assert!(tunnel_is_dead(
            Some(0),
            t0 + TUNNEL_DEAD_AFTER,
            &mut deadline,
            false
        ));
    }

    #[test]
    fn a_live_leg_pushes_the_deadline_forward() {
        let t0 = Instant::now();
        let mut deadline = t0 + TUNNEL_DEAD_AFTER;
        let later = t0 + TUNNEL_DEAD_AFTER * 2;
        assert!(!tunnel_is_dead(Some(1), later, &mut deadline, false));
        assert_eq!(deadline, later + TUNNEL_DEAD_AFTER);
    }

    #[test]
    fn the_window_after_a_network_change_never_kills_and_restarts_the_countdown() {
        let t0 = Instant::now();
        let mut deadline = t0 + TUNNEL_DEAD_AFTER;
        // Zero legs far past the deadline, but a network change just happened.
        let now = t0 + TUNNEL_DEAD_AFTER * 3;
        assert!(!tunnel_is_dead(Some(0), now, &mut deadline, true));
        // The countdown restarted from now, so the grace expiring does not kill at once.
        assert!(!tunnel_is_dead(
            Some(0),
            now + TUNNEL_DEAD_AFTER / 2,
            &mut deadline,
            false
        ));
        assert!(tunnel_is_dead(
            Some(0),
            now + TUNNEL_DEAD_AFTER,
            &mut deadline,
            false
        ));
    }
}
