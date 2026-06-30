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
use netrunner_core::net::NetworkConfig;
use netrunner_core::net::Muxer;
use netrunner_core::net::diagnostics::{
    self, DiagnosisRx, DiagnosticsEvent, DiagnosticsSnapshot, DiagnosticsStore,
    EngineMetrics, SocketMetrics, current_timestamp_ms,
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
use crate::tun::routing::setup_platform_routing;
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
/// Per-socket download backlog cap. A socket whose channel stays full for more
/// than this many queued frames is treated as a dead/stuck consumer and dropped,
/// so it can never stall the shared download pipe for other sockets.
const MAX_PENDING_FRAMES_PER_SOCKET: usize = 64;
/// Max diagnostics snapshots buffered locally awaiting upload to the server.
/// The most useful triggers (leg disconnect/reconnect) fire exactly when no leg
/// is up to carry them, so snapshots wait here and flush once a leg recovers.
/// Oldest is dropped past the cap — recent state matters more than ancient.
const DIAG_OUTBOX_CAP: usize = 128;
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
    /// Per-socket backlog of download frames whose target channel was full.
    /// Keyed by socket_id so a single slow/dead consumer can NEVER stall the
    /// shared download pipe for other sockets — the old single global slot did
    /// exactly that: one stuck socket (e.g. an app that stopped reading after a
    /// speedtest) froze rx_tunnel draining for everyone, killing all download.
    /// Frames per socket stay in order; a backlog past
    /// MAX_PENDING_FRAMES_PER_SOCKET means the consumer is dead → socket dropped.
    pending_download: std::collections::HashMap<u64, std::collections::VecDeque<Bytes>>,
    /// Cumulative download diagnostics (logged every STATS_LOG_INTERVAL).
    dl_dispatched: u64,
    dl_dropped_stuck: u64,
    dl_recv_closed: u64,
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
        let (writer, reader) = tun.split().expect("Failed to split TUN");

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

        loop {
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
                    if let Some(q) = self.pending_download.get_mut(&sid) {
                        while let Some(front) = q.pop_front() {
                            match tx.try_send(front) {
                                Ok(_) => {
                                    work_done = true;
                                    self.dl_dispatched += 1;
                                }
                                Err(mpsc::error::TrySendError::Full(p)) => {
                                    q.push_front(p);
                                    break;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    self.dl_recv_closed += 1;
                                    q.clear();
                                    break;
                                }
                            }
                        }
                    }
                    // Drop the backlog entry once fully drained (borrow of q ended).
                    if self
                        .pending_download
                        .get(&sid)
                        .map_or(false, |q| q.is_empty())
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
            loop {
                match rx_tunnel.try_recv() {
                    Ok(frame) => {
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
                    Err(_) => break,
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
                let pending_frames: usize =
                    self.pending_download.values().map(|q| q.len()).sum();
                let worst_backlog = self
                    .pending_download
                    .values()
                    .map(|q| q.len())
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
                loop {
                    match diag_rx.try_recv() {
                        Ok(event) => {
                            let snap = self.build_snapshot(event);
                            // Queue a compact JSON copy for upload to the server,
                            // then keep the snapshot in the local ring buffer.
                            if self.diag_outbox.len() >= DIAG_OUTBOX_CAP {
                                self.diag_outbox.pop_front();
                            }
                            self.diag_outbox.push_back(Bytes::from(snap.to_json_line()));
                            self.diag_store.push(snap);
                        }
                        Err(_) => break,
                    }
                }
                self.diag_rx = Some(diag_rx);
            }

            // ── 6b. Ship queued diagnostics to the server ────────────────
            // Best-effort, cold path: only runs when there's a backlog AND a leg
            // is up to carry it. send_diag_report is a non-blocking try_send under
            // the hood, so the await is cheap; on failure (no leg accepted it) we
            // re-queue the snapshot and retry on a later tick.
            if !self.diag_outbox.is_empty() {
                if let Some(muxer) = self.muxer.clone() {
                    if muxer.active_legs_count() > 0 {
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
    /// backlog is started. A backlog past MAX_PENDING_FRAMES_PER_SOCKET means the
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
        if let Some(q) = self.pending_download.get_mut(&socket_id) {
            if q.len() < MAX_PENDING_FRAMES_PER_SOCKET {
                q.push_back(payload);
                return;
            }
            // Over cap → fall through to drop the stuck socket.
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
                    let mut q = std::collections::VecDeque::with_capacity(8);
                    q.push_back(p);
                    self.pending_download.insert(socket_id, q);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.dl_recv_closed += 1;
                    local_cache.remove(&socket_id);
                }
            }
            return;
        }

        // Reached only when an existing backlog is at/over cap: the consumer is
        // dead/stuck — drop the socket so it can't stall the shared download pipe.
        self.dl_dropped_stuck += 1;
        warn!(
            "📥 Download: socket {} backlog cap ({}) hit — consumer dead, dropping socket to free the pipe",
            socket_id, MAX_PENDING_FRAMES_PER_SOCKET
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
                if let smoltcp::socket::Socket::Tcp(tcp) = socket {
                    if tcp.is_active() {
                        return Some(SocketSnap {
                            handle_str: format!("{}", handle),
                            state: format!("{:?}", tcp.state()),
                            send_queue: tcp.send_queue(),
                            send_cap: tcp.send_capacity(),
                            recv_queue: tcp.recv_queue(),
                            recv_cap: tcp.recv_capacity(),
                        });
                    }
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

    pub fn set_default_gateway(&mut self, gateway: smoltcp::wire::Ipv4Address) {
        info!("Setting default IPv4 gateway to: {}", gateway);
        self.interface.routes_mut().remove_default_ipv4_route();
        self.interface
            .routes_mut()
            .add_default_ipv4_route(gateway)
            .expect("Failed to set default gateway");
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
#[derive(Clone, Debug)]
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
        }
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
                "Applying platform routing rules (Killswitch: {})...",
                self.config.killswitch_enabled
            );
            setup_platform_routing(
                &self.config.remote_address,
                self.config.killswitch_enabled,
                &self.config.excluded_apps,
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

        info!("Establishing secure tunnel to proxy server...");
        let muxer = ClientHandler::connect(
            &self.config.remote_address,
            rx_for_client_handler,
            tx_for_client_handler,
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
            tokio::spawn(async move {
                #[cfg(target_os = "linux")]
                let phys_gw = crate::tun::routing::get_default_gateway_linux()
                    .unwrap_or_else(|| "192.168.1.1".into());
                #[cfg(not(target_os = "linux"))]
                let phys_gw = "192.168.1.1";

                for domain in excluded_domains {
                    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:443", domain)).await {
                        for addr in addrs {
                            if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                                debug!(
                                    "Adding exception route for domain {} -> IP {}",
                                    domain, ipv4
                                );
                                #[cfg(target_os = "linux")]
                                let _ = crate::tun::routing::run_cmd_ext(
                                    &format!("ip route add {} via {}", ipv4, phys_gw),
                                    true,
                                );
                                #[cfg(target_os = "windows")]
                                let _ = crate::tun::routing::run_cmd_ext(
                                    &format!(
                                        "route add {} mask 255.255.255.255 {}",
                                        ipv4, phys_gw
                                    ),
                                    true,
                                );
                            }
                        }
                    }
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
        engine.set_default_gateway(self.config.default_gateway);
        engine.activate();

        info!(
            "Engine successfully built. Stack IP: {} | Killswitch: {}",
            self.config.default_gateway, self.config.killswitch_enabled
        );

        Ok((engine, tun))
    }
}
