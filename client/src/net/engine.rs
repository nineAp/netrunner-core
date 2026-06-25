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
    /// A single download frame that couldn't be forwarded to its socket channel
    /// (channel was full).  Retried at the start of the next engine tick BEFORE
    /// reading more frames from rx_tunnel.  This preserves in-order delivery.
    pending_download: Option<(u64, Bytes)>,
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
            pending_download: None,
        }
    }

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
            // ORDERING CONTRACT: we must NEVER reorder bytes for a given socket.
            // Spawning a background task when the channel is full is forbidden —
            // it creates a race where later frames overtake the stalled one.
            //
            // Instead we use a single `pending_download` slot:
            //   • Retry any stalled frame FIRST each tick.
            //   • Only drain rx_tunnel once pending is empty.
            //   • If delivery fails again, set pending and skip rx_tunnel until
            //     the next tick (when smoltcp has had a chance to drain the channel).

            // — Retry stalled frame from previous tick —
            if let Some((socket_id, payload)) = self.pending_download.take() {
                let tx_opt = if let Some(cached) = local_cache.get(&socket_id) {
                    Some(cached.clone())
                } else if let Some(ref_tx) = inbound_map.get(&socket_id) {
                    let val = ref_tx.value().clone();
                    local_cache.insert(socket_id, val.clone());
                    Some(val)
                } else {
                    None
                };
                match tx_opt {
                    Some((tx, _)) => match tx.try_send(payload) {
                        Ok(_) => { work_done = true; }
                        Err(mpsc::error::TrySendError::Full(p)) => {
                            // Still full — will retry next tick.
                            self.pending_download = Some((socket_id, p));
                        }
                        Err(_) => {} // socket gone — drop
                    },
                    None => {} // socket gone — drop
                }
            }

            // — Drain rx_tunnel only when no frame is waiting for its slot —
            if self.pending_download.is_none() {
                loop {
                    match rx_tunnel.try_recv() {
                        Ok(frame) => {
                            work_done = true;
                            if frame.event == RawCastEvent::Close {
                                local_cache.remove(&frame.socket_id);
                                inbound_map.remove(&frame.socket_id);
                            } else if frame.event == RawCastEvent::Data {
                                let socket_id = frame.socket_id;
                                let tx_opt = if let Some(cached) = local_cache.get(&socket_id) {
                                    Some(cached.clone())
                                } else if let Some(ref_tx) = inbound_map.get(&socket_id) {
                                    let val = ref_tx.value().clone();
                                    local_cache.insert(socket_id, val.clone());
                                    Some(val)
                                } else {
                                    None
                                };
                                if let Some((tx, _)) = tx_opt {
                                    match tx.try_send(frame.payload) {
                                        Ok(_) => {}
                                        Err(mpsc::error::TrySendError::Full(data)) => {
                                            // Channel full — stash and stop draining.
                                            self.pending_download = Some((socket_id, data));
                                            break;
                                        }
                                        Err(_) => {} // socket gone — drop
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
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
                            self.diag_store.push(snap);
                        }
                        Err(_) => break,
                    }
                }
                self.diag_rx = Some(diag_rx);
            }

            // ── 7. Adaptive timing ───────────────────────────────────────
            if work_done {
                tokio::task::yield_now().await;
            } else {
                let delay = self
                    .interface
                    .poll_delay(Self::current_time(), &self.socket_set);

                let sleep_time = delay
                    .map(|d| Duration::from_micros(d.micros()).min(MAX_POLL_SLEEP))
                    .unwrap_or(MAX_POLL_SLEEP);

                if self.pending_download.is_some() {
                    // A frame is stalled — don't read more from rx_tunnel yet
                    // (would risk overwriting the pending slot or draining out-
                    // of-order).  Just wait for smoltcp to drain inbound_tx.
                    tokio::select! {
                        _ = sleep(sleep_time) => {}
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
                    }
                } else {
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
                        // Dispatch inline; step 1 drains the rest next iteration.
                        frame = rx_tunnel.recv() => {
                            match frame {
                                None => break,
                                Some(f) => {
                                    if f.event == RawCastEvent::Close {
                                        local_cache.remove(&f.socket_id);
                                        inbound_map.remove(&f.socket_id);
                                    } else if f.event == RawCastEvent::Data {
                                        let socket_id = f.socket_id;
                                        let tx_opt = if let Some(cached) = local_cache.get(&socket_id) {
                                            Some(cached.clone())
                                        } else if let Some(ref_tx) = inbound_map.get(&socket_id) {
                                            let val = ref_tx.value().clone();
                                            local_cache.insert(socket_id, val.clone());
                                            Some(val)
                                        } else {
                                            None
                                        };
                                        if let Some((tx, _)) = tx_opt {
                                            match tx.try_send(f.payload) {
                                                Ok(_) => {}
                                                Err(mpsc::error::TrySendError::Full(data)) => {
                                                    // Stash — next tick retries.
                                                    self.pending_download = Some((socket_id, data));
                                                }
                                                Err(_) => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll(&mut self) -> PollResult {
        let now = Self::current_time();
        self.interface
            .poll(now, &mut self.device, &mut self.socket_set)
    }

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

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub remote_address: String,
    pub cache_path: String,
    pub mtu: usize,
    pub setup_routing: bool,
    pub any_ip: bool,
    pub transparent_mode: bool,
    pub default_gateway: Ipv4Addr,
    pub killswitch_enabled: bool,
    pub excluded_apps: Vec<String>,
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
