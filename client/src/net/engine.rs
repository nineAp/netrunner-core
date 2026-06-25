use bytes::Bytes;
use netrunner_core::net::ClientHandler;
use netrunner_core::net::NetworkConfig;
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
use std::sync::atomic::Ordering;
use std::{sync::LazyLock, time::Instant as StdInstant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tun::{DeviceReader, DeviceWriter};

use netrunner_logger::{debug, error, info, warn};

use crate::net::connection_manager::ConnectionManager;
use crate::net::dns::DnsHandler;
use crate::net::socket_factory::{SmolSocketFactory, SocketProvider};
use crate::tun::device::TrafficCounter;
use crate::tun::routing::setup_platform_routing;
use crate::tun::tun::Tun;

pub static START_TIME: LazyLock<StdInstant> = LazyLock::new(StdInstant::now);

/// How many inbound packets the device can hold before backpressure kicks in.
/// Each packet is ≤ MTU bytes, so at 1500 B × 64 = 96 KB max queue.
const DEVICE_RX_CAP: usize = 64;
/// How many outbound packets smoltcp can stage before we drain them.
const DEVICE_TX_CAP: usize = 64;
/// Bounded capacity for the TUN-reader → engine channel (packets).
const TUN_CHAN_CAP: usize = 128;

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
            // Drain all available frames without blocking.
            loop {
                match rx_tunnel.try_recv() {
                    Ok(frame) => {
                        work_done = true;
                        if frame.event == RawCastEvent::Close {
                            local_cache.remove(&frame.socket_id);
                            inbound_map.remove(&frame.socket_id);
                        } else if frame.event == RawCastEvent::Data {
                            let tx_opt = if let Some(cached) = local_cache.get(&frame.socket_id) {
                                Some(cached.clone())
                            } else if let Some(ref_tx) = inbound_map.get(&frame.socket_id) {
                                let val = ref_tx.value().clone();
                                local_cache.insert(frame.socket_id, val.clone());
                                Some(val)
                            } else {
                                None
                            };

                            if let Some((tx, is_saturated)) = tx_opt {
                                if is_saturated.load(Ordering::Relaxed) {
                                    continue;
                                }
                                match tx.try_send(frame.payload) {
                                    Ok(_) => {}
                                    Err(mpsc::error::TrySendError::Full(data)) => {
                                        // Spawn a task to wait for space rather than drop.
                                        let tx2 = tx.clone();
                                        tokio::spawn(async move {
                                            let _ = tx2.send(data).await;
                                        });
                                    }
                                    Err(_) => {}
                                }
                            }
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
                        self.stats.record_rx(pkt.len());
                        self.manager
                            .try_create_socket_from_packet(&pkt, &mut self.socket_set);
                        self.device.push_rx(pkt);
                        work_done = true;
                        packets_read += 1;
                        if packets_read >= 250 {
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
            while let Some(pkt) = self.device.pop_tx() {
                self.stats.record_tx(pkt.len());
                // Non-blocking: if TUN writer is overloaded, drop the packet.
                // TCP will retransmit; UDP is best-effort.
                if self.tun_tx.try_send(pkt).is_err() {
                    break;
                }
            }

            // ── 5. Stats logging ─────────────────────────────────────────
            if last_stats_log.elapsed() >= Duration::from_secs(5) {
                let stats = self.stats.get_stats();
                info!(
                    "TunDevice Traffic: RX: {:.2} MB ({} pkts) | TX: {:.2} MB ({} pkts) | Speed: ↓{:.2} MB/s, ↑{:.2} MB/s",
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

            // ── 6. Adaptive timing ───────────────────────────────────────
            if work_done {
                tokio::task::yield_now().await;
            } else {
                let delay = self
                    .interface
                    .poll_delay(Self::current_time(), &self.socket_set);

                let sleep_time = delay
                    .map(|d| {
                        std::cmp::min(
                            Duration::from_micros(d.micros()),
                            Duration::from_millis(5),
                        )
                    })
                    .unwrap_or(Duration::from_millis(5));

                tokio::select! {
                    _ = sleep(sleep_time) => {}
                    msg = tun_rx.recv() => {
                        match msg {
                            Some(pkt) => {
                                self.stats.record_rx(pkt.len());
                                self.manager.try_create_socket_from_packet(&pkt, &mut self.socket_set);
                                self.device.push_rx(pkt);
                            }
                            None => break,
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
            let mut buf = vec![0u8; 65536];
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

        let cap = NetworkConfig::global().channel_capacity;
        let (tx_to_tunnel, rx_for_client_handler) = mpsc::channel::<RawCastFrame>(cap);
        let (tx_for_client_handler, rx_from_tunnel) = mpsc::channel::<RawCastFrame>(cap);

        info!("Establishing secure tunnel to proxy server...");
        ClientHandler::connect(
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
