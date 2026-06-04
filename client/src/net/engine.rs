use bytes::Bytes;
use netrunner_core::net::ClientHandler;
use netrunner_core::net::NetworkConfig;
use netrunner_core::rawcast::{RawCastEvent, RawCastFrame};
use smoltcp::iface::PollResult;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::DeviceCapabilities,
};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::{
    sync::{Arc, LazyLock, atomic::AtomicBool},
    time::Instant as StdInstant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::time::{Duration, sleep};
use tun::{DeviceReader, DeviceWriter};

use netrunner_logger::{debug, error, info, warn};

use crate::net::connection_manager::ConnectionManager;
use crate::net::dns::DnsHandler;
use crate::net::socket_factory::{SmolSocketFactory, SocketProvider};
use crate::tun::device::{TokenBuffer, VirtTunDevice};
use crate::tun::routing::setup_platform_routing;
use crate::tun::tun::Tun;

pub static START_TIME: LazyLock<StdInstant> = LazyLock::new(StdInstant::now);

pub struct Engine {
    interface: Interface,
    socket_set: SocketSet<'static>,
    manager: ConnectionManager,
    device: VirtTunDevice,
    to_smoltcp_tx: UnboundedSender<TokenBuffer>,
    from_smoltcp_rx: Option<UnboundedReceiver<TokenBuffer>>,
    avail: Arc<AtomicBool>,
    rx_from_tunnel: Option<Receiver<RawCastFrame>>,
    factory: Arc<dyn SocketProvider>,
}

impl Engine {
    pub fn new(
        config: Config,
        caps: DeviceCapabilities,
        dns_handler: DnsHandler,
        tx_to_tunnel: Sender<RawCastFrame>,
        rx_from_tunnel: Receiver<RawCastFrame>,
        factory: Arc<dyn SocketProvider>,
    ) -> Self {
        let now = Engine::current_time();

        let (mut device, to_smoltcp_tx, from_smoltcp_rx, avail) = VirtTunDevice::new(caps);
        let interface = Interface::new(config, &mut device, now);

        let socket_set = ConnectionManager::setup_sockets(factory.as_ref(), 2);
        let manager = ConnectionManager::new(dns_handler, tx_to_tunnel, factory.clone());

        Self {
            interface,
            socket_set,
            device,
            to_smoltcp_tx,
            from_smoltcp_rx: Some(from_smoltcp_rx),
            avail,
            manager,
            rx_from_tunnel: Some(rx_from_tunnel),
            factory,
        }
    }

    pub async fn run(&mut self, tun: Tun) {
        info!("Current routes: {:?}", self.interface.routes());
        let (writer, reader) = tun.split().expect("Failed to split TUN");

        let (tun_to_engine_tx, mut tun_to_engine_rx) = mpsc::unbounded_channel::<TokenBuffer>();

        Self::spawn_tun_reader(reader, tun_to_engine_tx, self.avail.clone());

        let from_smoltcp_rx = self.from_smoltcp_rx.take().expect("Engine started twice");
        Self::spawn_tun_writer(writer, from_smoltcp_rx);

        let mut last_stats_log = StdInstant::now();

        let inbound_map = self.manager.tracker.inbound_tx.clone();
        let mut rx_tunnel = self.rx_from_tunnel.take().unwrap();

        tokio::spawn(async move {
            let mut local_cache: std::collections::HashMap<
                u64,
                (mpsc::Sender<Bytes>, Arc<AtomicBool>),
            > = std::collections::HashMap::new();

            while let Some(frame) = rx_tunnel.recv().await {
                if frame.event == RawCastEvent::Close {
                    local_cache.remove(&frame.socket_id);
                    inbound_map.remove(&frame.socket_id);
                } else if frame.event == RawCastEvent::Data {
                    let tx_opt: Option<(mpsc::Sender<Bytes>, Arc<AtomicBool>)> =
                        if let Some(cached) = local_cache.get(&frame.socket_id) {
                            Some(cached.clone())
                        } else if let Some(ref_tx) = inbound_map.get(&frame.socket_id) {
                            let val = ref_tx.value().clone();
                            local_cache.insert(frame.socket_id, val.clone());
                            Some(val)
                        } else {
                            None
                        };

                    if let Some((tx, is_saturated)) = tx_opt {
                        // Pressure-Aware drop (нулевая нагрузка на ОС)
                        if is_saturated.load(Ordering::Relaxed) {
                            continue;
                        }

                        match tx.try_send(frame.payload) {
                            Ok(_) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                netrunner_logger::trace!(
                                    "⚠️ Local socket {} buffer suddenly full. Dropping frame.",
                                    frame.socket_id
                                );
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        });

        loop {
            let mut work_done = false;
            let mut repeat_poll = true;
            let now = Self::current_time();

            // 1. Опрашиваем сокеты до тех пор, пока есть движение данных
            while repeat_poll {
                self.manager.process_sockets(&mut self.socket_set, now);
                let poll_res = self.poll();
                self.manager.cleanup(&mut self.socket_set);
                if matches!(poll_res, PollResult::SocketStateChanged) {
                    work_done = true;
                    repeat_poll = true;
                } else {
                    repeat_poll = false;
                }
            }

            if last_stats_log.elapsed() >= Duration::from_secs(5) {
                let manager_ref = &self.manager;
                self.factory
                    .log_stats(&self.socket_set, &|handle| manager_ref.get_buf_info(handle));
                last_stats_log = StdInstant::now();
            }

            // 2. БАТЧИНГ: Выгребаем все доступные пакеты из TUN без блокировки
            let mut packets_processed = 0;
            while let Ok(token) = tun_to_engine_rx.try_recv() {
                self.manager
                    .try_create_socket_from_packet(&token, &mut self.socket_set);
                if self.to_smoltcp_tx.send(token).is_ok() {
                    self.device.mark_rx_available();
                }
                work_done = true;
                packets_processed += 1;
                // Предотвращаем starvation: если пакетов слишком много, даем другим потокам подышать
                if packets_processed > 250 {
                    break;
                }
            }

            // 3. АДАПТИВНЫЙ ТАЙМИНГ
            if work_done {
                // Если мы обработали пакеты или сокеты сдвинулись - НЕ СПИМ.
                // Уступаем квант времени другим задачам и моментально возвращаемся в цикл.
                tokio::task::yield_now().await;
            } else {
                // Мы отдыхаем только если сеть полностью простаивает
                let delay = self
                    .interface
                    .poll_delay(Self::current_time(), &self.socket_set);

                let sleep_time = delay
                    .map(|d| {
                        std::cmp::min(Duration::from_micros(d.micros()), Duration::from_millis(5))
                    })
                    .unwrap_or(Duration::from_millis(5));

                tokio::select! {
                    _ = sleep(sleep_time) => {}
                    msg = tun_to_engine_rx.recv() => {
                        if let Some(token) = msg {
                            self.manager.try_create_socket_from_packet(&token, &mut self.socket_set);
                            if self.to_smoltcp_tx.send(token).is_ok() {
                                self.device.mark_rx_available();
                            }
                        } else {
                            break;
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

    fn spawn_tun_reader(
        mut reader: DeviceReader,
        to_engine: mpsc::UnboundedSender<TokenBuffer>,
        is_avail: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            debug!("TUN Reader task started");

            loop {
                // 1. Берем чистый буфер
                let mut token = TokenBuffer::with_capacity(65536);

                // 2. Используем временный срез для чтения
                // Это гарантирует, что мы пишем в начало буфера
                let mut temp_buf = [0u8; 65536];

                match reader.read(&mut temp_buf).await {
                    Ok(n) if n > 0 => {
                        // 3. Копируем в наш TokenBuffer (это быстро, 64кБ - это L1 кэш)
                        token.extend_from_slice(&temp_buf[..n]);

                        if to_engine.send(token).is_ok() {
                            is_avail.store(true, Ordering::Release);
                        } else {
                            break;
                        }
                    }
                    Ok(_) => break, // EOF
                    Err(e) => {
                        error!("FATAL: TUN Reader task died with error: {}", e);
                        break;
                    }
                }
            }
        });
    }

    fn spawn_tun_writer(
        mut writer: DeviceWriter,
        mut from_smoltcp: UnboundedReceiver<TokenBuffer>,
    ) {
        tokio::spawn(async move {
            debug!("TUN Writer task started");
            while let Some(token) = from_smoltcp.recv().await {
                if writer.write_all(&token).await.is_err() {
                    break;
                }
            }
            warn!("TUN Writer task stopped");
        });
    }

    fn current_time() -> Instant {
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
                                    &format!("route add {} mask 255.255.255.255 {}", ipv4, phys_gw),
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
