use netrunner_core::proxy::connection::connection::ClientHandler;
use netrunner_core::proxy::connection::muxer::Muxer;
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
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::{Duration, sleep};
use tun::{DeviceReader, DeviceWriter};

use netrunner_logger::{debug, error, info, warn};

use crate::net::connection_manager::ConnectionManager;
use crate::net::dns::DnsHandler;
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
}

impl Engine {
    pub fn new(config: Config, caps: DeviceCapabilities, dns_handler: DnsHandler) -> Self {
        let now = Engine::current_time();

        let (mut device, to_smoltcp_tx, from_smoltcp_rx, avail) = VirtTunDevice::new(caps);
        let interface = Interface::new(config, &mut device, now);

        let socket_set = ConnectionManager::setup_sockets(2);
        let manager = ConnectionManager::new(dns_handler);

        Self {
            interface,
            socket_set,
            device,
            to_smoltcp_tx,
            from_smoltcp_rx: Some(from_smoltcp_rx),
            avail,
            manager,
        }
    }

    pub async fn run(&mut self, tun: Tun) {
        info!("Current routes: {:?}", self.interface.routes());
        let (writer, reader) = tun.split().expect("Failed to split TUN");

        let (tun_to_engine_tx, mut tun_to_engine_rx) = mpsc::unbounded_channel();
        Self::spawn_tun_reader(reader, tun_to_engine_tx, self.avail.clone());

        let from_smoltcp_rx = self.from_smoltcp_rx.take().expect("Engine started twice");
        Self::spawn_tun_writer(writer, from_smoltcp_rx);

        let mut last_log = StdInstant::now();

        loop {
            while let Ok(token) = tun_to_engine_rx.try_recv() {
                self.manager
                    .try_create_socket_from_packet(&token, &mut self.socket_set);

                if self.to_smoltcp_tx.send(token).is_ok() {
                    self.device.mark_rx_available();
                }
            }

            let result = self.poll();
            self.manager.process_sockets(&mut self.socket_set);

            if last_log.elapsed() >= Duration::from_secs(5) {
                self.manager.log_status(&self.socket_set);
                last_log = StdInstant::now();
            }

            if matches!(result, PollResult::SocketStateChanged) {
                continue;
            }

            if self.avail.swap(false, Ordering::Acquire) {
                tokio::task::yield_now().await;
                continue;
            }

            self.manager.cleanup(&mut self.socket_set);
            self.poll_delay().await;
        }
    }

    fn poll(&mut self) -> PollResult {
        let now = Self::current_time();
        self.interface
            .poll(now, &mut self.device, &mut self.socket_set)
    }

    async fn poll_delay(&mut self) {
        let timestamp = Self::current_time();
        let delay = self.interface.poll_delay(timestamp, &self.socket_set);
        let sleep_duration = match delay {
            Some(d) => Duration::from_micros(d.micros()),
            None => Duration::from_millis(10),
        };
        sleep(sleep_duration).await;
    }

    fn spawn_tun_reader(
        mut reader: DeviceReader,
        to_engine: UnboundedSender<TokenBuffer>,
        is_avail: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            debug!("TUN Reader task started");
            let mut buf = [0u8; 65536];
            while let Ok(n) = reader.read(&mut buf).await {
                if n == 0 {
                    break;
                }

                let first_byte = buf[0];
                let version = first_byte >> 4;
                if version == 4 {
                    if buf[12..16] == [0, 0, 0, 0] {
                        continue;
                    }
                    if buf[16] >= 224 && buf[16] <= 239 {
                        continue;
                    }
                } else if version == 6 {
                    if first_byte == 0xff {
                        continue;
                    }
                }

                let mut token = TokenBuffer::with_capacity(n);
                token.extend_from_slice(&buf[..n]);

                if to_engine.send(token).is_ok() {
                    is_avail.store(true, Ordering::Release);
                } else {
                    break;
                }
            }
            warn!("TUN Reader task stopped");
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

// ============================================================================
// КОНФИГУРАЦИЯ ДВИЖКА
// ============================================================================

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub remote_address: String,
    pub cache_path: String,
    pub mtu: usize,
    pub setup_routing: bool,
    pub any_ip: bool,
    pub transparent_mode: bool,
    pub default_gateway: Ipv4Addr,
}

impl EngineConfig {
    pub fn new(remote_address: impl Into<String>) -> Self {
        Self {
            remote_address: remote_address.into(),
            cache_path: ".".to_string(),
            mtu: 1350,
            setup_routing: true,
            any_ip: true,
            transparent_mode: true,
            default_gateway: Ipv4Addr::new(10, 0, 0, 2),
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

    pub fn _disable_routing(mut self) -> Self {
        self.setup_routing = false;
        self
    }
}

// ============================================================================
// БИЛДЕР ДВИЖКА
// ============================================================================

pub struct EngineBuilder {
    config: EngineConfig,
    tun_device: Option<Tun>,
}

impl EngineBuilder {
    /// Инициализируем билдер на основе готового конфига
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            tun_device: None,
        }
    }

    /// Передаем TUN интерфейс (зависит от платформы, поэтому не в конфиге)
    pub fn with_tun(mut self, tun: Tun) -> Self {
        self.tun_device = Some(tun);
        self
    }

    pub async fn build(self) -> Result<(Engine, Tun), String> {
        let tun = self.tun_device.ok_or("TUN device is required")?;

        info!(
            "Initializing Engine components with config: {:?}",
            self.config
        );

        // 1. Инициализация DNS
        let mut dns_handler = DnsHandler::new(&self.config.cache_path);
        if let Err(e) = dns_handler.init().await {
            error!("Failed to initialize DNS blocklist: {}", e);
        }

        // 2. Настройка системного роутинга (Опционально)
        if self.config.setup_routing {
            info!("Applying platform routing rules...");
            if let Err(e) = setup_platform_routing(&self.config.remote_address) {
                return Err(format!("Routing setup failed: {}", e));
            }
        } else {
            info!("Platform routing setup skipped via config.");
        }

        // 3. Конфигурация интерфейса smoltcp
        let smol_config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.config.mtu; // Берем из конфига
        caps.medium = smoltcp::phy::Medium::Ip;

        // 4. Подключение к серверу
        info!("Establishing secure tunnel to proxy server...");
        let muxer = ClientHandler::connect(&self.config.remote_address)
            .await
            .map_err(|e| format!("Failed to establish secure tunnel: {}", e))?;
        info!("Secure tunnel established, Muxer is ready.");

        // 5. Инициализация и настройка Engine
        let mut engine = Engine::new(smol_config, caps, dns_handler);

        engine.set_any_ip(self.config.any_ip);

        if self.config.transparent_mode {
            engine.set_transparent_mode();
        }

        engine.set_default_gateway(self.config.default_gateway);
        engine.activate();

        info!("Stack IP initialized: {}", self.config.default_gateway);

        Ok((engine, tun))
    }
}
