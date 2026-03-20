use smoltcp::iface::PollResult;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::DeviceCapabilities,
};
use std::sync::atomic::Ordering;
use std::{
    sync::{Arc, LazyLock, atomic::AtomicBool},
    time::Instant as StdInstant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::{Duration, sleep};
use tun::{DeviceReader, DeviceWriter};

use netrunner_logger::{debug, info, warn};

use crate::connections::dns::DnsHandler;
use crate::tun::connection_manager::ConnectionManager;
use crate::tun::device::{TokenBuffer, VirtTunDevice};
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
    pub fn new(
        config: Config,
        caps: DeviceCapabilities,
        ip: String,
        dns_handler: DnsHandler,
    ) -> Self {
        let now = Engine::current_time();

        let (mut device, to_smoltcp_tx, from_smoltcp_rx, avail) = VirtTunDevice::new(caps);
        let interface = Interface::new(config, &mut device, now);

        let socket_set = ConnectionManager::setup_sockets(64, 4);
        let manager = ConnectionManager::new(ip, dns_handler);

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
