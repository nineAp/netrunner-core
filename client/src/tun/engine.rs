use smoltcp::time::Instant;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::DeviceCapabilities,
};
use std::{
    mem,
    sync::{Arc, LazyLock, atomic::AtomicBool},
    time::Instant as StdInstant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::{Duration, sleep};
use tun::{DeviceReader, DeviceWriter};

use tracing::{debug, warn};

use crate::tun::connection_manager::ConnectionManager;
use crate::tun::device::{TokenBuffer, VirtTunDevice};
use crate::tun::tun::Tun;

pub static START_TIME: LazyLock<StdInstant> = LazyLock::new(StdInstant::now);
pub struct Engine {
    interface: Interface,
    socket_set: SocketSet<'static>,
    manager: ConnectionManager,
    device: VirtTunDevice,
    bridge_rx: UnboundedReceiver<TokenBuffer>,
    bridge_tx: UnboundedSender<TokenBuffer>,
    avail: Arc<AtomicBool>,
}

impl Engine {
    pub fn new(config: Config, caps: DeviceCapabilities, ip: String) -> Self {
        let now = Engine::current_time();
        let (mut device, bridge_rx, bridge_tx, avail) = VirtTunDevice::new(caps);
        let interface = Interface::new(config, &mut device, now);
        let socket_set = SocketSet::new(vec![]);
        Self {
            interface,
            socket_set,
            device,
            bridge_tx,
            bridge_rx,
            avail,
            manager: ConnectionManager::new(ip),
        }
    }

    pub async fn run(&mut self, tun: Tun) {
        //Bridge from tun to stack and stack to tun
        let (writer, reader) = tun.split().expect("Failed to split TUN");
        // Забираем bridge_rx, так как он нам нужен только в одной задаче
        let from_engine = mem::replace(&mut self.bridge_rx, mpsc::unbounded_channel().1);
        Self::spawn_tun_to_engine(reader, self.bridge_tx.clone(), self.avail.clone());
        Self::spawn_engine_to_tun(writer, from_engine);

        loop {
            self.manager.refill_sockets(&mut self.socket_set);
            self.poll();
            self.manager.process_sockets(&mut self.socket_set);
            if self.avail.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
                continue;
            }
            self.poll_delay().await;
        }
    }

    pub fn poll(&mut self) {
        let now = Self::current_time();
        // Передаем девайс и сокеты в интерфейс
        self.interface
            .poll(now, &mut self.device, &mut self.socket_set);
    }

    pub async fn poll_delay(&mut self) {
        let timestamp = Self::current_time();
        let delay = self.interface.poll_delay(timestamp, &self.socket_set);
        let sleep_duration = match delay {
            Some(d) => Duration::from_micros(d.micros()),
            None => Duration::from_millis(10),
        };
        sleep(sleep_duration).await;
    }

    fn spawn_tun_to_engine(
        mut reader: DeviceReader,
        to_engine: UnboundedSender<TokenBuffer>,
        is_avail: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            debug!("TUN-to-Engine bridge task started");
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf).await {
                if n == 0 {
                    break;
                }

                let mut token = TokenBuffer::with_capacity(n);
                token.extend_from_slice(&buf[..n]);

                if to_engine.send(token).is_ok() {
                    is_avail.store(true, std::sync::atomic::Ordering::Release);
                } else {
                    break;
                }
            }
            warn!("TUN-to-Engine bridge task stopped");
        });
    }

    fn spawn_engine_to_tun(
        mut writer: DeviceWriter,
        mut from_engine: UnboundedReceiver<TokenBuffer>,
    ) {
        tokio::spawn(async move {
            debug!("Engine-to-TUN bridge task started");
            while let Some(token) = from_engine.recv().await {
                if writer.write_all(&token).await.is_err() {
                    break;
                }
            }
            warn!("Engine-to-TUN bridge task stopped");
        });
    }

    fn current_time() -> Instant {
        let duration = StdInstant::now().duration_since(*START_TIME);
        Instant::from_micros(duration.as_micros() as i64)
    }

    pub fn add_address(&mut self, address: smoltcp::wire::IpCidr) {
        self.interface.update_ip_addrs(|addrs| {
            addrs
                .push(address)
                .expect("Failed to add IP: address list is full");
        });
        self.interface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
            .ok();
    }
}
