use bytes::{Bytes, BytesMut};
use netrunner_common::proxy::connection::muxer::{MuxMessage, Muxer};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{DeviceCapabilities, Medium};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::IpListenEndpoint;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, trace};

use crate::tun::virt_device::{TokenBuffer, VirtTunDevice};

pub enum BridgeState {
    WaitingHandshake,
    WaitingConnect,
    DataTransferring {
        tx_to_muxer: tokio::sync::mpsc::Sender<MuxMessage>,
        stream_id: u32,
    },
}

pub struct NetStack {
    interface: Interface,
    sockets: SocketSet<'static>,
    socket_buffers: HashMap<SocketHandle, BytesMut>,
    bridges: HashMap<SocketHandle, BridgeState>,
    muxer: Muxer,
    input: UnboundedSender<TokenBuffer>,
    output: UnboundedReceiver<TokenBuffer>,
    tun_available: Arc<AtomicBool>,
}

lazy_static::lazy_static! {
    static ref START_TIME: std::time::Instant = std::time::Instant::now();
}

fn current_smoltcp_time() -> Instant {
    let nanos = START_TIME.elapsed().as_micros() as i64;
    smoltcp::time::Instant::from_micros(nanos)
}

impl NetStack {
    pub fn new(muxer: Muxer) -> Self {
        let now = current_smoltcp_time();

        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;

        let (virt_device, iface_output, iface_input, in_buf_avail) = VirtTunDevice::new(caps);
        let device = Box::leak(Box::new(virt_device));

        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut interface = Interface::new(config, device, now);
        interface.set_any_ip(true);

        interface.update_ip_addrs(|addrs| {
            addrs
                .push(smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::v4(10, 0, 0, 2),
                    24,
                ))
                .unwrap();
        });

        interface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 2))
            .unwrap();

        let rx_data = Box::leak(vec![0u8; 4096].into_boxed_slice());
        let tx_data = Box::leak(vec![0u8; 4096].into_boxed_slice());

        let mut socket = SmolTcpSocket::new(SocketBuffer::new(rx_data), SocketBuffer::new(tx_data));

        // 4. Теперь listen() сработает, так как у интерфейса есть адрес!
        let endpoint = IpListenEndpoint {
            addr: None, // ВАЖНО: Принимаем пакеты для ЛЮБОГО IP назначения
            port: 443,  // Для HTTPS
        };
        socket.listen(endpoint).unwrap();

        let storage: Vec<SocketStorage> = (0..16).map(|_| SocketStorage::EMPTY).collect();
        let mut sockets = SocketSet::new(Box::leak(storage.into_boxed_slice()));
        sockets.add(socket);

        Self {
            interface,
            sockets,
            socket_buffers: HashMap::new(),
            bridges: HashMap::new(),
            muxer,
            input: iface_input,
            output: iface_output,
            tun_available: in_buf_avail,
        }
    }

    pub fn process_tun_input(&mut self, data: &[u8]) {
        let mut token = TokenBuffer::with_capacity(data.len());
        token.extend_from_slice(data);

        if self.input.send(token).is_ok() {
            self.tun_available
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    pub async fn next_outbound_packet(&mut self) -> Option<TokenBuffer> {
        self.output.recv().await
    }

    pub fn poll_delay(&mut self) -> tokio::time::Sleep {
        let timestamp = current_smoltcp_time();
        let ms = self
            .interface
            .poll_delay(timestamp, &self.sockets)
            .map(|d| d.total_millis())
            .unwrap_or(10); // Порог отзывчивости стека

        tokio::time::sleep(std::time::Duration::from_millis(ms))
    }

    pub fn poll(&mut self) {
        let timestamp = current_smoltcp_time();
    }
}
