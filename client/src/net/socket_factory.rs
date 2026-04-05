use netrunner_core::net::NetworkConfig;
use smoltcp::{
    iface::SocketSet,
    socket::{icmp, tcp, udp},
    time::Duration,
    wire::{IpAddress, IpListenEndpoint},
};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficProfile {
    Interactive,
    Bulk,
    Dns,
    Default,
}

pub const TCP_SOCKET_KEEP_ALIVE: Duration = Duration::from_secs(15);
pub const TCP_SOCKET_ACTIVE_TIMEOUT: Duration = Duration::from_secs(20);

impl TrafficProfile {
    pub fn guess_from_port(port: u16, is_tcp: bool) -> Self {
        match (port, is_tcp) {
            (22, true) | (3389, true) | (5900, true) => Self::Interactive,
            (443, true) | (80, true) | (8080, true) | (1935, true) => Self::Bulk,
            (53, false) | (123, false) => Self::Dns,
            _ => Self::Default,
        }
    }
}

pub trait SocketProvider: Send + Sync {
    fn create_tcp(&self, profile: TrafficProfile) -> tcp::Socket<'static>;
    fn create_udp(&self, profile: TrafficProfile) -> udp::Socket<'static>;
    fn create_icmp(&self) -> icmp::Socket<'static>;
    fn create_listening_tcp(&self, addr: Option<IpAddress>, port: u16) -> tcp::Socket<'static>;
    fn create_bound_udp(&self, addr: Option<IpAddress>, port: u16) -> udp::Socket<'static>;
    fn create_base_set(&self, n_icmp: usize) -> SocketSet<'static>;
    fn reconfigure_tcp(&self, socket: &mut tcp::Socket, profile: TrafficProfile);
}

pub struct SmolSocketFactory {
    config: Arc<NetworkConfig>,
}

impl SmolSocketFactory {
    pub fn new(config: Arc<NetworkConfig>) -> Self {
        Self { config }
    }

    fn alloc_buf(&self, size: usize) -> Vec<u8> {
        // Убрали пул памяти, так как 1MB RX буферы раздуют оперативку (128MB+).
        // Выделение памяти через vec! при старте сокета работает достаточно быстро.
        vec![0u8; size]
    }
}

impl SocketProvider for SmolSocketFactory {
    fn create_tcp(&self, profile: TrafficProfile) -> tcp::Socket<'static> {
        // 👈 Асимметричные буферы: RX большой (Download), TX маленький (Upload)
        let (rx_size, tx_size) = match profile {
            TrafficProfile::Bulk => (self.config.tcp_rx_heavy, self.config.tcp_tx_heavy),
            TrafficProfile::Interactive => (self.config.tcp_rx_light, self.config.tcp_tx_light),
            _ => (self.config.tcp_rx_light * 2, self.config.tcp_tx_light * 2),
        };

        let rx_buffer = tcp::SocketBuffer::new(self.alloc_buf(rx_size));
        let tx_buffer = tcp::SocketBuffer::new(self.alloc_buf(tx_size));

        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

        self.reconfigure_tcp(&mut socket, profile);

        socket.set_keep_alive(Some(TCP_SOCKET_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_SOCKET_ACTIVE_TIMEOUT));

        socket
    }

    fn reconfigure_tcp(&self, socket: &mut tcp::Socket, profile: TrafficProfile) {
        match profile {
            TrafficProfile::Interactive => {
                socket.set_nagle_enabled(false);
                socket.set_ack_delay(None);
            }
            TrafficProfile::Bulk | TrafficProfile::Default => {
                socket.set_nagle_enabled(false);
                socket.set_ack_delay(None);
            }
            _ => {}
        }
    }

    fn create_udp(&self, profile: TrafficProfile) -> udp::Socket<'static> {
        let (buf_size, meta_count) = match profile {
            TrafficProfile::Bulk => (self.config.udp_buf_heavy, self.config.udp_meta_heavy),
            TrafficProfile::Dns => (self.config.udp_buf_light, self.config.udp_meta_light),
            _ => (
                self.config.udp_buf_heavy / 2,
                self.config.udp_meta_heavy / 2,
            ),
        };

        udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; meta_count],
                self.alloc_buf(buf_size),
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; meta_count],
                self.alloc_buf(buf_size),
            ),
        )
    }

    fn create_icmp(&self) -> icmp::Socket<'static> {
        icmp::Socket::new(
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]),
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]),
        )
    }

    fn create_listening_tcp(&self, addr: Option<IpAddress>, port: u16) -> tcp::Socket<'static> {
        let profile = TrafficProfile::guess_from_port(port, true);
        let mut socket = self.create_tcp(profile);
        let _ = socket.listen(IpListenEndpoint { addr, port });
        socket
    }

    fn create_bound_udp(&self, addr: Option<IpAddress>, port: u16) -> udp::Socket<'static> {
        let profile = TrafficProfile::guess_from_port(port, false);
        let mut socket = self.create_udp(profile);
        let _ = socket.bind(IpListenEndpoint { addr, port });
        socket
    }

    fn create_base_set(&self, n_icmp: usize) -> SocketSet<'static> {
        let mut sockets = SocketSet::new(Vec::with_capacity(128));
        sockets.add(self.create_bound_udp(None, 53));
        for _ in 0..n_icmp {
            sockets.add(self.create_icmp());
        }
        sockets
    }
}
