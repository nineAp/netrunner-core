use netrunner_core::net::{
    BUFFERBLOAT_WARN_THRESHOLD, HTTPS_PORT, HTTP_ALT_PORT, HTTP_PORT, ICMP_BUFFER_SIZE,
    ICMP_META_SLOTS, MAX_SOCKETS, NTP_PORT, RDP_PORT, RTMP_PORT, SSH_PORT, VNC_PORT, NetworkConfig,
    DNS_PORT,
};
use netrunner_logger::{info, warn};
use smoltcp::{
    iface::SocketSet,
    socket::{
        icmp,
        tcp::{self, CongestionControl},
        udp,
    },
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
pub const TCP_SOCKET_ACTIVE_TIMEOUT: Duration = Duration::from_secs(60);

impl TrafficProfile {
    pub fn guess_from_port(port: u16, is_tcp: bool) -> Self {
        match (port, is_tcp) {
            (SSH_PORT, true) | (RDP_PORT, true) | (VNC_PORT, true) => Self::Interactive,
            (HTTPS_PORT, true) | (HTTP_PORT, true) | (HTTP_ALT_PORT, true) | (RTMP_PORT, true) => {
                Self::Bulk
            }
            (DNS_PORT, false) | (NTP_PORT, false) => Self::Dns,
            _ => Self::Default,
        }
    }
}

pub trait SocketProvider: Send + Sync {
    fn create_tcp(&self, profile: TrafficProfile) -> tcp::Socket;
    fn create_udp(&self, profile: TrafficProfile) -> udp::Socket<'static>;
    fn create_icmp(&self, profile: TrafficProfile) -> icmp::Socket<'static>;

    fn create_listening_tcp(&self, addr: Option<IpAddress>, port: u16) -> tcp::Socket;
    fn create_bound_udp(&self, addr: Option<IpAddress>, port: u16) -> udp::Socket<'static>;
    fn create_base_set(&self, n_icmp: usize) -> SocketSet<'static>;
    fn reconfigure_tcp(&self, socket: &mut tcp::Socket, profile: TrafficProfile);

    // 🔥 НОВЫЙ МЕТОД: Логирование статистики всех сокетов в сете
    fn log_stats(
        &self,
        sockets: &SocketSet,
        get_app_pending: &dyn Fn(smoltcp::iface::SocketHandle) -> usize,
    );
}

pub struct SmolSocketFactory {
    config: Arc<NetworkConfig>,
}

impl SmolSocketFactory {
    pub fn new(config: Arc<NetworkConfig>) -> Self {
        Self { config }
    }

    fn alloc_buf(&self, size: usize) -> Vec<u8> {
        vec![0u8; size]
    }
}

impl SocketProvider for SmolSocketFactory {
    fn create_tcp(&self, profile: TrafficProfile) -> tcp::Socket {
        let (rx_size, tx_size) = match profile {
            TrafficProfile::Bulk => (self.config.tcp_rx_heavy, self.config.tcp_tx_heavy),
            TrafficProfile::Interactive => (self.config.tcp_rx_light, self.config.tcp_tx_light),
            _ => (self.config.tcp_rx_light * 2, self.config.tcp_tx_light * 2),
        };

        info!(
            "🚀 TCP Socket Created | Profile: {:?} | Initial RX: {} KB, TX: {} KB",
            profile,
            rx_size / 1024,
            tx_size / 1024
        );

        let rx_buffer = tcp::DynamicSocketBuffer::new(rx_size);
        let tx_buffer = tcp::DynamicSocketBuffer::new(tx_size);
        let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

        self.reconfigure_tcp(&mut socket, profile);

        socket.set_keep_alive(Some(TCP_SOCKET_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_SOCKET_ACTIVE_TIMEOUT));
        socket
    }

    fn reconfigure_tcp(&self, socket: &mut tcp::Socket, _profile: TrafficProfile) {
        socket.set_nagle_enabled(false);

        socket.set_ack_delay(None);

        socket.set_congestion_control(CongestionControl::Bbr);
    }

    fn log_stats(
        &self,
        sockets: &SocketSet,
        get_app_pending: &dyn Fn(smoltcp::iface::SocketHandle) -> usize,
    ) {
        for (handle, socket) in sockets.iter() {
            if let smoltcp::socket::Socket::Tcp(tcp_socket) = socket {
                if tcp_socket.is_active() {
                    // 1. Статистика стека (facing the browser)
                    let tcp_rx_len = tcp_socket.recv_queue(); // Данные от браузера к нам
                    let tcp_rx_cap = tcp_socket.recv_capacity();

                    let tcp_tx_len = tcp_socket.send_queue(); // Данные от нас к браузеру
                    let tcp_tx_cap = tcp_socket.send_capacity();

                    // 2. Статистика приложения (теневая очередь из туннеля)
                    // Это данные, которые уже прилетели из Германии/Финляндии,
                    // но еще не влезли в tcp_socket.send_slice()
                    let app_pending_len = get_app_pending(handle);

                    let state = tcp_socket.state();

                    // Выбираем иконку для статуса
                    let status_icon = match state {
                        tcp::State::Established => "✅",
                        tcp::State::CloseWait => "⏳", // Сервер закрылся, мы дочищаем хвосты
                        tcp::State::FinWait1 | tcp::State::FinWait2 => "👋",
                        _ => "ℹ️ ",
                    };

                    // Логируем одной строкой для удобства чтения в Logcat
                    info!(
                        "📊 [TCP {}] {:<12} {} | RX_BR: {:>4}/{} KB | TX_BR: {:>4}/{} KB | APP_WAIT: {:>4} KB",
                        handle,
                        format!("{:?}", state),
                        status_icon,
                        tcp_rx_len / 1024,
                        tcp_rx_cap / 1024, // Пришло от браузера
                        tcp_tx_len / 1024,
                        tcp_tx_cap / 1024,      // Ушло браузеру (из стека)
                        app_pending_len / 1024  // Ждет входа в стек (из туннеля)
                    );

                    if app_pending_len > BUFFERBLOAT_WARN_THRESHOLD {
                        warn!(
                            "⚠️ [TCP {}] Bufferbloat detected! Application queue is > {} KB",
                            handle,
                            BUFFERBLOAT_WARN_THRESHOLD / 1024
                        );
                    }
                }
            }
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

    fn create_icmp(&self, _profile: TrafficProfile) -> icmp::Socket<'static> {
        icmp::Socket::new(
            icmp::PacketBuffer::new(
                vec![icmp::PacketMetadata::EMPTY; ICMP_META_SLOTS],
                vec![0; ICMP_BUFFER_SIZE],
            ),
            icmp::PacketBuffer::new(
                vec![icmp::PacketMetadata::EMPTY; ICMP_META_SLOTS],
                vec![0; ICMP_BUFFER_SIZE],
            ),
        )
    }

    fn create_listening_tcp(&self, addr: Option<IpAddress>, port: u16) -> tcp::Socket {
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
        let mut sockets = SocketSet::new(Vec::with_capacity(MAX_SOCKETS));
        sockets.add(self.create_bound_udp(None, 53));
        for _ in 0..n_icmp {
            sockets.add(self.create_icmp(TrafficProfile::Default));
        }
        sockets
    }
}
