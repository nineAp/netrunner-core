use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::IpListenEndpoint,
};
use std::{
    collections::HashMap,
    time::{Duration, Instant as StdInstant},
};
use tracing::{debug, info};

use crate::{connections::tcp_connection::TcpConnection, tun::engine::START_TIME};
pub struct ConnectionManager {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp_sessions: HashMap<SocketHandle, TcpConnection>,
    //active_udp_sessions: HashMap<SocketHandle, UdpSession>,
    proxy_ip: String,
}

impl ConnectionManager {
    pub fn new(ip: String) -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp_sessions: HashMap::new(),
            proxy_ip: ip,
        }
    }

    /// Основной метод, который вызывается в цикле Engine
    pub fn process_sockets(&mut self, socket_set: &mut SocketSet) {
        for (handle, socket) in socket_set.iter_mut() {
            // 1. Пытаемся даункастить сокет до TCP
            if let Some(tcp) = tcp::Socket::downcast_mut(socket) {
                self.handle_tcp(handle, tcp);
                continue;
            }

            // 2. До UDP
            if let Some(udp) = udp::Socket::downcast_mut(socket) {
                self.handle_udp(handle, udp);
                continue;
            }

            // 3. До ICMP
            if let Some(icmp) = icmp::Socket::downcast_mut(socket) {
                self.handle_icmp(handle, icmp);
                continue;
            }
        }
    }
    fn handle_tcp(&mut self, handle: SocketHandle, socket: &mut tcp::Socket) {
        if socket.state() == tcp::State::Established {
            let proxy_ip = self.proxy_ip.clone(); // Берем из конфига менеджера

            let conn = self.active_tcp_sessions.entry(handle).or_insert_with(|| {
                // 1. Получаем endpoint и безопасно распаковываем его
                let endpoint = socket
                    .remote_endpoint()
                    .expect("TCP socket in Established state must have a remote endpoint");

                // 2. Конвертируем smoltcp::wire::IpAddress в std::net::IpAddr
                let ip: std::net::IpAddr = match endpoint.addr {
                    smoltcp::wire::IpAddress::Ipv4(v4) => std::net::IpAddr::V4(v4.into()),
                    smoltcp::wire::IpAddress::Ipv6(v6) => std::net::IpAddr::V6(v6.into()),
                };

                // 3. Собираем финальный SocketAddr
                let target_addr = std::net::SocketAddr::new(ip, endpoint.port);

                info!(handle=%handle, target=%target_addr, "Creating new TcpConnection bridge");
                TcpConnection::new(handle, proxy_ip, target_addr)
            });

            conn.poll_and_process(socket);
        }
        if socket.state() == tcp::State::Closed {
            self.active_tcp_sessions.remove(&handle);
        }
    }

    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        if socket.can_recv() {
            match socket.recv() {
                Ok((data, endpoint)) => {
                    info!(handle=%handle, from=?endpoint, len=data.len(), "UDP: packet received");
                    // МОК: Обработка UDP датаграммы
                }
                Err(_) => {}
            }
        }
    }

    fn handle_icmp(&mut self, handle: SocketHandle, socket: &mut icmp::Socket) {
        if socket.can_recv() {
            match socket.recv() {
                Ok((data, endpoint)) => {
                    debug!(handle=%handle, from=?endpoint, "ICMP: packet received");
                    // МОК: Ответ на пинг или обработка ошибок
                }
                Err(_) => {}
            }
        }
    }

    fn create_tcp_socket<'a>() -> tcp::Socket<'a> {
        const BUF_SIZE: usize = 65535;
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUF_SIZE]),
            tcp::SocketBuffer::new(vec![0; BUF_SIZE]),
        )
    }

    fn create_udp_socket<'a>() -> udp::Socket<'a> {
        const BUF_SIZE: usize = 65535;
        udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUF_SIZE]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUF_SIZE]),
        )
    }

    fn create_icmp_socket<'a>() -> icmp::Socket<'a> {
        let icmp_rx_buffer =
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 1024]);
        let icmp_tx_buffer =
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 1024]);
        icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer)
    }

    pub fn refill_sockets(&mut self, socket_set: &mut SocketSet) {
        self.prune_sockets(socket_set);
        const TARGET_FREE_TCP: usize = 16;
        const TARGET_FREE_UDP: usize = 8;

        for &port in &[80, 443, 8080] {
            let current_port_sockets = socket_set
                .iter()
                .filter(|(_, s)| {
                    if let Some(tcp) = tcp::Socket::downcast(s) {
                        // Если эндпоинт есть - сверяем порт
                        if let Some(endpoint) = tcp.local_endpoint() {
                            return endpoint.port == port;
                        }

                        // КЛЮЧЕВОЙ МОМЕНТ:
                        // Если эндпоинта НЕТ, но сокет НЕ в состоянии CLOSED,
                        // или он только что был создан для прослушивания.
                        // В smoltcp после listen() сокет переходит в LISTEN,
                        // но local_endpoint может появиться чуть позже.
                        tcp.state() == tcp::State::Listen
                    } else {
                        false
                    }
                })
                .count();

            if current_port_sockets < 5 {
                let mut s = Self::create_tcp_socket();
                let endpoint = IpListenEndpoint { addr: None, port };

                // Попробуй сначала listen, а потом добавлять
                if s.listen(endpoint).is_ok() {
                    socket_set.add(s);
                    info!(
                        "--- REAL ADD --- Port: {}, Sockets for this port: {}",
                        port,
                        current_port_sockets + 1
                    );
                }
            }
        }

        let udp_active = socket_set
            .iter()
            .filter(|(_, s)| udp::Socket::downcast(s).is_some())
            .count();

        let has_icmp = socket_set
            .iter()
            .any(|(_, s)| icmp::Socket::downcast(s).is_some());

        if udp_active < TARGET_FREE_UDP {
            let diff = TARGET_FREE_UDP - udp_active;
            debug!("Refilling UDP pool: adding {} sockets", diff);
            for _ in 0..diff {
                let s = Self::create_udp_socket();
                socket_set.add(s);
            }
        }

        if !has_icmp {
            debug!("Adding ICMP socket for echo requests");
            let s = Self::create_icmp_socket();
            socket_set.add(s);
        }
    }

    fn prune_sockets(&mut self, socket_set: &mut SocketSet) {
        let now = StdInstant::now();
        let udp_timeout = Duration::from_secs(60); // 1 минута для UDP
        let mut to_remove = Vec::new();

        for (handle, socket) in socket_set.iter() {
            if let Some(tcp) = tcp::Socket::downcast(socket) {
                if tcp.state() == tcp::State::Closed {
                    to_remove.push(handle);
                    continue;
                }
            }

            if let Some(udp) = udp::Socket::downcast(socket) {
                if udp.endpoint().port == 0 {
                    continue;
                }
                let last = self.last_activity.get(&handle).unwrap_or(&START_TIME);
                if now.duration_since(*last) > udp_timeout {
                    debug!(handle=%handle, "UDP socket timeout reached");
                    to_remove.push(handle);
                }
            }

            if let Some(_icmp) = icmp::Socket::downcast(socket) {
                continue;
            }
        }

        for handle in to_remove {
            socket_set.remove(handle);
            self.last_activity.remove(&handle);
        }
    }
}
