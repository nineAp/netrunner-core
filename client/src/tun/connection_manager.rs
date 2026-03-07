use netrunner_common::protocol::codec::socks::TargetAddress;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::{IpAddress, IpListenEndpoint},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant as StdInstant},
};
use tracing::{debug, info, warn};

use crate::{
    connections::{
        ip_store::FakeIpStore, tcp_connection::TcpConnection, udp_connection::UdpConnection,
    },
    tun::engine::START_TIME,
};
pub struct ConnectionManager {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp_sessions: HashMap<SocketHandle, TcpConnection>,
    //active_udp_sessions: HashMap<SocketHandle, UdpSession>,
    fake_ip_store: FakeIpStore,
    proxy_ip: String,
}

impl ConnectionManager {
    pub fn new(ip: String) -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp_sessions: HashMap::new(),
            proxy_ip: ip,
            fake_ip_store: FakeIpStore::new(),
        }
    }
    pub fn start_listening(&mut self, socket_set: &mut SocketSet) {
        for (_, socket) in socket_set.iter_mut() {
            // Обработка TCP (как было)
            if let Some(tcp) = tcp::Socket::downcast_mut(socket) {
                if !tcp.is_open() {
                    let endpoint = IpListenEndpoint {
                        addr: None,
                        port: 443,
                    };
                    let _ = tcp.listen(endpoint);
                }
            }
            // Добавляем обработку UDP
            else if let Some(udp) = udp::Socket::downcast_mut(socket) {
                if !udp.is_open() {
                    // Биндим на 53 порт, чтобы ловить DNS-запросы
                    let endpoint = IpListenEndpoint {
                        addr: None,
                        port: 53,
                    };
                    match udp.bind(endpoint) {
                        Ok(_) => debug!("UDP socket bound to port 53"),
                        Err(e) => warn!(error=?e, "Failed to bind UDP socket"),
                    }
                }
            }
        }
    }

    fn resolve_target(&self, socket: &tcp::Socket) -> TargetAddress {
        // Безопасно получаем эндпоинт
        let local_endpoint = match socket.local_endpoint() {
            Some(ep) => ep,
            None => {
                warn!(handle=?socket, "Attempted to resolve target for an unconnected socket");
                // Возвращаем дефолт, чтобы не падать
                return TargetAddress::Domain("disconnected".to_string(), 0);
            }
        };
        debug!(remote_addr = %local_endpoint.addr, remote_port = %local_endpoint.port, "SMOLTCP RAW REMOTE ENDPOINT");

        let port = local_endpoint.port;
        let ip = local_endpoint.addr;

        match ip {
            smoltcp::wire::IpAddress::Ipv4(ipv4_addr) => {
                let std_ip = std::net::Ipv4Addr::from(ipv4_addr);

                debug!(ip=%std_ip, "Trying to resolve IP in FakeIpStore");
                if let Some(domain) = self.fake_ip_store.lookup_by_ip(&std_ip) {
                    debug!(target=%domain, port=%port, "Resolved fake IP to domain");
                    return TargetAddress::Domain(domain, port);
                } else {
                    warn!(ip=%std_ip, "IP not found in FakeIpStore! SOCKS request will fail.");
                }

                debug!(ip=%std_ip, port=%port, "Using raw IP target");
                TargetAddress::Ipv4(std_ip, port)
            }
            smoltcp::wire::IpAddress::Ipv6(ipv6_addr) => {
                let std_ip = std::net::Ipv6Addr::from(ipv6_addr);
                debug!(ip=%std_ip, port=%port, "Using IPv6 target");
                TargetAddress::Ipv6(std_ip, port)
            }
        }
    }
    pub fn process_sockets(&mut self, socket_set: &mut SocketSet) {
        for (handle, socket) in socket_set.iter_mut() {
            if let Some(tcp) = tcp::Socket::downcast_mut(socket) {
                self.handle_tcp(handle, tcp);
            } else if let Some(udp) = udp::Socket::downcast_mut(socket) {
                self.handle_udp(handle, udp);
            } else if let Some(icmp) = icmp::Socket::downcast_mut(socket) {
                self.handle_icmp(handle, icmp);
            }
        }
    }

    fn handle_tcp(&mut self, handle: SocketHandle, socket: &mut tcp::Socket) {
        if socket.state() == tcp::State::Established {
            let target = self.resolve_target(socket);
            debug!(
                handle=%handle,
                local=?socket.local_endpoint(),
                remote=?socket.remote_endpoint(),
                "Socket details"
            );

            let mut conn = TcpConnection::new(handle, self.proxy_ip.clone(), target);

            conn.tick(socket);

            if conn.is_active() {
                self.active_tcp_sessions.insert(handle, conn);
            } else {
                socket.abort();
            }
        }

        if let Some(conn) = self.active_tcp_sessions.get_mut(&handle) {
            if !conn.tick(socket) {
                self.active_tcp_sessions.remove(&handle);
            }
        }
    }

    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        self.last_activity.insert(handle, StdInstant::now());

        UdpConnection::process_incoming(socket, &mut self.fake_ip_store);
    }

    fn handle_icmp(&mut self, handle: SocketHandle, socket: &mut icmp::Socket) {
        if socket.can_recv() {
            match socket.recv() {
                Ok((data, endpoint)) => {
                    debug!(handle=%handle, from=?endpoint, data=?data, "ICMP: packet received");
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

    pub fn setup_sockets(n_tcp: usize, n_udp: usize, n_icmp: usize) -> SocketSet<'static> {
        // Создаем хранилище с запасом на все типы сокетов
        let mut sockets = SocketSet::new(Vec::with_capacity(n_tcp + n_udp + n_icmp));

        // 1. Добавляем TCP сокеты
        for _ in 0..n_tcp {
            sockets.add(Self::create_tcp_socket());
        }

        // 2. Добавляем UDP сокеты
        for _ in 0..n_udp {
            sockets.add(Self::create_udp_socket());
        }

        // 3. Добавляем ICMP сокет
        for _ in 0..n_icmp {
            sockets.add(Self::create_icmp_socket());
        }

        sockets
    }
}
