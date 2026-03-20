use netrunner_core::protocol::codec::socks::TargetAddress;
use netrunner_logger::{debug, error, info, warn};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::{IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant as StdInstant},
};

use crate::connections::{
    dns::DnsHandler, ip_store::FakeIpStore, tcp_connection::TcpConnection,
    udp_connection::UdpConnection,
};
pub struct ConnectionManager {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp_sessions: HashMap<SocketHandle, TcpConnection>,
    active_udp_sessions: HashMap<SocketHandle, UdpConnection>,
    dns_handler: DnsHandler,
    fake_ip_store: FakeIpStore,
    proxy_ip: String,
    failed_until: HashMap<SocketHandle, StdInstant>,
    sockets_to_remove: Vec<SocketHandle>,
}

impl ConnectionManager {
    pub fn new(ip: String, dns_handler: DnsHandler) -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp_sessions: HashMap::new(),
            active_udp_sessions: HashMap::new(),
            proxy_ip: ip,
            fake_ip_store: FakeIpStore::new(),
            failed_until: HashMap::new(),
            dns_handler,
            sockets_to_remove: Vec::new(),
        }
    }
    pub fn start_listening(&mut self, socket_set: &mut SocketSet) {
        for (_, socket) in socket_set.iter_mut() {
            if let Some(tcp) = tcp::Socket::downcast_mut(socket) {
                if !tcp.is_open() {
                    let endpoint = IpListenEndpoint {
                        addr: None,
                        port: 443,
                    };
                    let _ = tcp.listen(endpoint);
                }
            } else if let Some(udp) = udp::Socket::downcast_mut(socket) {
                if !udp.is_open() {
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
        let local_endpoint = match socket.local_endpoint() {
            Some(ep) => ep,
            None => {
                warn!(handle=?socket, "Attempted to resolve target for an unconnected socket");

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
        use tcp::State;

        // 1. Очистка закрытых сокетов
        if socket.state() == State::Closed {
            // Если сокет закрыт, удаляем его сессию и помечаем на удаление из сета
            if self.active_tcp_sessions.contains_key(&handle) {
                debug!(%handle, "TCP session closed, removing from active sessions");
                self.active_tcp_sessions.remove(&handle);
            }

            // Добавляем в очередь на удаление из SocketSet (чтобы освободить память)
            if !self.sockets_to_remove.contains(&handle) {
                self.sockets_to_remove.push(handle);
            }
            return;
        }

        // 2. Инициализация сессии при установке соединения
        if socket.state() == State::Established && !self.active_tcp_sessions.contains_key(&handle) {
            let target = self.resolve_target(socket);

            if let TargetAddress::Domain(d, _) = &target {
                if d == "disconnected" {
                    socket.abort();
                    return;
                }
            }

            info!(%handle, "New TCP session established for target: {:?}", target);
            let conn = TcpConnection::new(handle, self.proxy_ip.clone(), target);
            self.active_tcp_sessions.insert(handle, conn);
        }

        // 3. Тик активной сессии (проброс данных в прокси)
        if let Some(conn) = self.active_tcp_sessions.get_mut(&handle) {
            if !conn.tick(socket) {
                debug!(%handle, "Connection tick failed, aborting.");
                socket.abort();
                // Сессия удалится на следующем проходе, когда стейт станет Closed
            }
        }

        if socket.state() == State::CloseWait {
            socket.close();
        }
    }
    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        self.last_activity.insert(handle, StdInstant::now());

        UdpConnection::process_incoming(socket, &mut self.fake_ip_store, &self.dns_handler);
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
        const BUF_SIZE: usize = 512 * 1024;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUF_SIZE]),
            tcp::SocketBuffer::new(vec![0; BUF_SIZE]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
        socket.set_hop_limit(Some(64));
        socket
    }

    fn create_dynamic_tcp_socket<'a>(port: u16) -> tcp::Socket<'a> {
        let buf_size = match port {
            443 | 80 => 256 * 1024,     // 256 KB для веба
            22 | 53 | 123 => 16 * 1024, // 16 KB для мелких протоколов (SSH, DNS over TCP, NTP)
            _ => 64 * 1024,             // Дефолт
        };

        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; buf_size]),
            tcp::SocketBuffer::new(vec![0; buf_size]),
        );

        socket.set_nagle_enabled(false); // Для отзывчивости (особенно в играх типа Silent Hill, если через VPN)
        socket.set_ack_delay(None);
        socket
    }

    pub fn try_create_socket_from_packet(&mut self, packet: &[u8], socket_set: &mut SocketSet) {
        let Ok(ip_packet) = Ipv4Packet::new_checked(packet) else {
            return;
        };
        if ip_packet.next_header() != IpProtocol::Tcp {
            return;
        };
        let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) else {
            return;
        };

        // Ищем только SYN (начало соединения)
        if tcp_packet.syn() && !tcp_packet.ack() {
            let dst_port = tcp_packet.dst_port();
            let dst_addr = ip_packet.dst_addr();

            // Проверяем, не создали ли мы уже такой сокет на предыдущем шаге
            if !self.has_active_session(socket_set, dst_addr.into(), dst_port) {
                debug!(target: "netrunner", "Dynamic TCP: Creating socket for {}:{}", dst_addr, dst_port);

                let mut socket = Self::create_dynamic_tcp_socket(dst_port);
                let endpoint = IpListenEndpoint {
                    addr: Some(dst_addr.into()),
                    port: dst_port,
                };

                if let Ok(_) = socket.listen(endpoint) {
                    socket_set.add(socket);
                }
            }
        }
    }

    fn create_udp_socket<'a>() -> udp::Socket<'a> {
        const BUF_SIZE: usize = 1024 * 64;
        const PACKET_COUNT: usize = 128;

        udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; PACKET_COUNT],
                vec![0; BUF_SIZE],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; PACKET_COUNT],
                vec![0; BUF_SIZE],
            ),
        )
    }

    fn create_icmp_socket<'a>() -> icmp::Socket<'a> {
        let icmp_rx_buffer =
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 2048]);
        let icmp_tx_buffer =
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 2048]);
        icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer)
    }

    fn has_active_session(
        &self,
        socket_set: &SocketSet,
        dst_addr: smoltcp::wire::IpAddress,
        dst_port: u16,
    ) -> bool {
        for (_, socket) in socket_set.iter() {
            if let Some(tcp) = tcp::Socket::downcast(socket) {
                if let Some(endpoint) = tcp.local_endpoint() {
                    if endpoint.addr == dst_addr && endpoint.port == dst_port {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn cleanup(&mut self, socket_set: &mut SocketSet) {
        for handle in self.sockets_to_remove.drain(..) {
            debug!(%handle, "Memory free: removing socket from set");
            socket_set.remove(handle);
            self.last_activity.remove(&handle);
            self.failed_until.remove(&handle);
        }
    }
    pub fn setup_sockets(n_udp: usize, n_icmp: usize) -> SocketSet<'static> {
        let mut sockets = SocketSet::new(Vec::with_capacity(n_udp + n_icmp + 10));

        for _ in 0..n_udp {
            sockets.add(Self::create_udp_socket());
        }

        for _ in 0..n_icmp {
            sockets.add(Self::create_icmp_socket());
        }

        sockets
    }
    pub fn log_status(&self, socket_set: &SocketSet) {
        let mut established = 0;
        let mut total_tcp = 0;

        for (_, socket) in socket_set.iter() {
            if let Some(tcp) = tcp::Socket::downcast(socket) {
                total_tcp += 1;
                if tcp.state() == tcp::State::Established {
                    established += 1;
                }
            }
        }

        debug!(
            "TCP Stats: Total_Sockets={}, Established={}, Active_Sessions={}",
            total_tcp,
            established,
            self.active_tcp_sessions.len()
        );
    }
}
