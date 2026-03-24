use bytes::Bytes;
use netrunner_core::protocol::codec::socks::TargetAddress;
use netrunner_logger::{debug, error, info, trace, warn};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::{IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
};
use std::{collections::HashMap, time::Duration, time::Instant as StdInstant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::net::{
    connection::{TcpConnection, UdpConnection},
    dns::DnsHandler,
    ip_store::FakeIpStore,
};

// ============================================================================
// 1. УПРАВЛЕНИЕ СОСТОЯНИЕМ СЕССИЙ (SessionTracker)
// ============================================================================

struct SessionTracker {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp: HashMap<SocketHandle, TcpConnection>,
    active_udp: HashMap<SocketHandle, UdpConnection>,
    failed_until: HashMap<SocketHandle, StdInstant>,
    to_remove: Vec<SocketHandle>,
}

impl SessionTracker {
    fn new() -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp: HashMap::new(),
            active_udp: HashMap::new(),
            failed_until: HashMap::new(),
            to_remove: Vec::new(),
        }
    }

    fn queue_removal(&mut self, handle: SocketHandle) {
        if !self.to_remove.contains(&handle) {
            self.to_remove.push(handle);
        }
    }

    fn cleanup(&mut self, socket_set: &mut SocketSet) {
        for handle in self.to_remove.drain(..) {
            debug!(%handle, "Cleanup: Removing socket from SocketSet and internal maps");
            socket_set.remove(handle);
            self.last_activity.remove(&handle);
            self.failed_until.remove(&handle);
            self.active_tcp.remove(&handle);
            self.active_udp.remove(&handle);
        }
    }

    fn has_tcp(
        &self,
        dst_addr: smoltcp::wire::IpAddress,
        dst_port: u16,
        socket_set: &SocketSet,
    ) -> bool {
        socket_set.iter().any(|(_, s)| {
            if let Some(tcp) = tcp::Socket::downcast(s) {
                if let Some(ep) = tcp.local_endpoint() {
                    return ep.addr == dst_addr && ep.port == dst_port;
                }
            }
            false
        })
    }

    fn has_udp(
        &self,
        dst_addr: smoltcp::wire::IpAddress,
        dst_port: u16,
        socket_set: &SocketSet,
    ) -> bool {
        socket_set.iter().any(|(_, s)| {
            if let Some(udp) = udp::Socket::downcast(s) {
                let ep = udp.endpoint();
                return ep.addr == Some(dst_addr) && ep.port == dst_port;
            }
            false
        })
    }
}

// ============================================================================
// 2. РАЗРЕШЕНИЕ АДРЕСОВ И DNS (TargetResolver)
// ============================================================================

struct TargetResolver {
    dns_handler: DnsHandler,
    fake_ip_store: FakeIpStore,
}

impl TargetResolver {
    fn new(dns_handler: DnsHandler) -> Self {
        Self {
            dns_handler,
            fake_ip_store: FakeIpStore::new(),
        }
    }

    fn resolve_tcp(&self, socket: &tcp::Socket) -> TargetAddress {
        let ep = match socket.local_endpoint() {
            Some(ep) => ep,
            None => {
                warn!(handle=?socket, "Target resolution failed: no local endpoint");
                return TargetAddress::Domain("disconnected".to_string(), 0);
            }
        };

        match ep.addr {
            smoltcp::wire::IpAddress::Ipv4(ip) => {
                let std_ip = std::net::Ipv4Addr::from(ip);
                if let Some(domain) = self.fake_ip_store.lookup_by_ip(&std_ip) {
                    TargetAddress::Domain(domain, ep.port)
                } else {
                    TargetAddress::Ipv4(std_ip, ep.port)
                }
            }
            smoltcp::wire::IpAddress::Ipv6(ip) => {
                TargetAddress::Ipv6(std::net::Ipv6Addr::from(ip), ep.port)
            }
        }
    }

    fn process_dns_query(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.dns_handler.handle_query(data, &mut self.fake_ip_store)
    }
}

// ============================================================================
// 3. ФАБРИКА СОКЕТОВ (SocketFactory)
// ============================================================================

struct SocketFactory;

impl SocketFactory {
    fn create_tcp<'a>(port: u16) -> tcp::Socket<'a> {
        let buf_size = match port {
            443 | 80 => 1024 * 1024 * 2,
            22 => 32 * 1024,
            53 => 16 * 1024,
            _ => 128 * 1024,
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; buf_size]),
            tcp::SocketBuffer::new(vec![0; buf_size]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        socket
    }

    fn create_udp<'a>(port: u16) -> udp::Socket<'a> {
        let (buf_size, packet_count) = match port {
            443 => (512 * 1024, 390),
            53 => (64 * 1024, 32),
            _ => (128 * 1024, 100),
        };
        udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; packet_count],
                vec![0; buf_size],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; packet_count],
                vec![0; buf_size],
            ),
        )
    }

    fn create_icmp<'a>() -> icmp::Socket<'a> {
        icmp::Socket::new(
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 2048]),
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 2048]),
        )
    }
}

// ============================================================================
// 4. ГЛАВНЫЙ КООРДИНАТОР (ConnectionManager)
// ============================================================================

pub struct ConnectionManager {
    tracker: SessionTracker,
    resolver: TargetResolver,
}

impl ConnectionManager {
    pub fn new(dns_handler: DnsHandler) -> Self {
        Self {
            tracker: SessionTracker::new(),
            resolver: TargetResolver::new(dns_handler),
        }
    }

    pub fn setup_sockets(n_icmp: usize) -> SocketSet<'static> {
        let mut sockets = SocketSet::new(Vec::with_capacity(48));
        for _ in 0..n_icmp {
            sockets.add(SocketFactory::create_icmp());
        }
        sockets
    }

    pub fn start_listening(&mut self, socket_set: &mut SocketSet) {
        for (_, socket) in socket_set.iter_mut() {
            if let Some(tcp) = tcp::Socket::downcast_mut(socket) {
                if !tcp.is_open() {
                    let _ = tcp.listen(IpListenEndpoint {
                        addr: None,
                        port: 443,
                    });
                }
            } else if let Some(udp) = udp::Socket::downcast_mut(socket) {
                if !udp.is_open() {
                    let _ = udp.bind(IpListenEndpoint {
                        addr: None,
                        port: 53,
                    });
                }
            }
        }
    }

    pub fn try_create_socket_from_packet(&mut self, packet: &[u8], socket_set: &mut SocketSet) {
        let Ok(ip_packet) = Ipv4Packet::new_checked(packet) else {
            trace!("try_create_socket: Failed to parse IPv4 packet, ignoring");
            return;
        };

        let dst_addr = ip_packet.dst_addr();

        match ip_packet.next_header() {
            IpProtocol::Tcp => {
                if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                    if tcp_packet.syn() && !tcp_packet.ack() {
                        let dst_port = tcp_packet.dst_port();
                        trace!(%dst_addr, dst_port, "Received TCP SYN");

                        if !self.tracker.has_tcp(dst_addr.into(), dst_port, socket_set) {
                            debug!(%dst_addr, dst_port, "No active TCP socket found, allocating new one");

                            let mut socket = SocketFactory::create_tcp(dst_port);
                            let endpoint = IpListenEndpoint {
                                addr: Some(dst_addr.into()),
                                port: dst_port,
                            };

                            match socket.listen(endpoint) {
                                Ok(_) => {
                                    debug!(%dst_addr, dst_port, "TCP socket successfully listening");
                                    socket_set.add(socket);
                                }
                                Err(e) => {
                                    error!(%dst_addr, dst_port, "Failed to listen on TCP socket: {:?}", e);
                                }
                            }
                        } else {
                            trace!(%dst_addr, dst_port, "TCP socket already exists, ignoring SYN");
                        }
                    }
                } else {
                    trace!("try_create_socket: Failed to parse TCP payload");
                }
            }
            IpProtocol::Udp => {
                if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                    let dst_port = udp_packet.dst_port();

                    // Блокируем порты локального вещания и NetBIOS
                    if dst_port == 0 || dst_port == 137 || dst_port == 138 {
                        trace!(%dst_addr, dst_port, "Ignored blocked UDP port");
                        return;
                    }

                    if !self.tracker.has_udp(dst_addr.into(), dst_port, socket_set) {
                        debug!(%dst_addr, dst_port, "No active UDP socket found, allocating new one");

                        let mut socket = SocketFactory::create_udp(dst_port);
                        let endpoint = IpListenEndpoint {
                            addr: Some(dst_addr.into()),
                            port: dst_port,
                        };

                        match socket.bind(endpoint) {
                            Ok(_) => {
                                debug!(%dst_addr, dst_port, "UDP socket successfully bound");
                                socket_set.add(socket);
                            }
                            Err(e) => {
                                error!(%dst_addr, dst_port, "Failed to bind UDP socket: {:?}", e);
                            }
                        }
                    } else {
                        trace!(%dst_addr, dst_port, "UDP socket already exists, ignoring creation");
                    }
                } else {
                    trace!("try_create_socket: Failed to parse UDP payload");
                }
            }
            protocol => {
                trace!(
                    "try_create_socket: Ignored unsupported IP protocol: {:?}",
                    protocol
                );
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
        if socket.state() == tcp::State::Closed {
            self.tracker.active_tcp.remove(&handle);
            self.tracker.queue_removal(handle);
            return;
        }

        if socket.state() == tcp::State::Established
            && !self.tracker.active_tcp.contains_key(&handle)
        {
            let target = self.resolver.resolve_tcp(socket);
            if let TargetAddress::Domain(ref d, _) = target {
                if d == "disconnected" {
                    socket.abort();
                    return;
                }
            }

            info!(%handle, target = %target, "New TCP session established");

            let (conn, mut rx_from_smol, tx_to_smol, handshake_tx) = TcpConnection::new(handle);
            self.tracker.active_tcp.insert(handle, conn);

            // Конвертируем TargetAddress в строку, понятную для tokio::net
            let target_str = match target {
                TargetAddress::Domain(d, p) => format!("{}:{}", d, p),
                TargetAddress::Ipv4(ip, p) => format!("{}:{}", ip, p),
                TargetAddress::Ipv6(ip, p) => format!("{}:{}", ip, p),
            };

            tokio::spawn(async move {
                let mut upstream = match TcpStream::connect(&target_str).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to connect to upstream TCP {}: {}", target_str, e);
                        return;
                    }
                };

                // Сообщаем соединению smoltcp, что мы готовы (рукопожатие выполнено)
                let _ = handshake_tx.send(());

                let (mut r, mut w) = upstream.into_split();

                // Читаем из tun (smoltcp) и пишем во внешнюю сеть
                let to_upstream = async {
                    while let Some(data) = rx_from_smol.recv().await {
                        if w.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                };

                // Читаем из внешней сети и пишем в tun (smoltcp)
                let from_upstream = async {
                    let mut buf = vec![0u8; 8192]; // Читаем чанками
                    while let Ok(n) = r.read(&mut buf).await {
                        if n == 0 {
                            break;
                        } // EOF
                        if tx_to_smol
                            .send(Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };

                tokio::select! { _ = to_upstream => {}, _ = from_upstream => {} }
            });
        }

        if let Some(conn) = self.tracker.active_tcp.get_mut(&handle) {
            if !conn.tick(socket) {
                socket.abort();
            }
        }

        if socket.state() == tcp::State::CloseWait {
            socket.close();
        }
    }

    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        self.tracker.last_activity.insert(handle, StdInstant::now());

        if socket.endpoint().port == 53 {
            while socket.can_recv() {
                if let Ok((data, meta)) = socket.recv() {
                    if let Some(response) = self.resolver.process_dns_query(data) {
                        let _ = socket.send_slice(&response, meta);
                    }
                } else {
                    break;
                }
            }
            return;
        }

        if socket.is_open() && !self.tracker.active_udp.contains_key(&handle) {
            let ep = socket.endpoint();
            let target = match ep.addr {
                Some(smoltcp::wire::IpAddress::Ipv4(ip)) => {
                    TargetAddress::Ipv4(std::net::Ipv4Addr::from(ip), ep.port)
                }
                Some(smoltcp::wire::IpAddress::Ipv6(ip)) => {
                    TargetAddress::Ipv6(std::net::Ipv6Addr::from(ip), ep.port)
                }
                None => return,
            };

            let (conn, mut rx_from_smol, tx_to_smol) = UdpConnection::new(handle);
            self.tracker.active_udp.insert(handle, conn);

            // Конвертируем для tokio::net::UdpSocket
            let target_str = match target {
                TargetAddress::Domain(d, p) => format!("{}:{}", d, p),
                TargetAddress::Ipv4(ip, p) => format!("{}:{}", ip, p),
                TargetAddress::Ipv6(ip, p) => format!("{}:{}", ip, p),
            };

            tokio::spawn(async move {
                // Создаем локальный UDP сокет со случайным портом
                let upstream = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to bind local UDP socket: {}", e);
                        return;
                    }
                };

                // "Подключаем" UDP сокет к цели (включает фильтр пакетов и позволяет использовать обычные send/recv)
                if let Err(e) = upstream.connect(&target_str).await {
                    error!("Failed to connect UDP to {}: {}", target_str, e);
                    return;
                }

                let upstream = std::sync::Arc::new(upstream);
                let upstream_rx = upstream.clone();
                let upstream_tx = upstream;

                // Из smoltcp наружу
                let to_upstream = async {
                    while let Some(data) = rx_from_smol.recv().await {
                        if upstream_tx.send(&data).await.is_err() {
                            break;
                        }
                    }
                };

                // Извне в smoltcp
                let from_upstream = async {
                    let mut buf = vec![0u8; 65536]; // Максимальный размер UDP датаграммы
                    while let Ok(n) = upstream_rx.recv(&mut buf).await {
                        if tx_to_smol
                            .send(Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                };

                tokio::select! { _ = to_upstream => {}, _ = from_upstream => {} }
            });
        }

        if let Some(conn) = self.tracker.active_udp.get_mut(&handle) {
            if !conn.tick(socket) {
                self.tracker.queue_removal(handle);
                self.tracker.active_udp.remove(&handle);
            }
        }
    }

    fn handle_icmp(&mut self, _handle: SocketHandle, socket: &mut icmp::Socket) {
        if socket.can_recv() {
            let _ = socket.recv();
        }
    }

    pub fn cleanup(&mut self, socket_set: &mut SocketSet) {
        self.tracker.cleanup(socket_set);
    }

    pub fn log_status(&self, socket_set: &SocketSet) {
        let mut est = 0;
        let mut total = 0;
        for (_, socket) in socket_set.iter() {
            if let Some(tcp) = tcp::Socket::downcast(socket) {
                total += 1;
                if tcp.state() == tcp::State::Established {
                    est += 1;
                }
            }
        }
        debug!(
            "TCP Stats: Total={}, Established={}, Active={}",
            total,
            est,
            self.tracker.active_tcp.len()
        );
    }
}
