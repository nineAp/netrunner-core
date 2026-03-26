use bytes::Bytes;
use netrunner_core::{
    net::network::NetworkConfig,
    rawcast::{LocalProtocol, RawCastEvent, RawCastFrame},
};
use netrunner_logger::{debug, error, info, trace};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::{IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
};
use std::{collections::HashMap, time::Instant as StdInstant};
use tokio::sync::mpsc;

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
    inbound_tx: HashMap<u64, mpsc::Sender<Bytes>>,
    failed_until: HashMap<SocketHandle, StdInstant>,
    to_remove: Vec<SocketHandle>,
    next_socket_id: u64,
    handle_to_id: HashMap<SocketHandle, u64>,
}

impl SessionTracker {
    fn new() -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp: HashMap::new(),
            active_udp: HashMap::new(),
            inbound_tx: HashMap::new(),
            failed_until: HashMap::new(),
            to_remove: Vec::new(),
            next_socket_id: 1,
            handle_to_id: HashMap::new(),
        }
    }

    fn generate_socket_id(&mut self) -> u64 {
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.wrapping_add(1);
        id
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

            // ВОТ ТУТ ГЛАВНОЕ ИСПРАВЛЕНИЕ:
            // Достаем НАШ socket_id, который мы выдали этому handle при старте сессии
            if let Some(socket_id) = self.handle_to_id.remove(&handle) {
                self.inbound_tx.remove(&socket_id);
            }
        }
    }

    fn has_connection_from(
        &self,
        src_addr: smoltcp::wire::IpAddress,
        src_port: u16,
        socket_set: &SocketSet,
    ) -> bool {
        socket_set.iter().any(|(_, s)| {
            if let Some(tcp) = tcp::Socket::downcast(s) {
                // Если сокет уже привязался к клиенту, проверяем его исходные данные
                if let Some(remote) = tcp.remote_endpoint() {
                    if remote.addr == src_addr && remote.port == src_port {
                        return true;
                    }
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
        let max_buf = NetworkConfig::global().smoltcp_socket_buf;

        // Для Web-трафика используем максимум из конфига (например, 2 МБ)
        // Для остальных урезаем в 4 раза, чтобы сэкономить RAM на фоновых соединениях
        let buf_size = match port {
            443 | 80 | 8080 => max_buf,
            22 => 32 * 1024,
            53 => 16 * 1024,
            _ => max_buf / 4,
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
        let config = NetworkConfig::global();
        let max_buf = config.udp_buffer_size;
        let payload_size = config.safe_payload_size.max(1); // Защита от деления на 0

        // Вычисляем размер буфера и количество пакетов
        let (buf_size, packet_count) = match port {
            443 => (max_buf, max_buf / payload_size), // QUIC/HTTP3 трафик
            53 => (64 * 1024, (64 * 1024) / payload_size), // DNS
            _ => (max_buf, max_buf / payload_size),
        };

        // Гарантируем, что метаданных хватит хотя бы на 10 пакетов
        let packet_count = packet_count.max(10);

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
    tx_to_tunnel: mpsc::Sender<RawCastFrame>,
}

impl ConnectionManager {
    pub fn new(dns_handler: DnsHandler, tx_to_tunnel: mpsc::Sender<RawCastFrame>) -> Self {
        Self {
            tracker: SessionTracker::new(),
            resolver: TargetResolver::new(dns_handler),
            tx_to_tunnel,
        }
    }

    // ВАЖНО: Метод для получения данных из сети (от VPN) и инъекции их в smoltcp
    // Пытается внедрить пакет. Если канал переполнен — возвращает пакет обратно!
    pub fn try_inject_inbound(&mut self, frame: RawCastFrame) -> Result<(), RawCastFrame> {
        if frame.event != RawCastEvent::Data {
            if frame.event == RawCastEvent::Close {
                self.tracker.inbound_tx.remove(&frame.socket_id);
            }
            return Ok(());
        }

        if let Some(tx) = self.tracker.inbound_tx.get(&frame.socket_id) {
            match tx.try_send(frame.payload.clone()) {
                Ok(_) => Ok(()),
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    Err(frame) // Возвращаем кадр, чтобы Engine затормозил чтение туннеля
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    Ok(()) // Сокет уже закрыт браузером, дропаем пакет
                }
            }
        } else {
            Ok(())
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
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();

                if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                    // 2. Проверяем, что это пакет инициализации соединения (SYN)
                    if tcp_packet.syn() && !tcp_packet.ack() {
                        let src_port = tcp_packet.src_port();
                        let dst_port = tcp_packet.dst_port();

                        trace!(%dst_addr, dst_port, src_port, "Received TCP SYN");

                        // 3. Теперь src_addr доступен в этой области видимости
                        if !self
                            .tracker
                            .has_connection_from(src_addr.into(), src_port, socket_set)
                        {
                            debug!(%dst_addr, dst_port, src_port, "Allocating new TCP socket");

                            let mut socket = SocketFactory::create_tcp(dst_port);
                            let endpoint = IpListenEndpoint {
                                addr: Some(dst_addr.into()),
                                port: dst_port,
                            };

                            match socket.listen(endpoint) {
                                Ok(_) => {
                                    socket_set.add(socket);
                                }
                                Err(e) => {
                                    error!(%dst_addr, dst_port, "Failed to listen: {:?}", e);
                                }
                            }
                        } else {
                            trace!(%dst_addr, dst_port, src_port, "Socket already exists, ignoring SYN");
                        }
                    }
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
            let (dst_ip, dst_port) = match socket.local_endpoint() {
                Some(ep) => match ep.addr {
                    smoltcp::wire::IpAddress::Ipv4(ip) => (std::net::Ipv4Addr::from(ip), ep.port),
                    _ => return,
                },
                None => return,
            };

            info!(%handle, ip = %dst_ip, port = dst_port, "New TCP session intercepted");

            let socket_id = self.tracker.generate_socket_id();
            self.tracker.handle_to_id.insert(handle, socket_id);

            let (conn, mut rx_from_smol, tx_to_smol, handshake_tx) = TcpConnection::new(handle);

            self.tracker.active_tcp.insert(handle, conn);
            self.tracker.inbound_tx.insert(socket_id, tx_to_smol);

            // ИСПРАВЛЕНИЕ ЗДЕСЬ: Переводим IP обратно в домен
            let target_str = if let Some(domain) = self.resolver.fake_ip_store.lookup_by_ip(&dst_ip)
            {
                format!("{}:{}", domain, dst_port)
            } else {
                format!("{}:{}", dst_ip, dst_port)
            };

            let tx_tunnel = self.tx_to_tunnel.clone();

            tokio::spawn(async move {
                // Создаем кадр коннекта
                let mut connect_frame =
                    RawCastFrame::connect(LocalProtocol::Tcp, socket_id, dst_ip, dst_port);
                // Кладем доменное имя в payload, чтобы ClientHandler его прочитал
                connect_frame.payload = bytes::Bytes::from(target_str);

                if tx_tunnel.send(connect_frame).await.is_err() {
                    return;
                }

                let _ = handshake_tx.send(());

                while let Some(data) = rx_from_smol.recv().await {
                    let data_frame = RawCastFrame::data(
                        LocalProtocol::Tcp,
                        socket_id,
                        dst_ip,
                        dst_port,
                        data.to_vec(),
                    );
                    if tx_tunnel.send(data_frame).await.is_err() {
                        break;
                    }
                }

                let close_frame =
                    RawCastFrame::close(LocalProtocol::Tcp, socket_id, dst_ip, dst_port);
                let _ = tx_tunnel.send(close_frame).await;
            });
        }

        if let Some(conn) = self.tracker.active_tcp.get_mut(&handle) {
            if !conn.tick(socket) {
                socket.abort();
            }
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
            let (dst_ip, dst_port) = match socket.endpoint().addr {
                Some(smoltcp::wire::IpAddress::Ipv4(ip)) => {
                    (std::net::Ipv4Addr::from(ip), socket.endpoint().port)
                }
                _ => return,
            };

            // 1. Генерируем уникальный ID
            let socket_id = self.tracker.generate_socket_id();

            // 2. Сохраняем привязку для будущего cleanup
            self.tracker.handle_to_id.insert(handle, socket_id);

            let (conn, mut rx_from_smol, tx_to_smol) = UdpConnection::new(handle);

            self.tracker.active_udp.insert(handle, conn);
            self.tracker.inbound_tx.insert(socket_id, tx_to_smol);
            let target_str = if let Some(domain) = self.resolver.fake_ip_store.lookup_by_ip(&dst_ip)
            {
                format!("{}:{}", domain, dst_port)
            } else {
                format!("{}:{}", dst_ip, dst_port)
            };

            let tx_tunnel = self.tx_to_tunnel.clone();

            tokio::spawn(async move {
                let mut connect_frame =
                    RawCastFrame::connect(LocalProtocol::Udp, socket_id, dst_ip, dst_port);
                connect_frame.payload = bytes::Bytes::from(target_str); // Кладем домен
                let _ = tx_tunnel.send(connect_frame).await;

                while let Some(data) = rx_from_smol.recv().await {
                    let data_frame = RawCastFrame::data(
                        LocalProtocol::Udp,
                        socket_id,
                        dst_ip,
                        dst_port,
                        data.to_vec(),
                    );
                    if tx_tunnel.send(data_frame).await.is_err() {
                        break;
                    }
                }

                let close_frame =
                    RawCastFrame::close(LocalProtocol::Udp, socket_id, dst_ip, dst_port);
                let _ = tx_tunnel.send(close_frame).await;
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
