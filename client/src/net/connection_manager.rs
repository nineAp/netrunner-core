use bytes::Bytes;
use netrunner_core::{
    net::network::NetworkConfig,
    rawcast::{LocalProtocol, RawCastEvent, RawCastFrame},
};
use netrunner_logger::{debug, error, info, trace, warn};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::{
        IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
    },
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

    fn get_id_by_port(&self, port: u16) -> Option<u64> {
        self.active_udp.iter().find_map(|(handle, conn)| {
            if conn.has_client(port) {
                self.handle_to_id.get(handle).copied()
            } else {
                None
            }
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
            _ => max_buf,
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
        let max_buf = config.smoltcp_socket_buf;
        let payload_size = config.safe_payload_size.max(1); // Защита от деления на 0

        // Вычисляем размер буфера и количество пакетов
        let (buf_size, packet_count) = match port {
            443 => (max_buf, max_buf / payload_size), // QUIC/HTTP3 трафик
            53 => (64 * 1024, (64 * 1024) / payload_size), // DNS
            _ => (max_buf, max_buf / payload_size),
        };
        let packet_count = packet_count.max(32);

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
                info!("💀 [Stream {}] Received CLOSE from tunnel", frame.socket_id);
                self.tracker.inbound_tx.remove(&frame.socket_id);
            }
            return Ok(());
        }

        if let Some(tx) = self.tracker.inbound_tx.get(&frame.socket_id) {
            match tx.try_send(frame.payload.clone()) {
                Ok(_) => {
                    // Логируем входящие данные (trace чтобы не спамить, но можно временно info)
                    trace!(
                        "📥 [Stream {}] Inbound data: {} bytes",
                        frame.socket_id,
                        frame.payload.len()
                    );
                    Ok(())
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!("🟡 [Stream {}] Inbound channel FULL", frame.socket_id);
                    Err(frame)
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    error!("🔴 [Stream {}] Inbound channel CLOSED", frame.socket_id);
                    self.tracker.inbound_tx.remove(&frame.socket_id);
                    Ok(())
                }
            }
        } else {
            trace!(
                "👻 [Stream {}] ORPHAN packet from tunnel. ID mismatch?",
                frame.socket_id
            );
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
        if packet.is_empty() {
            return;
        }
        match packet[0] >> 4 {
            4 => self.process_ipv4(packet, socket_set),
            6 => self.process_ipv6(packet, socket_set),
            _ => {}
        }
    }

    fn process_ipv4(&mut self, packet: &[u8], socket_set: &mut SocketSet) {
        let Ok(ip) = Ipv4Packet::new_checked(packet) else {
            return;
        };
        let (src, dst) = (ip.src_addr().into(), ip.dst_addr().into());

        match ip.next_header() {
            IpProtocol::Tcp => {
                if let Ok(p) = TcpPacket::new_checked(ip.payload()) {
                    self.intercept_tcp(src, dst, p.src_port(), p.dst_port(), socket_set);
                }
            }
            IpProtocol::Udp => {
                if let Ok(p) = UdpPacket::new_checked(ip.payload()) {
                    self.intercept_udp(src, dst, p.src_port(), p.dst_port(), socket_set);
                }
            }
            p => trace!("Skip IPv4 protocol {:?}", p),
        }
    }

    fn process_ipv6(&mut self, packet: &[u8], socket_set: &mut SocketSet) {
        let Ok(ip) = Ipv6Packet::new_checked(packet) else {
            return;
        };
        let (src, dst) = (ip.src_addr().into(), ip.dst_addr().into());

        match ip.next_header() {
            IpProtocol::Tcp => {
                if let Ok(p) = TcpPacket::new_checked(ip.payload()) {
                    self.intercept_tcp(src, dst, p.src_port(), p.dst_port(), socket_set);
                }
            }
            IpProtocol::Udp => {
                if let Ok(p) = UdpPacket::new_checked(ip.payload()) {
                    self.intercept_udp(src, dst, p.src_port(), p.dst_port(), socket_set);
                }
            }
            _ => {}
        }
    }

    // В TCP мы просто открываем "слушающий" сокет на конкретный IP:Port,
    // а саму сессию туннеля запустим позже в handle_tcp, когда handshake завершится.
    fn intercept_tcp(
        &mut self,
        src: smoltcp::wire::IpAddress,
        dst: smoltcp::wire::IpAddress,
        src_p: u16,
        dst_p: u16,
        socket_set: &mut SocketSet,
    ) {
        if !self.tracker.has_connection_from(src, src_p, socket_set) {
            info!(
                "🆕 [TCP] New session detected: {}:{} -> {}:{}",
                src, src_p, dst, dst_p
            );
            let mut socket = SocketFactory::create_tcp(dst_p);
            let _ = socket.listen(IpListenEndpoint {
                addr: Some(dst),
                port: dst_p,
            });
            socket_set.add(socket);
        }
    }

    fn intercept_udp(
        &mut self,
        src: smoltcp::wire::IpAddress,
        dst: smoltcp::wire::IpAddress,
        src_p: u16,
        dst_p: u16,
        socket_set: &mut SocketSet,
    ) {
        if dst_p == 0
            || dst_p == 137
            || dst_p == 138
            || self.tracker.get_id_by_port(src_p).is_some()
        {
            return;
        }

        if dst_p == 53 {
            debug!("🎯 [DNS] Intercepting local query: {}:{} -> 53", src, src_p);
            let mut socket = SocketFactory::create_udp(53);
            // Биндимся на адрес назначения, который ожидает клиент (обычно 10.0.0.2 или 8.8.8.8)
            if socket
                .bind(IpListenEndpoint {
                    addr: Some(dst),
                    port: 53,
                })
                .is_ok()
            {
                let handle = socket_set.add(socket);
                let (conn, _rx_smol, tx_smol) = UdpConnection::new(handle, src, src_p);

                // Регистрируем, но НЕ спавним задачу туннеля!
                let socket_id = self.tracker.generate_socket_id();
                self.tracker.handle_to_id.insert(handle, socket_id);
                self.tracker.active_udp.insert(handle, conn);
                self.tracker.inbound_tx.insert(socket_id, tx_smol);
            }
            return;
        }

        let socket_id = self.tracker.generate_socket_id();

        // ВОТ ТУТ МЫ ИЗВЛЕКАЕМ IP И ДЕЛАЕМ LOOKUP С ЛОГИРОВАНИЕМ
        let (dst_ip, target) = match dst {
            smoltcp::wire::IpAddress::Ipv4(ip) => {
                let std_ip = std::net::Ipv4Addr::from(ip);
                if let Some(domain) = self.resolver.fake_ip_store.lookup_by_ip(&std_ip) {
                    info!(
                        "🔍 [UDP {}] Reverse lookup MATCH: {} -> {}",
                        socket_id, std_ip, domain
                    );
                    (std_ip, format!("{}:{}", domain, dst_p))
                } else {
                    info!(
                        "🔍 [UDP {}] Reverse lookup MISS: using raw IP {}",
                        socket_id, std_ip
                    );
                    (std_ip, format!("{}:{}", std_ip, dst_p))
                }
            }
            smoltcp::wire::IpAddress::Ipv6(ip) => {
                let std_ip = std::net::Ipv4Addr::new(0, 0, 0, 0);
                (std_ip, format!("[{}]:{}", ip, dst_p))
            }
        };

        info!(
            "🚀 [UDP MASTER] ID:{} | Intercepted: {}:{} -> Target: {}",
            socket_id, src, src_p, target
        );

        let mut socket = SocketFactory::create_udp(dst_p);
        if socket
            .bind(IpListenEndpoint {
                addr: Some(dst),
                port: dst_p,
            })
            .is_ok()
        {
            let handle = socket_set.add(socket);
            let (conn, mut rx_smol, tx_smol) = UdpConnection::new(handle, src, src_p);

            self.tracker.handle_to_id.insert(handle, socket_id);
            self.tracker.active_udp.insert(handle, conn);
            self.tracker.inbound_tx.insert(socket_id, tx_smol);

            let tx_tunnel = self.tx_to_tunnel.clone();
            tokio::spawn(async move {
                info!("📡 [UDP {}] Task started for {}", socket_id, target);

                // ВОТ ТУТ ИСПРАВЛЕН ХАРДКОД! Передаем dst_ip вместо нулей
                let mut frame = RawCastFrame::connect(LocalProtocol::Udp, socket_id, dst_ip, dst_p);
                frame.payload = bytes::Bytes::from(target.clone());

                info!(
                    "📦 [UDP {}] Packed Connect frame: dst_ip={}, dst_port={}, payload={}",
                    socket_id, dst_ip, dst_p, target
                );

                if tx_tunnel.send(frame).await.is_err() {
                    error!("❌ [UDP {}] Failed to send CONNECT to tunnel", socket_id);
                    return;
                }

                let mut pkt_count = 0;
                while let Some((data, ip, port)) = rx_smol.recv().await {
                    pkt_count += 1;
                    if pkt_count == 1 {
                        info!("📤 [UDP {}] First data packet sent to tunnel", socket_id);
                    }

                    let df =
                        RawCastFrame::data(LocalProtocol::Udp, socket_id, ip, port, data.to_vec());
                    if tx_tunnel.send(df).await.is_err() {
                        break;
                    }
                }
                info!(
                    "🛑 [UDP {}] Task stopped. Sent {} packets",
                    socket_id, pkt_count
                );
            });
        }
    }

    // --- ЦИКЛ ОБРАБОТКИ СОКЕТОВ (Pumping) ---

    pub fn process_sockets(&mut self, socket_set: &mut SocketSet) {
        for (handle, socket) in socket_set.iter_mut() {
            if let Some(s) = tcp::Socket::downcast_mut(socket) {
                self.handle_tcp(handle, s);
            } else if let Some(s) = udp::Socket::downcast_mut(socket) {
                self.handle_udp(handle, s);
            } else if let Some(s) = icmp::Socket::downcast_mut(socket) {
                // smoltcp использует один тип icmp::Socket для v4 и v6
                // разделяем логику по содержимому или конфигурации
                self.handle_icmp(handle, s);
                self.handle_icmpv6(handle, s);
            }
        }
    }

    fn handle_tcp(&mut self, handle: SocketHandle, socket: &mut tcp::Socket) {
        if socket.state() == tcp::State::Closed {
            if let Some(id) = self.tracker.handle_to_id.get(&handle) {
                info!("🏁 [TCP {}] Connection closed", id);
            }
            self.tracker.queue_removal(handle);
            return;
        }

        if socket.state() == tcp::State::Established
            && !self.tracker.active_tcp.contains_key(&handle)
        {
            let Some(ep) = socket.local_endpoint() else {
                return;
            };
            let socket_id = self.tracker.generate_socket_id();
            let (conn, mut rx_smol, tx_smol, handshake_tx) = TcpConnection::new(handle);

            self.tracker.handle_to_id.insert(handle, socket_id);
            self.tracker.active_tcp.insert(handle, conn);
            self.tracker.inbound_tx.insert(socket_id, tx_smol);

            // ДОБАВЛЕНО ЛОГИРОВАНИЕ ДЛЯ TCP
            let (dst_ip, target) = match ep.addr {
                smoltcp::wire::IpAddress::Ipv4(ip) => {
                    let std_ip = std::net::Ipv4Addr::from(ip);
                    if let Some(domain) = self.resolver.fake_ip_store.lookup_by_ip(&std_ip) {
                        info!(
                            "🔍 [TCP {}] Reverse lookup MATCH: {} -> {}",
                            socket_id, std_ip, domain
                        );
                        (std_ip, format!("{}:{}", domain, ep.port))
                    } else {
                        info!(
                            "🔍 [TCP {}] Reverse lookup MISS: using raw IP {}",
                            socket_id, std_ip
                        );
                        (std_ip, format!("{}:{}", std_ip, ep.port))
                    }
                }
                smoltcp::wire::IpAddress::Ipv6(ip) => (
                    std::net::Ipv4Addr::new(0, 0, 0, 0),
                    format!("[{}]:{}", ip, ep.port),
                ),
            };

            info!("🔗 [TCP {}] established -> {}", socket_id, target);

            let tx_tunnel = self.tx_to_tunnel.clone();
            tokio::spawn(async move {
                let mut frame =
                    RawCastFrame::connect(LocalProtocol::Tcp, socket_id, dst_ip, ep.port);
                frame.payload = bytes::Bytes::from(target.clone());

                info!(
                    "📦 [TCP {}] Packed Connect frame: dst_ip={}, dst_port={}, payload={}",
                    socket_id, dst_ip, ep.port, target
                );

                if tx_tunnel.send(frame).await.is_ok() {
                    let _ = handshake_tx.send(());
                    while let Some(data) = rx_smol.recv().await {
                        let _ = tx_tunnel
                            .send(RawCastFrame::data(
                                LocalProtocol::Tcp,
                                socket_id,
                                dst_ip,
                                ep.port,
                                data.to_vec(),
                            ))
                            .await;
                    }
                }
            });
        }

        if let Some(conn) = self.tracker.active_tcp.get_mut(&handle) {
            if !conn.tick(socket) {
                info!("⚠️ [TCP] Tick failed, aborting handle {:?}", handle);
                socket.abort();
            }
        }
    }

    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        self.tracker.last_activity.insert(handle, StdInstant::now());

        // 1. DNS перехват с логированием
        if socket.endpoint().port == 53 {
            while let Ok((data, meta)) = socket.recv() {
                if let Some(res) = self.resolver.process_dns_query(data) {
                    // Используем debug, чтобы не заливать консоль, но видеть активность
                    debug!("🔍 [DNS] Resolved query for client {}", meta.endpoint);
                    if let Err(e) = socket.send_slice(&res, meta) {
                        warn!("❌ [DNS] Failed to send response: {:?}", e);
                    }
                }
            }
            return;
        }

        // 2. Жизненный цикл обычных UDP сессий
        if let Some(conn) = self.tracker.active_udp.get_mut(&handle) {
            if !conn.tick(socket) {
                if let Some(socket_id) = self.tracker.handle_to_id.get(&handle) {
                    info!("🛑 [UDP {}] Session expired or closed by tick", socket_id);
                }
                self.tracker.queue_removal(handle);
            }
        }
    }

    fn handle_icmp(&mut self, _handle: SocketHandle, socket: &mut icmp::Socket) {
        if !socket.can_recv() {
            return;
        }

        match socket.recv() {
            Ok((data, src_addr)) => {
                let Ok(pkt) = smoltcp::wire::Icmpv4Packet::new_checked(data) else {
                    return;
                };

                match pkt.msg_type() {
                    smoltcp::wire::Icmpv4Message::EchoRequest => {
                        info!("🏓 [ICMPv4] Ping Request from {}", src_addr);

                        // Формируем ответ (Echo Reply)
                        let mut reply_data = data.to_vec();
                        let mut reply_pkt =
                            smoltcp::wire::Icmpv4Packet::new_unchecked(&mut reply_data);
                        reply_pkt.set_msg_type(smoltcp::wire::Icmpv4Message::EchoReply);
                        reply_pkt.fill_checksum();

                        if let Err(e) = socket.send_slice(&reply_data, src_addr) {
                            warn!("❌ [ICMPv4] Reply failed to {}: {:?}", src_addr, e);
                        } else {
                            info!("✅ [ICMPv4] Echo Reply sent to {}", src_addr);
                        }
                    }
                    smoltcp::wire::Icmpv4Message::DstUnreachable => {
                        warn!(
                            "🚫 [ICMPv4] Destination Unreachable from {}. Check MTU!",
                            src_addr
                        );
                    }
                    _ => debug!("📡 [ICMPv4] Message {:?} from {}", pkt.msg_type(), src_addr),
                }
            }
            Err(e) => trace!("ICMPv4 recv error: {:?}", e),
        }
    }

    fn handle_icmpv6(&mut self, _handle: SocketHandle, socket: &mut icmp::Socket) {
        if !socket.can_recv() {
            return;
        }

        match socket.recv() {
            Ok((data, src_addr)) => {
                // 1. Извлекаем конкретно Ipv6Address из перечисления IpAddress
                let smoltcp::wire::IpAddress::Ipv6(ipv6_src) = src_addr else {
                    return; // Если пришел не IPv6, выходим
                };

                let Ok(pkt) = smoltcp::wire::Icmpv6Packet::new_checked(data) else {
                    return;
                };

                match pkt.msg_type() {
                    smoltcp::wire::Icmpv6Message::EchoRequest => {
                        info!("🏓 [ICMPv6] Ping Request from {}", ipv6_src);

                        let mut reply_data = data.to_vec();
                        let mut reply_pkt =
                            smoltcp::wire::Icmpv6Packet::new_unchecked(&mut reply_data);

                        reply_pkt.set_msg_type(smoltcp::wire::Icmpv6Message::EchoReply);

                        // 2. РАСЧЕТ ЧЕКСУММЫ (Критический момент)
                        let my_v6_gateway =
                            smoltcp::wire::Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

                        reply_pkt.fill_checksum(&my_v6_gateway, &ipv6_src);

                        if let Err(e) = socket.send_slice(&reply_data, src_addr) {
                            warn!("❌ [ICMPv6] Failed to send reply: {:?}", e);
                        } else {
                            info!("✅ [ICMPv6] Echo Reply sent to {}", src_addr);
                        }
                    }
                    smoltcp::wire::Icmpv6Message::DstUnreachable => {
                        warn!("🚫 [ICMPv6] Destination Unreachable from {}", ipv6_src);
                    }
                    smoltcp::wire::Icmpv6Message::PktTooBig => {
                        warn!(
                            "📏 [ICMPv6] Packet Too Big! MTU issue detected at {}",
                            ipv6_src
                        );
                    }
                    _ => {}
                }
            }
            Err(e) => trace!("ICMPv6 recv error: {:?}", e),
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
