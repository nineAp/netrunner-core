use bytes::Bytes;
use netrunner_core::{
    protocol::codec::{frame::FrameType, socks::TargetAddress},
    proxy::connection::{
        TCP_BUF_SIZE,
        muxer::{MuxMessage, Muxer},
    },
};
use netrunner_logger::{debug, info, warn};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::{IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket},
};
use std::{collections::HashMap, time::Duration, time::Instant as StdInstant};
use tokio::sync::mpsc;

use crate::connections::{
    CHANNEL_CAPACITY, dns::DnsHandler, ip_store::FakeIpStore, tcp_connection::TcpConnection,
    udp_connection::UdpConnection,
};

pub struct ConnectionManager {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp_sessions: HashMap<SocketHandle, TcpConnection>,
    active_udp_sessions: HashMap<SocketHandle, UdpConnection>,
    dns_handler: DnsHandler,
    fake_ip_store: FakeIpStore,
    failed_until: HashMap<SocketHandle, StdInstant>,
    sockets_to_remove: Vec<SocketHandle>,
    muxer: Muxer,
}

impl ConnectionManager {
    pub fn new(dns_handler: DnsHandler, muxer: Muxer) -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp_sessions: HashMap::new(),
            active_udp_sessions: HashMap::new(),
            fake_ip_store: FakeIpStore::new(),
            failed_until: HashMap::new(),
            dns_handler,
            sockets_to_remove: Vec::new(),
            muxer,
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

        if socket.state() == State::Closed {
            if self.active_tcp_sessions.contains_key(&handle) {
                debug!(%handle, "TCP session closed, removing from active sessions");
                self.active_tcp_sessions.remove(&handle);
            }

            if !self.sockets_to_remove.contains(&handle) {
                self.sockets_to_remove.push(handle);
            }
            return;
        }

        if socket.state() == State::Established && !self.active_tcp_sessions.contains_key(&handle) {
            let target = self.resolve_target(socket);

            if let TargetAddress::Domain(d, _) = &target {
                if d == "disconnected" {
                    socket.abort();
                    return;
                }
            }

            info!(%handle, "New TCP session established for target: {:?}", target);

            // 1. Создаем соединение и получаем каналы
            let (conn, mut rx_from_smol, tx_to_smol, handshake_tx) = TcpConnection::new(handle);
            self.active_tcp_sessions.insert(handle, conn);

            // 2. Выносим логику мультиплексирования в фоновую задачу
            let muxer = self.muxer.clone();
            let stream_id = muxer.next_id();
            let connect_payload = target.to_string();

            tokio::spawn(async move {
                let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(TCP_BUF_SIZE);
                muxer.register_stream(stream_id, v_tx);

                if muxer
                    .send_to_netwrok(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Connect,
                        data: Bytes::from(connect_payload),
                    })
                    .await
                    .is_err()
                {
                    muxer.remove_stream(stream_id);
                    return;
                }

                let first_payload =
                    tokio::time::timeout(Duration::from_secs(10), v_rx.recv()).await;
                match first_payload {
                    Ok(Some(data)) => {
                        if data.len() >= 2 && data[1] == 0x00 {
                            let _ = handshake_tx.send(());
                        } else {
                            netrunner_logger::warn!(stream_id, "Server rejected TCP connection");
                            muxer.remove_stream(stream_id);
                            return;
                        }
                    }
                    _ => {
                        netrunner_logger::error!(stream_id, "Timeout waiting for proxy response");
                        muxer.remove_stream(stream_id);
                        return;
                    }
                }

                let to_proxy = async {
                    while let Some(data) = rx_from_smol.recv().await {
                        let msg = MuxMessage {
                            stream_id,
                            frame_type: FrameType::Data,
                            data,
                        };
                        if muxer.send_to_netwrok(msg).await.is_err() {
                            break;
                        }
                    }
                };

                let from_proxy = async {
                    while let Some(data) = v_rx.recv().await {
                        if data.is_empty() {
                            break;
                        }
                        if tx_to_smol.send(data).await.is_err() {
                            break;
                        }
                    }
                };

                tokio::select! {
                    _ = to_proxy => {}
                    _ = from_proxy => {}
                }

                let _ = muxer
                    .send_to_netwrok(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Close,
                        data: Bytes::new(),
                    })
                    .await;
                muxer.remove_stream(stream_id);
            });
        }

        if let Some(conn) = self.active_tcp_sessions.get_mut(&handle) {
            if !conn.tick(socket) {
                debug!(%handle, "Connection tick failed, aborting.");
                socket.abort();
            }
        }

        if socket.state() == State::CloseWait {
            socket.close();
        }
    }

    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        self.last_activity.insert(handle, StdInstant::now());

        let local_port = socket.endpoint().port;

        if local_port == 53 {
            while socket.can_recv() {
                let (data, meta) = match socket.recv() {
                    Ok(res) => res,
                    Err(_) => break,
                };

                if let Some(response) = self.dns_handler.handle_query(data, &mut self.fake_ip_store)
                {
                    netrunner_logger::debug!(to = %meta.endpoint, "Sending DNS response (FakeIP/Filtered)");
                    let _ = socket.send_slice(&response, meta);
                }
            }
            return;
        }

        if socket.is_open() && !self.active_udp_sessions.contains_key(&handle) {
            let endpoint = socket.endpoint();
            let target = match endpoint.addr {
                Some(smoltcp::wire::IpAddress::Ipv4(ipv4_addr)) => {
                    TargetAddress::Ipv4(std::net::Ipv4Addr::from(ipv4_addr), endpoint.port)
                }
                Some(smoltcp::wire::IpAddress::Ipv6(ipv6_addr)) => {
                    TargetAddress::Ipv6(std::net::Ipv6Addr::from(ipv6_addr), endpoint.port)
                }
                None => {
                    netrunner_logger::warn!(%handle, "UDP socket endpoint has no IP address bound");
                    return;
                }
            };

            netrunner_logger::info!(%handle, target = %target, "New UDP proxied session established");

            // 1. Создаем UDP соединение и получаем каналы
            let (conn, mut rx_from_smol, tx_to_smol) = UdpConnection::new(handle);
            self.active_udp_sessions.insert(handle, conn);

            // 2. Фоновая задача для Muxer'а
            let muxer = self.muxer.clone();
            let stream_id = muxer.next_id();
            let connect_payload = target.to_string();

            tokio::spawn(async move {
                let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);
                muxer.register_stream(stream_id, v_tx);

                let _ = muxer
                    .send_to_netwrok(MuxMessage {
                        stream_id,
                        frame_type: FrameType::UdpConnect,
                        data: Bytes::from(connect_payload),
                    })
                    .await;

                let to_proxy = async {
                    while let Some(data) = rx_from_smol.recv().await {
                        let msg = MuxMessage {
                            stream_id,
                            frame_type: FrameType::UdpData,
                            data,
                        };
                        if muxer.send_to_netwrok(msg).await.is_err() {
                            break;
                        }
                    }
                };

                let from_proxy = async {
                    while let Some(data) = v_rx.recv().await {
                        if data.is_empty() {
                            break;
                        }
                        if tx_to_smol.send(data).await.is_err() {
                            break;
                        }
                    }
                };

                tokio::select! {
                    _ = to_proxy => {}
                    _ = from_proxy => {}
                }

                let _ = muxer
                    .send_to_netwrok(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Close,
                        data: Bytes::new(),
                    })
                    .await;
                muxer.remove_stream(stream_id);
            });
        }

        if let Some(conn) = self.active_udp_sessions.get_mut(&handle) {
            if !conn.tick(socket) {
                self.sockets_to_remove.push(handle);
                self.active_udp_sessions.remove(&handle);
            }
        }
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

    fn create_dynamic_tcp_socket<'a>(port: u16) -> tcp::Socket<'a> {
        let buf_size = match port {
            443 | 80 => 512 * 1024,
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

    pub fn try_create_socket_from_packet(&mut self, packet: &[u8], socket_set: &mut SocketSet) {
        let Ok(ip_packet) = Ipv4Packet::new_checked(packet) else {
            return;
        };

        match ip_packet.next_header() {
            IpProtocol::Tcp => {
                let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) else {
                    return;
                };

                if tcp_packet.syn() && !tcp_packet.ack() {
                    let dst_port = tcp_packet.dst_port();
                    let dst_addr = ip_packet.dst_addr();

                    if !self.has_active_tcp_session(socket_set, dst_addr.into(), dst_port) {
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
            IpProtocol::Udp => {
                let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) else {
                    return;
                };
                let dst_port = udp_packet.dst_port();
                let dst_addr = ip_packet.dst_addr();

                if dst_port == 0 || dst_port == 137 || dst_port == 138 {
                    return;
                }

                if !self.has_active_udp_session(socket_set, dst_addr.into(), dst_port) {
                    netrunner_logger::debug!(target: "netrunner", "Dynamic UDP: Creating socket for {}:{}", dst_addr, dst_port);

                    let mut socket = Self::create_dynamic_udp_socket(dst_port);
                    let endpoint = IpListenEndpoint {
                        addr: Some(dst_addr.into()),
                        port: dst_port,
                    };

                    if let Ok(_) = socket.bind(endpoint) {
                        socket_set.add(socket);
                    }
                }
            }
            _ => {}
        }
    }

    fn create_dynamic_udp_socket<'a>(port: u16) -> udp::Socket<'a> {
        let (buf_size, packet_count) = match port {
            443 => (512 * 1024, 380), // Большой буфер для QUIC (YouTube)
            53 => (16 * 1024, 32),    // DNS
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

    fn create_icmp_socket<'a>() -> icmp::Socket<'a> {
        let icmp_rx_buffer =
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 2048]);
        let icmp_tx_buffer =
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 2048]);
        icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer)
    }

    fn has_active_tcp_session(
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

    fn has_active_udp_session(
        &self,
        socket_set: &SocketSet,
        dst_addr: smoltcp::wire::IpAddress,
        dst_port: u16,
    ) -> bool {
        for (_, socket) in socket_set.iter() {
            if let Some(udp) = udp::Socket::downcast(socket) {
                let endpoint = udp.endpoint();
                if endpoint.addr == Some(dst_addr) && endpoint.port == dst_port {
                    return true;
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

    pub fn setup_sockets(n_icmp: usize) -> SocketSet<'static> {
        let mut sockets = SocketSet::new(Vec::with_capacity(48));

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
