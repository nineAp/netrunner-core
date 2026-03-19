use netrunner_core::protocol::codec::socks::TargetAddress;
use netrunner_logger::{debug, error, info, warn};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, icmp, tcp, udp},
    wire::IpListenEndpoint,
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
            dns_handler, // Просто сохраняем готовый объект
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
            if let Some(until) = self.failed_until.get(&handle) {
                if StdInstant::now() < *until {
                    return;
                }
            }

            self.active_tcp_sessions.remove(&handle);
            socket.abort();
            let _ = socket.listen(443);
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

            let conn = TcpConnection::new(handle, self.proxy_ip.clone(), target);
            self.active_tcp_sessions.insert(handle, conn);
        }

        if let Some(conn) = self.active_tcp_sessions.get_mut(&handle) {
            if !conn.tick(socket) {
                debug!(%handle, "Connection handshake failed or closed, aborting socket.");
                self.active_tcp_sessions.remove(&handle);
                socket.abort();
                self.failed_until
                    .insert(handle, StdInstant::now() + Duration::from_secs(5));
            }
        } else if socket.state() == State::Established {
            self.failed_until
                .insert(handle, StdInstant::now() + Duration::from_secs(5));
            socket.abort();
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

    pub fn setup_sockets(n_tcp: usize, n_udp: usize, n_icmp: usize) -> SocketSet<'static> {
        let mut sockets = SocketSet::new(Vec::with_capacity(n_tcp + n_udp + n_icmp));

        for _ in 0..n_tcp {
            sockets.add(Self::create_tcp_socket());
        }

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
