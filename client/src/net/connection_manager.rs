use netrunner_core::rawcast::{RawCastEvent, RawCastFrame};
use netrunner_logger::{info, trace};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{Socket, tcp, udp},
    wire::{IpAddress, IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket},
};
use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;

use crate::net::{
    connection::{IcmpResponder, TcpConnection, UdpConnection},
    dns::{DnsHandler, FakeIpStore},
    session_tracker::SessionTracker,
    socket_factory::SocketProvider,
};

struct Flow {
    src: IpAddress,
    dst: IpAddress,
    src_p: u16,
    dst_p: u16,
}

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

    pub fn resolve_destination(&self, addr: IpAddress, port: u16) -> (std::net::Ipv4Addr, String) {
        match addr {
            IpAddress::Ipv4(ip) => {
                let std_ip = std::net::Ipv4Addr::from(ip);
                if let Some(domain) = self.fake_ip_store.lookup_by_ip(&std_ip) {
                    (std_ip, format!("{}:{}", domain, port))
                } else {
                    (std_ip, format!("{}:{}", std_ip, port))
                }
            }
            IpAddress::Ipv6(ip) => (
                std::net::Ipv4Addr::UNSPECIFIED,
                format!("[{}]:{}", ip, port),
            ),
        }
    }
}

pub struct ConnectionManager {
    tracker: SessionTracker,
    resolver: TargetResolver,
    tx_to_tunnel: mpsc::Sender<RawCastFrame>,
    factory: Arc<dyn SocketProvider>,
}

impl ConnectionManager {
    pub fn new(
        dns_handler: DnsHandler,
        tx_to_tunnel: mpsc::Sender<RawCastFrame>,
        factory: Arc<dyn SocketProvider>,
    ) -> Self {
        Self {
            tracker: SessionTracker::new(),
            resolver: TargetResolver::new(dns_handler),
            tx_to_tunnel,
            factory,
        }
    }

    pub fn try_inject_inbound(&mut self, frame: RawCastFrame) -> Result<(), RawCastFrame> {
        if frame.event == RawCastEvent::Close {
            info!("💀 [Stream {}] Received CLOSE from tunnel", frame.socket_id);
            self.tracker.close_tunnel_session(frame.socket_id);
            return Ok(());
        }

        if frame.event != RawCastEvent::Data {
            return Ok(());
        }

        if let Some(tx) = self.tracker.get_inbound_tx(frame.socket_id) {
            tx.try_send(frame.payload.clone()).map_err(|e| {
                if matches!(e, mpsc::error::TrySendError::Closed(_)) {
                    self.tracker.close_tunnel_session(frame.socket_id);
                }
                frame
            })
        } else {
            trace!("👻 [Stream {}] Orphan packet", frame.socket_id);
            Ok(())
        }
    }

    pub fn setup_sockets(factory: &dyn SocketProvider, n_icmp: usize) -> SocketSet<'static> {
        factory.create_base_set(n_icmp)
    }

    pub fn start_listening(&mut self, socket_set: &mut SocketSet) {
        for (_, socket) in socket_set.iter_mut() {
            match socket {
                Socket::Tcp(tcp) => {
                    if !tcp.is_open() {
                        let _ = tcp.listen(IpListenEndpoint {
                            addr: None,
                            port: 443,
                        });
                    }
                }
                Socket::Udp(udp) => {
                    if !udp.is_open() {
                        let _ = udp.bind(IpListenEndpoint {
                            addr: None,
                            port: 53,
                        });
                    }
                }
                _ => {}
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
        let mut flow = Flow {
            src: ip.src_addr().into(),
            dst: ip.dst_addr().into(),
            src_p: 0,
            dst_p: 0,
        };

        match ip.next_header() {
            IpProtocol::Tcp => {
                if let Ok(p) = TcpPacket::new_checked(ip.payload()) {
                    flow.src_p = p.src_port();
                    flow.dst_p = p.dst_port();
                    self.intercept_tcp(flow, socket_set);
                }
            }
            IpProtocol::Udp => {
                if let Ok(p) = UdpPacket::new_checked(ip.payload()) {
                    flow.src_p = p.src_port();
                    flow.dst_p = p.dst_port();
                    self.intercept_udp(flow, socket_set);
                }
            }
            _ => {}
        }
    }

    fn process_ipv6(&mut self, packet: &[u8], socket_set: &mut SocketSet) {
        let Ok(ip) = Ipv6Packet::new_checked(packet) else {
            return;
        };
        let mut flow = Flow {
            src: ip.src_addr().into(),
            dst: ip.dst_addr().into(),
            src_p: 0,
            dst_p: 0,
        };

        match ip.next_header() {
            IpProtocol::Tcp => {
                if let Ok(p) = TcpPacket::new_checked(ip.payload()) {
                    flow.src_p = p.src_port();
                    flow.dst_p = p.dst_port();
                    self.intercept_tcp(flow, socket_set);
                }
            }
            IpProtocol::Udp => {
                if let Ok(p) = UdpPacket::new_checked(ip.payload()) {
                    flow.src_p = p.src_port();
                    flow.dst_p = p.dst_port();
                    self.intercept_udp(flow, socket_set);
                }
            }
            _ => {}
        }
    }

    fn intercept_tcp(&mut self, f: Flow, socket_set: &mut SocketSet) {
        if !self.tracker.has_connection_from(f.src, f.src_p, socket_set) {
            let socket = self.factory.create_listening_tcp(Some(f.dst), f.dst_p);
            let handle = socket_set.add(socket);
            self.tracker.add_pending_tcp(handle);
        }
    }

    fn intercept_udp(&mut self, f: Flow, socket_set: &mut SocketSet) {
        if f.dst_p == 0
            || f.dst_p == 137
            || f.dst_p == 138
            || f.dst_p == 53
            || self.tracker.is_client_known(f.src_p)
        {
            return;
        }

        let socket_id = self.tracker.next_id();
        let (dst_ip, target) = self.resolver.resolve_destination(f.dst, f.dst_p);

        let socket = self.factory.create_bound_udp(Some(f.dst), f.dst_p);
        if socket.is_open() {
            let handle = socket_set.add(socket);
            let (conn, rx_smol, tx_smol) = UdpConnection::new(handle, f.src, f.src_p);

            self.tracker.register_udp(handle, socket_id, conn, tx_smol);
            UdpConnection::spawn(
                socket_id,
                dst_ip,
                f.dst_p,
                target,
                rx_smol,
                self.tx_to_tunnel.clone(),
            );
        }
    }

    pub fn process_sockets(&mut self, socket_set: &mut SocketSet) {
        for (handle, socket) in socket_set.iter_mut() {
            match socket {
                Socket::Tcp(s) => self.handle_tcp(handle, s),
                Socket::Udp(s) => self.handle_udp(handle, s),
                Socket::Icmp(s) => IcmpResponder::handle(s),
            }
        }
    }

    fn handle_tcp(&mut self, handle: SocketHandle, socket: &mut tcp::Socket) {
        self.tracker.update_activity(handle);

        if socket.state() == tcp::State::Closed {
            self.tracker.queue_removal(handle);
            return;
        }

        if self
            .tracker
            .check_pending_timeout(handle, Duration::from_secs(20))
        {
            socket.abort();
            self.tracker.queue_removal(handle);
            return;
        }

        if socket.state() == tcp::State::Established && self.tracker.should_init_tcp(handle) {
            let ep = socket.local_endpoint().unwrap();
            let socket_id = self.tracker.next_id();
            let (dst_ip, target) = self.resolver.resolve_destination(ep.addr, ep.port);

            let (conn, rx_smol, tx_smol, handshake_tx) = TcpConnection::new(handle);
            self.tracker.register_tcp(handle, socket_id, conn, tx_smol);

            TcpConnection::spawn(
                socket_id,
                dst_ip,
                ep.port,
                target,
                rx_smol,
                handshake_tx,
                self.tx_to_tunnel.clone(),
            );
        }

        if let Some(conn) = self.tracker.get_tcp_mut(handle) {
            if !conn.tick(socket) {
                socket.abort();
            }
        }
    }

    fn handle_udp(&mut self, handle: SocketHandle, socket: &mut udp::Socket) {
        self.tracker.update_activity(handle);

        if socket.endpoint().port == 53 {
            while let Ok((data, meta)) = socket.recv() {
                if let Some(res) = self.resolver.process_dns_query(data) {
                    let _ = socket.send_slice(&res, meta);
                }
            }
            return;
        }

        if let Some(conn) = self.tracker.get_udp_mut(handle) {
            if !conn.tick(socket) {
                self.tracker.queue_removal(handle);
            }
        }
    }

    pub fn cleanup(&mut self, socket_set: &mut SocketSet) {
        self.tracker.enforce_idle_timeouts(Duration::from_secs(120));

        self.tracker.cleanup(socket_set);
    }
}
