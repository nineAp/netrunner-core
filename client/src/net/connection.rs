use bytes::{Buf, Bytes};
use netrunner_core::{
    net::{GLOBAL_MIN_RTT, NetworkConfig, UDP_IDLE_TIMEOUT},
    rawcast::{LocalProtocol, RawCastFrame},
};
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    time::Duration,
    wire::{
        Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpAddress, IpEndpoint,
        Ipv6Address,
    },
};
use std::{collections::VecDeque, sync::atomic::Ordering};
use tokio::sync::{mpsc, oneshot};

use netrunner_logger::{debug, info};

pub struct ConnectionCore<T> {
    pub handle: SocketHandle,
    pub tx: mpsc::UnboundedSender<T>,       // 🔥 Полностью Unbounded
    pub rx: mpsc::UnboundedReceiver<Bytes>, // 🔥 Полностью Unbounded
}

impl<T> ConnectionCore<T> {
    pub fn new(
        handle: SocketHandle,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<T>,
        mpsc::UnboundedSender<Bytes>,
    ) {
        let (tx_to_net, rx_from_smol) = mpsc::unbounded_channel::<T>();
        let (tx_to_smol, rx_from_net) = mpsc::unbounded_channel::<Bytes>();

        let core = Self {
            handle,
            tx: tx_to_net,
            rx: rx_from_net,
        };

        (core, rx_from_smol, tx_to_smol)
    }
}

#[derive(Debug, PartialEq)]
pub enum ConnectionState {
    Established,
    Handshaking,
    Active,
    Closed,
}

pub struct TcpConnection {
    core: ConnectionCore<Bytes>,
    state: ConnectionState,
    pending_data: VecDeque<Bytes>,
    handshake_rx: Option<oneshot::Receiver<()>>,
    chunk_buf: Vec<u8>,
    server_eof: bool,
}

impl TcpConnection {
    pub fn new(
        handle: SocketHandle,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<Bytes>,
        mpsc::UnboundedSender<Bytes>,
        oneshot::Sender<()>,
    ) {
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle);
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let conn = Self {
            core,
            state: ConnectionState::Handshaking,
            pending_data: VecDeque::new(),
            handshake_rx: Some(handshake_rx),
            chunk_buf: vec![0u8; NetworkConfig::global().tcp_chunk_size],
            server_eof: false,
        };

        (conn, rx_from_smol, tx_to_smol, handshake_tx)
    }

    pub fn tick(&mut self, socket: &mut tcp::Socket) -> bool {
        match self.state {
            ConnectionState::Handshaking => {
                if let Some(rx) = &mut self.handshake_rx {
                    match rx.try_recv() {
                        Ok(_) => {
                            debug!(%self.core.handle, "TCP Handshake successful, State -> Active");
                            self.state = ConnectionState::Established;
                            self.handshake_rx = None;
                            return true;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => return true,
                        Err(oneshot::error::TryRecvError::Closed) => {
                            self.state = ConnectionState::Closed;
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }

            ConnectionState::Active => {
                self.poll_and_process(socket);

                if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    debug!(%self.core.handle, "TCP Socket is finished, state -> Closed");
                    self.state = ConnectionState::Closed;
                    return false;
                }
            }

            ConnectionState::Closed => {
                return false;
            }

            ConnectionState::Established => {
                info!(
                    "✅ [TCP {}] Connection fully established and ready for data",
                    self.core.handle
                );
                self.state = ConnectionState::Active;
                return true;
            }
        }

        true
    }

    fn poll_and_process(&mut self, socket: &mut tcp::Socket) {
        let current_rtt = GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        let rtt = Duration::from_millis(current_rtt as u64);
        socket.set_tunnel_rtt(rtt);

        if self.app_pending_out_size() < 512 * 1024 {
            while socket.can_recv() {
                if let Ok(n) = socket.peek_slice(&mut self.chunk_buf) {
                    if n == 0 {
                        break;
                    }
                    let chunk = Bytes::copy_from_slice(&self.chunk_buf[..n]);

                    if self.core.tx.send(chunk).is_ok() {
                        socket.recv_slice(&mut self.chunk_buf[..n]).unwrap();
                    } else {
                        self.server_eof = true;
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        if !self.server_eof {
            loop {
                match self.core.rx.try_recv() {
                    Ok(data) => {
                        self.pending_data.push_back(data);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        debug!(%self.core.handle, "Tunnel channel closed (Server EOF)");
                        self.server_eof = true;
                        break;
                    }
                }
            }
        }

        while socket.can_send() {
            if let Some(mut chunk) = self.pending_data.pop_front() {
                match socket.send_slice(&chunk) {
                    Ok(n) => {
                        if n < chunk.len() {
                            chunk.advance(n);
                            self.pending_data.push_front(chunk);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(%self.core.handle, "Smoltcp send error: {:?}", e);
                        self.pending_data.push_front(chunk);
                        break;
                    }
                }
            } else {
                break;
            }
        }

        if self.server_eof && self.pending_data.is_empty() {
            let state = socket.state();
            if state == tcp::State::Established || state == tcp::State::CloseWait {
                debug!(%self.core.handle, "All data flushed after server EOF, sending FIN to browser");
                socket.close();
            }
        }
    }

    pub fn spawn(
        socket_id: u64,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
        target: String,
        mut rx_smol: mpsc::UnboundedReceiver<Bytes>,
        handshake_tx: oneshot::Sender<()>,
        // 🔥 ФИКС: Тип изменен на UnboundedSender
        tx_tunnel: mpsc::UnboundedSender<RawCastFrame>,
    ) {
        tokio::spawn(async move {
            let mut frame = RawCastFrame::connect(LocalProtocol::Tcp, socket_id, dst_ip, dst_port);
            frame.payload = Bytes::from(target);

            // send() на UnboundedSender не асинхронный и возвращает Result<(), T>
            if tx_tunnel.send(frame).is_err() {
                netrunner_logger::error!("❌ [TCP {}] Failed to send CONNECT to tunnel", socket_id);
                return;
            }

            let _ = handshake_tx.send(());

            while let Some(data) = rx_smol.recv().await {
                let data_frame = RawCastFrame::data(
                    LocalProtocol::Tcp,
                    socket_id,
                    dst_ip,
                    dst_port,
                    data.to_vec(),
                );

                if tx_tunnel.send(data_frame).is_err() {
                    break;
                }
            }

            let close_frame = RawCastFrame::close(LocalProtocol::Tcp, socket_id, dst_ip, dst_port);
            let _ = tx_tunnel.send(close_frame);

            debug!("🏁 [TCP {}] Spawned task finished", socket_id);
        });
    }

    pub fn app_pending_out_size(&self) -> usize {
        self.pending_data.iter().map(|b| b.len()).sum()
    }
}

pub type UdpPacketTarget = (Bytes, std::net::Ipv4Addr, u16);

pub struct UdpConnection {
    core: ConnectionCore<UdpPacketTarget>,
    last_client_endpoint: Option<IpEndpoint>,
    last_activity: std::time::Instant,
}

impl UdpConnection {
    pub fn new(
        handle: SocketHandle,
        client_addr: smoltcp::wire::IpAddress,
        client_port: u16,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<UdpPacketTarget>,
        mpsc::UnboundedSender<Bytes>,
    ) {
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle);
        let conn = Self {
            core,
            last_client_endpoint: Some(IpEndpoint::new(client_addr, client_port)),
            last_activity: std::time::Instant::now(),
        };
        (conn, rx_from_smol, tx_to_smol)
    }

    pub fn has_client(&self, port: u16) -> bool {
        self.last_client_endpoint
            .map_or(false, |ep| ep.port == port)
    }

    pub fn tick(&mut self, socket: &mut udp::Socket) -> bool {
        if self.last_activity.elapsed() > UDP_IDLE_TIMEOUT {
            socket.close();
            return false;
        }

        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv() {
                if let smoltcp::wire::IpAddress::Ipv4(ip) = metadata.endpoint.addr {
                    self.last_client_endpoint = Some(metadata.endpoint);
                    let target_ip = std::net::Ipv4Addr::from(ip);
                    let target_port = metadata.endpoint.port;
                    let payload = (Bytes::copy_from_slice(data), target_ip, target_port);

                    if self.core.tx.send(payload).is_ok() {
                        self.last_activity = std::time::Instant::now();
                    }
                }
            }
        }

        if let Some(client_endpoint) = self.last_client_endpoint {
            while socket.can_send() {
                match self.core.rx.try_recv() {
                    Ok(data) => {
                        if let Err(e) = socket.send_slice(&data, client_endpoint) {
                            debug!("Dropped UDP packet: {:?}", e);
                        } else {
                            self.last_activity = std::time::Instant::now();
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        true
    }

    pub fn spawn(
        socket_id: u64,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
        target: String,
        mut rx_smol: mpsc::UnboundedReceiver<UdpPacketTarget>,
        // 🔥 ФИКС: Тип изменен на UnboundedSender
        tx_tunnel: mpsc::UnboundedSender<RawCastFrame>,
    ) {
        tokio::spawn(async move {
            debug!("📡 [UDP {}] Task started for {}", socket_id, target);
            let mut frame = RawCastFrame::connect(LocalProtocol::Udp, socket_id, dst_ip, dst_port);
            frame.payload = Bytes::from(target);

            if tx_tunnel.send(frame).is_err() {
                netrunner_logger::error!("❌ [UDP {}] Failed to send CONNECT to tunnel", socket_id);
                return;
            }

            while let Some((data, ip, port)) = rx_smol.recv().await {
                let data_frame =
                    RawCastFrame::data(LocalProtocol::Udp, socket_id, ip, port, data.to_vec());
                if tx_tunnel.send(data_frame).is_err() {
                    break;
                }
            }

            let close_frame = RawCastFrame::close(LocalProtocol::Udp, socket_id, dst_ip, dst_port);
            let _ = tx_tunnel.send(close_frame);
            info!("🛑 [UDP {}] Task stopped", socket_id);
        });
    }
}

// IcmpResponder оставляем как был (он не использует каналы)
use smoltcp::socket::icmp;

pub struct IcmpResponder;

impl IcmpResponder {
    pub fn handle(socket: &mut icmp::Socket) {
        if !socket.can_recv() {
            return;
        }

        let result = socket.recv();

        if let Ok((data, src_addr)) = result {
            let payload = data.to_vec();

            match src_addr {
                IpAddress::Ipv4(_) => Self::reply_v4(socket, payload, src_addr),
                IpAddress::Ipv6(v6) => Self::reply_v6(socket, payload, v6),
            }
        }
    }

    fn reply_v4(socket: &mut icmp::Socket, mut payload: Vec<u8>, src: IpAddress) {
        if let Ok(pkt) = Icmpv4Packet::new_checked(&payload) {
            if pkt.msg_type() == Icmpv4Message::EchoRequest {
                let mut reply_pkt = Icmpv4Packet::new_unchecked(&mut payload);
                reply_pkt.set_msg_type(Icmpv4Message::EchoReply);
                reply_pkt.fill_checksum();

                let _ = socket.send_slice(&payload, src);
                info!("🏓 [ICMPv4] Echo Reply -> {}", src);
            }
        }
    }

    fn reply_v6(socket: &mut icmp::Socket, mut payload: Vec<u8>, src: Ipv6Address) {
        if let Ok(pkt) = Icmpv6Packet::new_checked(&payload) {
            if pkt.msg_type() == Icmpv6Message::EchoRequest {
                let mut reply_pkt = Icmpv6Packet::new_unchecked(&mut payload);
                reply_pkt.set_msg_type(Icmpv6Message::EchoReply);

                let gateway = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
                reply_pkt.fill_checksum(&gateway, &src);

                let _ = socket.send_slice(&payload, src.into());
                info!("🏓 [ICMPv6] Echo Reply -> {}", src);
            }
        }
    }
}
