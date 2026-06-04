use bytes::{Buf, Bytes};
use netrunner_core::{
    net::{GLOBAL_MIN_RTT, NetworkConfig, UDP_IDLE_TIMEOUT},
    rawcast::{LocalProtocol, RawCastFrame},
};
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    wire::{
        Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpAddress, IpEndpoint,
        Ipv6Address,
    },
};
use std::{collections::VecDeque, sync::{Arc, atomic::{AtomicBool, Ordering}}};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use netrunner_logger::{debug, info, instrument};
pub struct ConnectionCore<T> {
    pub handle: SocketHandle,
    pub tx: mpsc::Sender<T>,
    pub rx: mpsc::Receiver<Bytes>,
    pub is_saturated: Arc<AtomicBool>,
}

impl<T> ConnectionCore<T> {
    pub fn new(handle: SocketHandle) -> (Self, mpsc::Receiver<T>, mpsc::Sender<Bytes>, Arc<AtomicBool>) {
        let cap = NetworkConfig::global().channel_capacity;
        let (tx_to_net, rx_from_smol) = mpsc::channel::<T>(cap);
        let (tx_to_smol, rx_from_net) = mpsc::channel::<Bytes>(cap);
        let is_saturated = Arc::new(AtomicBool::new(false));

        let core = Self {
            handle,
            tx: tx_to_net,
            rx: rx_from_net,
            is_saturated: is_saturated.clone(),
        };

        (core, rx_from_smol, tx_to_smol, is_saturated)
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
    pending_bytes: usize,
    handshake_rx: Option<oneshot::Receiver<()>>,
    chunk_buf: Vec<u8>,
    server_eof: bool,
    permit: Option<OwnedSemaphorePermit>,

    total_up_bytes: u64,
    total_down_bytes: u64,
    rx_congested: bool,
    tx_congested: bool, 
}

impl TcpConnection {
    pub fn new(
        handle: SocketHandle,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> (
        Self,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<Bytes>,
        oneshot::Sender<()>,
        Arc<AtomicBool>
    ) {
        let (core, rx_from_smol, tx_to_smol, is_saturated) = ConnectionCore::new(handle);
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let conn = Self {
            core,
            state: ConnectionState::Handshaking,
            permit: Some(permit),
            pending_data: VecDeque::new(),
            pending_bytes: 0,
            handshake_rx: Some(handshake_rx),
            chunk_buf: vec![0u8; NetworkConfig::global().tcp_chunk_size],
            server_eof: false,
            total_up_bytes: 0,
            total_down_bytes: 0,
            rx_congested: false,
            tx_congested: false,
        };

        (conn, rx_from_smol, tx_to_smol, handshake_tx, is_saturated)
    }

    pub fn tick(&mut self, socket: &mut tcp::Socket, timestamp: smoltcp::time::Instant) -> bool {
        match self.state {
            ConnectionState::Handshaking => {
                if let Some(rx) = &mut self.handshake_rx {
                    match rx.try_recv() {
                        Ok(_) => {
                            debug!(%self.core.handle, "TCP Handshake successful, State -> Active");
                            self.permit.take();
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
                self.poll_and_process(socket, timestamp);

                if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    info!(
                        %self.core.handle, 
                        UP = %self.total_up_bytes, 
                        DOWN = %self.total_down_bytes, 
                        "🏁 TCP Socket finished and closed"
                    );
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

    fn poll_and_process(&mut self, socket: &mut tcp::Socket, timestamp: smoltcp::time::Instant) {
        let current_rtt = GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        let rtt = smoltcp::time::Duration::from_millis(current_rtt as u64);
        socket.set_tunnel_rtt(rtt);

        // 1. Читаем из браузера -> в Туннель (Upload)
        while socket.can_recv() && self.core.tx.capacity() > 0 {
            if let Ok(n) = socket.peek_slice(&mut self.chunk_buf, timestamp) {
                if n == 0 { break; }
                let chunk = Bytes::copy_from_slice(&self.chunk_buf[..n]);

                match self.core.tx.try_send(chunk) {
                    Ok(_) => {
                        socket.recv_slice(&mut self.chunk_buf[..n]).unwrap();
                        self.total_up_bytes += n as u64; // Учет Upload
                        
                        // Если была перегрузка, а теперь прошло — пишем радостный лог
                        if self.tx_congested {
                            netrunner_logger::debug!(%self.core.handle, "🟢 Upload channel cleared. Resuming read from browser.");
                            self.tx_congested = false;
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        if !self.tx_congested {
                            netrunner_logger::debug!(%self.core.handle, "🟡 Upload Congestion: Channel to Muxer is full. Pausing read from browser.");
                            self.tx_congested = true;
                        }
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.server_eof = true;
                        break;
                    }
                }
            } else { break; }
        }

        // 2. Читаем из Туннеля -> в Браузер (Download)
        if !self.server_eof {
            loop {
                if self.pending_bytes > 1024 * 1024 { 
                    if !self.rx_congested {
                        netrunner_logger::warn!(%self.core.handle, "🟡 Download Congestion: App buffer high. Pausing tunnel read.");
                        self.rx_congested = true;
                        self.core.is_saturated.store(true, Ordering::Release); // 🔥 ОПОВЕЩАЕМ ENGINE
                    }
                    break;
                } 
                // Нижний порог (512 КБ)
                else if self.rx_congested && self.pending_bytes < 512 * 1024 {
                    netrunner_logger::debug!(%self.core.handle, "🟢 Download buffer relieved. Resuming tunnel read.");
                    self.rx_congested = false;
                    self.core.is_saturated.store(false, Ordering::Release); // 🔥 ДАЕМ ДОБРО ENGINE
                }

                match self.core.rx.try_recv() {
                    Ok(data) => {
                        self.pending_bytes += data.len();
                        self.total_down_bytes += data.len() as u64; // Учет Download
                        self.pending_data.push_back(data);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.server_eof = true;
                        break;
                    }
                }
            }
        }

        // 3. Отправляем в smoltcp то, что накопилось (оставляем как было)
        while socket.can_send() {
            if let Some(mut chunk) = self.pending_data.pop_front() {
                match socket.send_slice(&chunk) {
                    Ok(n) => {
                        self.pending_bytes -= n;
                        if n < chunk.len() {
                            chunk.advance(n);
                            self.pending_data.push_front(chunk);
                            break; 
                        }
                    }
                    Err(e) => {
                        netrunner_logger::debug!(%self.core.handle, "Smoltcp send error: {:?}", e);
                        self.pending_data.push_front(chunk);
                        break;
                    }
                }
            } else { break; }
        }

        if self.server_eof && self.pending_data.is_empty() {
            let state = socket.state();
            if state == tcp::State::Established || state == tcp::State::CloseWait {
                netrunner_logger::debug!(%self.core.handle, "All data flushed, sending FIN to browser");
                socket.close();
            }
        }
    }

    pub fn app_pending_out_size(&self) -> usize {
        self.pending_bytes
    }

    #[instrument(skip(rx_smol, handshake_tx, tx_tunnel), fields(
        socket_id = socket_id, 
        dst = %target
    ))]
    pub fn spawn(
        socket_id: u64,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
        target: String,
        mut rx_smol: mpsc::Receiver<Bytes>,
        handshake_tx: oneshot::Sender<()>,
        tx_tunnel: mpsc::Sender<RawCastFrame>,
    ) {
        tokio::spawn(async move {
            let mut frame = RawCastFrame::connect(LocalProtocol::Tcp, socket_id, dst_ip, dst_port);
            frame.payload = Bytes::from(target);

            if tx_tunnel.send(frame).await.is_err() {
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
                    data
                );

                if tx_tunnel.send(data_frame).await.is_err() {
                    break;
                }
            }

            let close_frame = RawCastFrame::close(LocalProtocol::Tcp, socket_id, dst_ip, dst_port);
            let _ = tx_tunnel.send(close_frame).await;

            debug!("🏁 [TCP {}] Spawned task finished", socket_id);
        });
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
    ) -> (Self, mpsc::Receiver<UdpPacketTarget>, mpsc::Sender<Bytes>, Arc<AtomicBool>) {
        let (core, rx_from_smol, tx_to_smol, is_saturated) = ConnectionCore::new(handle);
        let conn = Self {
            core,
            last_client_endpoint: Some(IpEndpoint::new(client_addr, client_port)),
            last_activity: std::time::Instant::now(),
        };
        (conn, rx_from_smol, tx_to_smol, is_saturated)
    }

    pub fn has_client(&self, port: u16) -> bool {
        self.last_client_endpoint
            .map_or(false, |ep| ep.port == port)
    }

    pub fn tick(&mut self, socket: &mut udp::Socket, timestamp: smoltcp::time::Instant) -> bool {
        if self.last_activity.elapsed() > UDP_IDLE_TIMEOUT {
            socket.close();
            return false;
        }

        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv(timestamp) {
                if let smoltcp::wire::IpAddress::Ipv4(ip) = metadata.endpoint.addr {
                    self.last_client_endpoint = Some(metadata.endpoint);
                    let target_ip = std::net::Ipv4Addr::from(ip);
                    let target_port = metadata.endpoint.port;
                    let payload = (Bytes::copy_from_slice(data), target_ip, target_port);

                    if self.core.tx.try_send(payload).is_ok() {
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

    #[instrument(skip(rx_smol, tx_tunnel), fields(
        socket_id = socket_id, 
        dst = %target
    ))]
    pub fn spawn(
        socket_id: u64,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
        target: String,
        mut rx_smol: mpsc::Receiver<UdpPacketTarget>,
        tx_tunnel: mpsc::Sender<RawCastFrame>,
    ) {
        tokio::spawn(async move {
            debug!("📡 [UDP {}] Task started for {}", socket_id, target);
            let mut frame = RawCastFrame::connect(LocalProtocol::Udp, socket_id, dst_ip, dst_port);
            frame.payload = Bytes::from(target);

            if tx_tunnel.send(frame).await.is_err() {
                netrunner_logger::error!("❌ [UDP {}] Failed to send CONNECT to tunnel", socket_id);
                return;
            }

            while let Some((data, ip, port)) = rx_smol.recv().await {
                let data_frame =
                    RawCastFrame::data(LocalProtocol::Udp, socket_id, ip, port, data);
                if tx_tunnel.send(data_frame).await.is_err() {
                    break;
                }
            }

            let close_frame = RawCastFrame::close(LocalProtocol::Udp, socket_id, dst_ip, dst_port);
            let _ = tx_tunnel.send(close_frame).await;
            info!("🛑 [UDP {}] Task stopped", socket_id);
        });
    }
}

use smoltcp::socket::icmp;

pub struct IcmpResponder;

impl IcmpResponder {
    pub fn handle(socket: &mut icmp::Socket, timestamp: smoltcp::time::Instant) {
        if !socket.can_recv() {
            return;
        }

        let result = socket.recv(timestamp);

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
