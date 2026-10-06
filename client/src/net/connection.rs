//! Виртуальные соединения клиента: мост между smoltcp-сокетом и туннелем.
//!
//! Каждое перехваченное приложение-соединение представлено одним из типов:
//! [`TcpConnection`], [`UdpConnection`] или ответчиком [`IcmpResponder`]. Они
//! живут в синхронном цикле стека (`tick`), но общаются с асинхронным туннелем
//! через каналы (`ConnectionCore`): локальный сокет ⇄ канал ⇄ задача `spawn` ⇄
//! [`RawCastFrame`] ⇄ туннель.
//!
//! Главное в [`TcpConnection`] — управление потоком без bufferbloat:
//! - **upload** (браузер→туннель): читаем из smoltcp, пока есть место в канале;
//!   переполнение канала ставит флаг `tx_congested` → перестаём читать → срабатывает
//!   TCP backpressure к приложению;
//! - **download** (туннель→браузер): держим максимум ОДИН `pending_chunk`; если
//!   tx-буфер smoltcp полон — придерживаем чанк и поднимаем `is_saturated`;
//! - **RTT-проброс** в smoltcp (`set_tunnel_rtt`/AQM) для BBR — с потолком, чтобы
//!   рост RTT не раздувал очередь по положительной обратной связи.

use bytes::Bytes;
use netrunner_core::{
    net::{CreditReceiver, GLOBAL_MIN_RTT, NetworkConfig, UDP_IDLE_TIMEOUT},
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
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use netrunner_logger::{debug, info, instrument};

/// Общая «обвязка каналов» соединения: хендл сокета + два встречных канала +
/// флаг насыщения tx-буфера. Параметр `T` — тип исходящего сообщения (для TCP
/// это [`Bytes`], для UDP — кортеж с адресом).
pub struct ConnectionCore<T> {
    pub handle: SocketHandle,
    /// Канал «локальный сокет → туннель».
    pub tx: mpsc::Sender<T>,
    /// Канал «туннель → локальный сокет».
    pub rx: mpsc::Receiver<Bytes>,
    /// Полон ли tx-буфер smoltcp (сигнал backpressure для download).
    pub is_saturated: Arc<AtomicBool>,
}

impl<T> ConnectionCore<T> {
    pub fn new(
        handle: SocketHandle,
    ) -> (
        Self,
        mpsc::Receiver<T>,
        mpsc::Sender<Bytes>,
        Arc<AtomicBool>,
    ) {
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

/// Стадия жизненного цикла виртуального TCP-соединения.
#[derive(Debug, PartialEq)]
pub enum ConnectionState {
    /// Туннель подтвердил установку — можно переходить к Active.
    Established,
    /// Ждём подтверждения от туннеля (CONNECT отправлен).
    Handshaking,
    /// Рабочее состояние: качаем данные в обе стороны.
    Active,
    /// Закрыто.
    Closed,
}

/// Виртуальное TCP-соединение: один smoltcp tcp-сокет ↔ один поток туннеля.
pub struct TcpConnection {
    core: ConnectionCore<Bytes>,
    state: ConnectionState,
    /// A single in-flight chunk that partially fit into smoltcp's tx_buf.
    /// When Some, we retry flushing it before reading the next chunk from core.rx.
    pending_chunk: Option<Bytes>,
    handshake_rx: Option<oneshot::Receiver<()>>,
    chunk_buf: Vec<u8>,
    server_eof: bool,
    permit: Option<OwnedSemaphorePermit>,

    total_up_bytes: u64,
    total_down_bytes: u64,
    tx_congested: bool,
    last_rtt_push_ms: i64,
    last_pushed_rtt_ms: u32,
    /// Snapshot of (up+down) bytes at the previous had_io() call, used to detect
    /// real data movement so the socket's LRU/idle timestamp is refreshed only
    /// when the connection is genuinely active.
    last_io_total: u64,
    /// Receiver side of the stream's end-to-end flow control: tells the server how
    /// many download bytes it may still send, as the app actually takes them.
    credit: CreditReceiver,
    /// Where grants go (the bridge task) and what identifies this socket there.
    credit_tx: mpsc::Sender<RawCastFrame>,
    credit_dst: (u64, std::net::Ipv4Addr, u16),
    /// Newest grant that did not fit into `credit_tx` yet. Grants are absolute
    /// limits, so only the latest one ever needs to be kept.
    pending_grant: Option<u32>,
}

impl TcpConnection {
    const RTT_PUSH_INTERVAL_MS: i64 = 50;
    const RTT_CHANGE_RATIO: f64 = 0.10;
    /// Hard ceiling (ms) on the AQM sojourn budget. Stops the bufferbloat
    /// feedback loop where a higher RTT was granted an ever-larger queue.
    const AQM_MAX_AGE_CEILING_MS: u64 = 300;

    pub fn new(
        handle: SocketHandle,
        permit: OwnedSemaphorePermit,
        credit_tx: mpsc::Sender<RawCastFrame>,
        socket_id: u64,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
    ) -> (
        Self,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<Bytes>,
        oneshot::Sender<()>,
        Arc<AtomicBool>,
    ) {
        let (core, rx_from_smol, tx_to_smol, is_saturated) = ConnectionCore::new(handle);
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let conn = Self {
            core,
            state: ConnectionState::Handshaking,
            permit: Some(permit),
            pending_chunk: None,
            handshake_rx: Some(handshake_rx),
            chunk_buf: vec![0u8; NetworkConfig::global().tcp_chunk_size],
            server_eof: false,
            total_up_bytes: 0,
            total_down_bytes: 0,
            tx_congested: false,
            last_rtt_push_ms: i64::MIN,
            last_pushed_rtt_ms: 0,
            last_io_total: 0,
            credit: CreditReceiver::new(),
            credit_tx,
            credit_dst: (socket_id, dst_ip, dst_port),
            pending_grant: None,
        };

        (conn, rx_from_smol, tx_to_smol, handshake_tx, is_saturated)
    }

    /// True if this connection moved any bytes since the previous call. The
    /// socket manager uses it to refresh the LRU/idle timestamp, so a connection
    /// that is actively transferring is NEVER mistaken for idle and reaped.
    /// (Previously `last_activity` was frozen at creation, so both the 120 s idle
    /// sweep and the MAX_SOCKETS LRU eviction killed long-lived ACTIVE
    /// connections — e.g. a big download — once enough sockets churned.)
    pub fn had_io(&mut self) -> bool {
        let total = self.total_up_bytes.wrapping_add(self.total_down_bytes);
        let moved = total != self.last_io_total;
        self.last_io_total = total;
        moved
    }

    /// Один шаг конечного автомата соединения внутри poll-цикла стека.
    ///
    /// Прогоняет состояние (Handshaking→Established→Active→Closed) и в активной
    /// фазе качает данные через [`poll_and_process`](TcpConnection::poll_and_process).
    /// Возвращает `false`, когда соединение закрылось и его пора убирать.
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

            ConnectionState::Closed => return false,

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

    fn maybe_update_tunnel_rtt(
        &mut self,
        socket: &mut tcp::Socket,
        timestamp: smoltcp::time::Instant,
    ) {
        let now_ms = timestamp.total_millis();

        if self.last_rtt_push_ms != i64::MIN
            && now_ms - self.last_rtt_push_ms < Self::RTT_PUSH_INTERVAL_MS
        {
            return;
        }

        let current_rtt = GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        if current_rtt == 0 {
            return;
        }

        let first_push = self.last_rtt_push_ms == i64::MIN;
        let changed_enough = if self.last_pushed_rtt_ms == 0 {
            true
        } else {
            let prev = self.last_pushed_rtt_ms as f64;
            let diff = (current_rtt as f64 - prev).abs();
            diff / prev >= Self::RTT_CHANGE_RATIO
        };

        if first_push || changed_enough {
            socket.set_tunnel_rtt(smoltcp::time::Duration::from_millis(current_rtt as u64));
            // Bound the AQM sojourn budget. Was rtt*2 — positive-feedback
            // bufferbloat: higher RTT → bigger allowed queue → even higher RTT
            // (download RTT blew past 1.3 s under speedtest). Cap it so download
            // queueing delay / jitter stay bounded; only tightens at high RTT.
            let aqm_age = (current_rtt as u64 * 2).clamp(50, Self::AQM_MAX_AGE_CEILING_MS);
            socket.set_aqm_max_age(aqm_age);
            self.last_pushed_rtt_ms = current_rtt;
            self.last_rtt_push_ms = now_ms;
            debug!(%self.core.handle, "BBR RTT: {} ms", current_rtt);
        } else {
            self.last_rtt_push_ms = now_ms;
        }
    }

    /// Прокачивает данные в обе стороны за один тик (см. обзор модуля: upload с
    /// `tx_congested`-паузой и download с одним `pending_chunk` + `is_saturated`).
    /// В конце, если выгрузка завершена и буфер пуст, шлёт FIN приложению.
    fn poll_and_process(&mut self, socket: &mut tcp::Socket, timestamp: smoltcp::time::Instant) {
        self.maybe_update_tunnel_rtt(socket, timestamp);

        // ── Upload: browser → smoltcp rx_buf → channel → muxer ──────────
        while socket.can_recv() && self.core.tx.capacity() > 0 {
            if let Ok(n) = socket.peek_slice(&mut self.chunk_buf, timestamp) {
                if n == 0 {
                    break;
                }
                let chunk = Bytes::copy_from_slice(&self.chunk_buf[..n]);
                match self.core.tx.try_send(chunk) {
                    Ok(_) => {
                        socket.recv_slice(&mut self.chunk_buf[..n]).unwrap();
                        self.total_up_bytes += n as u64;
                        if self.tx_congested {
                            netrunner_logger::debug!(
                                %self.core.handle,
                                "🟢 Upload channel cleared. Resuming read from browser."
                            );
                            self.tx_congested = false;
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        if !self.tx_congested {
                            netrunner_logger::debug!(
                                %self.core.handle,
                                "🟡 Upload Congestion: Channel to Muxer is full. Pausing."
                            );
                            self.tx_congested = true;
                        }
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.server_eof = true;
                        break;
                    }
                }
            } else {
                break;
            }
        }

        // ── Download: muxer → channel → smoltcp tx_buf → browser ─────────
        //
        // We keep at most ONE in-flight chunk (pending_chunk). When smoltcp's
        // tx_buf is full we stop reading from core.rx, which naturally
        // backpressures the bounded channel and eventually the muxer.
        if !self.server_eof {
            loop {
                // First flush any partially-sent chunk from a previous tick.
                let chunk = match self.pending_chunk.take() {
                    Some(c) => c,
                    None => match self.core.rx.try_recv() {
                        Ok(data) => {
                            self.total_down_bytes += data.len() as u64;
                            data
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            self.server_eof = true;
                            break;
                        }
                    },
                };

                if !socket.can_send() {
                    // tx_buf is full → hold the chunk, signal saturation.
                    self.pending_chunk = Some(chunk);
                    self.core.is_saturated.store(true, Ordering::Release);
                    break;
                }

                match socket.send_slice(&chunk) {
                    Ok(n) if n == chunk.len() => {
                        // Entire chunk accepted.
                        self.on_download_consumed(n);
                    }
                    Ok(n) => {
                        // Partial write — keep the remainder for the next tick.
                        self.on_download_consumed(n);
                        self.pending_chunk = Some(chunk.slice(n..));
                        break;
                    }
                    Err(e) => {
                        netrunner_logger::debug!(
                            %self.core.handle,
                            "smoltcp send error: {:?}", e
                        );
                        self.pending_chunk = Some(chunk);
                        break;
                    }
                }
            }

            // Clear saturation when tx_buf has room and no chunk is pending.
            if self.pending_chunk.is_none() && socket.can_send() {
                self.core.is_saturated.store(false, Ordering::Release);
            }
        }

        self.flush_pending_grant();

        if self.server_eof && self.pending_chunk.is_none() {
            let state = socket.state();
            if state == tcp::State::Established || state == tcp::State::CloseWait {
                netrunner_logger::debug!(
                    %self.core.handle,
                    "All data flushed, sending FIN to browser"
                );
                socket.close();
            }
        }
    }

    /// `n` download bytes were handed to the app-facing socket. This — the app taking
    /// the data, not its arrival from the tunnel — is what frees the sender's window.
    fn on_download_consumed(&mut self, n: usize) {
        let rtt_ms = GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        let rtt = std::time::Duration::from_millis(if rtt_ms == 0 { 100 } else { rtt_ms as u64 });
        if let Some(offset) = self
            .credit
            .on_consumed(n, std::time::Instant::now(), rtt)
        {
            self.pending_grant = Some(offset);
        }
        self.flush_pending_grant();
    }

    /// Hands the newest grant to the bridge if the channel has room; otherwise it
    /// stays pending and is retried on the next tick.
    fn flush_pending_grant(&mut self) {
        let Some(offset) = self.pending_grant else {
            return;
        };
        let (socket_id, ip, port) = self.credit_dst;
        let frame = RawCastFrame::credit(LocalProtocol::Tcp, socket_id, ip, port, offset);
        match self.credit_tx.try_send(frame) {
            Ok(()) => self.pending_grant = None,
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => self.pending_grant = None,
        }
    }

    pub fn app_pending_out_size(&self) -> usize {
        self.pending_chunk.as_ref().map(|c| c.len()).unwrap_or(0)
    }

    /// Запускает асинхронную задачу-«насос» соединения.
    ///
    /// Шлёт в туннель `Connect` (с целью в payload), сигналит хендшейк, затем в
    /// цикле гонит данные из smoltcp-канала в туннель `Data`-кадрами, а на выходе
    /// отправляет `Close`. Связывает синхронный сокет с асинхронным туннелем.
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

            // First credit grant, right behind the Connect: from here on the server limits
            // what it pushes to what this socket actually consumes (see `net::credit`).
            let initial_grant = RawCastFrame::credit(
                LocalProtocol::Tcp,
                socket_id,
                dst_ip,
                dst_port,
                CreditReceiver::initial_offset(),
            );
            let _ = tx_tunnel.send(initial_grant).await;

            let _ = handshake_tx.send(());

            while let Some(data) = rx_smol.recv().await {
                let data_frame =
                    RawCastFrame::data(LocalProtocol::Tcp, socket_id, dst_ip, dst_port, data);
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

// ─── UDP ────────────────────────────────────────────────────────────────────

/// UDP-датаграмма с адресом назначения: `(данные, ip, port)`.
pub type UdpPacketTarget = (Bytes, std::net::Ipv4Addr, u16);

/// Виртуальное UDP-«соединение» (NAT-запись): smoltcp udp-сокет ↔ поток туннеля.
pub struct UdpConnection {
    core: ConnectionCore<UdpPacketTarget>,
    /// Последний известный endpoint клиента (куда возвращать ответы).
    last_client_endpoint: Option<IpEndpoint>,
    /// Время последней активности (для idle-таймаута).
    last_activity: std::time::Instant,
}

impl UdpConnection {
    pub fn new(
        handle: SocketHandle,
        client_addr: IpAddress,
        client_port: u16,
    ) -> (
        Self,
        mpsc::Receiver<UdpPacketTarget>,
        mpsc::Sender<Bytes>,
        Arc<AtomicBool>,
    ) {
        let (core, rx_from_smol, tx_to_smol, is_saturated) = ConnectionCore::new(handle);
        let conn = Self {
            core,
            last_client_endpoint: Some(IpEndpoint::new(client_addr, client_port)),
            last_activity: std::time::Instant::now(),
        };
        (conn, rx_from_smol, tx_to_smol, is_saturated)
    }

    pub fn has_client(&self, port: u16) -> bool {
        self.last_client_endpoint.is_some_and(|ep| ep.port == port)
    }

    pub fn tick(&mut self, socket: &mut udp::Socket, timestamp: smoltcp::time::Instant) -> bool {
        if self.last_activity.elapsed() > UDP_IDLE_TIMEOUT {
            socket.close();
            return false;
        }

        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv(timestamp) {
                if let IpAddress::Ipv4(ip) = metadata.endpoint.addr {
                    self.last_client_endpoint = Some(metadata.endpoint);
                    let target_ip = ip;
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
                let data_frame = RawCastFrame::data(LocalProtocol::Udp, socket_id, ip, port, data);
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

// ─── ICMP ───────────────────────────────────────────────────────────────────

use smoltcp::socket::icmp;

/// Отвечает на ICMP Echo (ping) локально, не гоняя его через туннель.
pub struct IcmpResponder;

impl IcmpResponder {
    /// Принимает ICMP-пакет; на Echo Request формирует Echo Reply (v4/v6) с
    /// пересчётом контрольной суммы и отправляет обратно источнику.
    pub fn handle(socket: &mut icmp::Socket, timestamp: smoltcp::time::Instant) {
        if !socket.can_recv() {
            return;
        }

        if let Ok((data, src_addr)) = socket.recv(timestamp) {
            let payload = data.to_vec();
            match src_addr {
                IpAddress::Ipv4(_) => Self::reply_v4(socket, payload, src_addr),
                IpAddress::Ipv6(v6) => Self::reply_v6(socket, payload, v6),
            }
        }
    }

    fn reply_v4(socket: &mut icmp::Socket, mut payload: Vec<u8>, src: IpAddress) {
        if let Ok(pkt) = Icmpv4Packet::new_checked(&payload)
            && pkt.msg_type() == Icmpv4Message::EchoRequest
        {
            let mut reply_pkt = Icmpv4Packet::new_unchecked(&mut payload);
            reply_pkt.set_msg_type(Icmpv4Message::EchoReply);
            reply_pkt.fill_checksum();
            let _ = socket.send_slice(&payload, src);
            info!("🏓 [ICMPv4] Echo Reply -> {}", src);
        }
    }

    fn reply_v6(socket: &mut icmp::Socket, mut payload: Vec<u8>, src: Ipv6Address) {
        if let Ok(pkt) = Icmpv6Packet::new_checked(&payload)
            && pkt.msg_type() == Icmpv6Message::EchoRequest
        {
            let mut reply_pkt = Icmpv6Packet::new_unchecked(&mut payload);
            reply_pkt.set_msg_type(Icmpv6Message::EchoReply);
            let gateway = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            reply_pkt.fill_checksum(&gateway, &src);
            let _ = socket.send_slice(&payload, src.into());
            info!("🏓 [ICMPv6] Echo Reply -> {}", src);
        }
    }
}
