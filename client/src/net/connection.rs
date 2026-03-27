use bytes::{Buf, Bytes, BytesMut};
use netrunner_core::net::network::NetworkConfig;
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    wire::IpEndpoint,
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
// Добавили trace для частых логов (попакетно) и debug для состояний
use netrunner_logger::debug;

// ============================================================================
// 1. БАЗОВАЯ СТРУКТУРА (ConnectionCore)
// ============================================================================

/// Фундамент для любого соединения.
/// Инициализирует и хранит каналы связи между smoltcp и Muxer'ом.
pub struct ConnectionCore<T> {
    pub handle: SocketHandle,
    pub tx: mpsc::Sender<T>,
    pub rx: mpsc::Receiver<Bytes>, // Входящие из туннеля всегда байты
}

impl<T> ConnectionCore<T> {
    pub fn new(
        handle: SocketHandle,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<T>, mpsc::Sender<Bytes>) {
        let (tx_to_net, rx_from_smol) = mpsc::channel::<T>(capacity);
        let (tx_to_smol, rx_from_net) = mpsc::channel::<Bytes>(capacity);

        let core = Self {
            handle,
            tx: tx_to_net,
            rx: rx_from_net,
        };

        (core, rx_from_smol, tx_to_smol)
    }
}
// ============================================================================
// 2. TCP СОЕДИНЕНИЕ (TcpConnection)
// ============================================================================

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
    pending_data: BytesMut,
    handshake_rx: Option<oneshot::Receiver<()>>,
    chunk_buf: Vec<u8>,
    server_eof: bool, // <--- ДОБАВЛЕН ФЛАГ ОКОНЧАНИЯ ПЕРЕДАЧИ
}

impl TcpConnection {
    pub fn new(
        handle: SocketHandle,
    ) -> (
        Self,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<Bytes>,
        oneshot::Sender<()>,
    ) {
        let capacity = NetworkConfig::global().tcp_stream_capacity;
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle, capacity);
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let conn = Self {
            core,
            state: ConnectionState::Handshaking,
            pending_data: BytesMut::new(),
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
                            self.state = ConnectionState::Active;
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

                // Если сокет достиг финальных стадий, убиваем нашу сессию
                if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    debug!(%self.core.handle, "TCP Socket is finished, state -> Closed");
                    self.state = ConnectionState::Closed;
                    return false;
                }
            }

            ConnectionState::Closed => {
                return false;
            }

            _ => {}
        }

        true
    }

    fn poll_and_process(&mut self, socket: &mut tcp::Socket) {
        let max_pending = NetworkConfig::global().tcp_max_pending;

        // 1. Вычитываем данные из smoltcp и шлем в Muxer
        while socket.can_recv() {
            let mut full = false;

            if let Ok(n) = socket.peek_slice(&mut self.chunk_buf) {
                if n == 0 {
                    break;
                }

                let chunk = Bytes::copy_from_slice(&self.chunk_buf[..n]);
                match self.core.tx.try_send(chunk) {
                    Ok(_) => {
                        socket.recv_slice(&mut self.chunk_buf[..n]).unwrap();
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        full = true;
                    }
                    Err(_) => {
                        // Канал Muxer'а закрыт
                        self.server_eof = true;
                        break;
                    }
                }
            } else {
                break;
            }

            if full {
                break;
            }
        }

        // 2. Читаем данные из Muxer'а
        if !self.server_eof {
            loop {
                match self.core.rx.try_recv() {
                    Ok(data) => {
                        self.pending_data.extend_from_slice(&data);
                        if self.pending_data.len() >= max_pending {
                            break;
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // ВАЖНО: Удаленный сервер прислал EOF!
                        debug!(%self.core.handle, "Server sent EOF (channel disconnected).");
                        self.server_eof = true;
                        break;
                    }
                }
            }
        }

        // 3. Пишем данные браузеру
        if !self.pending_data.is_empty() && socket.can_send() {
            match socket.send_slice(&self.pending_data) {
                Ok(n) => {
                    self.pending_data.advance(n);
                }
                Err(e) => {
                    debug!(%self.core.handle, "Smoltcp send error: {:?}", e);
                }
            }
        }

        // 4. ГРАЦИОЗНОЕ ЗАКРЫТИЕ (Отправка FIN браузеру)

        // Сценарий А: Сервер закрыл соединение, и мы отдали все остатки данных браузеру
        if self.server_eof && self.pending_data.is_empty() && socket.may_send() {
            debug!(%self.core.handle, "All data flushed after server EOF, sending FIN to browser");
            socket.close();
        }

        // Сценарий Б: Браузер сам инициировал закрытие (CloseWait), но мы дожидаемся опустошения буфера
        if socket.state() == tcp::State::CloseWait
            && self.pending_data.is_empty()
            && socket.may_send()
        {
            debug!(%self.core.handle, "Browser in CloseWait and buffer flushed, sending FIN");
            socket.close();
        }
    }
}

// ============================================================================
// 3. UDP СОЕДИНЕНИЕ (UdpConnection)
// ============================================================================

const UDP_TIMEOUT: Duration = Duration::from_secs(60);

pub type UdpPacketTarget = (Bytes, std::net::Ipv4Addr, u16);
pub struct UdpConnection {
    core: ConnectionCore<UdpPacketTarget>, // Используем кортеж
    last_client_endpoint: Option<IpEndpoint>,
    last_activity: std::time::Instant,
}

impl UdpConnection {
    pub fn new(
        handle: SocketHandle,
        client_addr: smoltcp::wire::IpAddress,
        client_port: u16,
    ) -> (Self, mpsc::Receiver<UdpPacketTarget>, mpsc::Sender<Bytes>) {
        // Для UDP используем фиксированный буфер 512
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle, 512);

        let conn = Self {
            core,
            last_client_endpoint: Some(IpEndpoint::new(client_addr, client_port)),
            last_activity: std::time::Instant::now(),
        };

        (conn, rx_from_smol, tx_to_smol)
    }
    // Вспомогательный метод для Tracker'а
    pub fn has_client(&self, port: u16) -> bool {
        self.last_client_endpoint
            .map_or(false, |ep| ep.port == port)
    }
    pub fn tick(&mut self, socket: &mut udp::Socket) -> bool {
        if self.last_activity.elapsed() > UDP_TIMEOUT {
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

                    if self.core.tx.try_send(payload).is_ok() {
                        self.last_activity = std::time::Instant::now();
                    }
                }
            }
        }

        // Исходящие из туннеля (от Telegram) — всё еще просто Bytes
        if socket.can_send() {
            if let Some(client_endpoint) = self.last_client_endpoint {
                while let Ok(data) = self.core.rx.try_recv() {
                    let _ = socket.send_slice(&data, client_endpoint);
                    self.last_activity = std::time::Instant::now();
                }
            }
        }
        true
    }
}
