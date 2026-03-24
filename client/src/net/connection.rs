use crate::net::CHANNEL_CAPACITY;
use bytes::{Buf, Bytes, BytesMut};
use smoltcp::{
    iface::SocketHandle,
    socket::{tcp, udp},
    wire::IpEndpoint,
};
use std::time::Duration;
use tokio::{
    sync::{mpsc, oneshot},
    time::Instant,
};

// ============================================================================
// 1. БАЗОВАЯ СТРУКТУРА (ConnectionCore)
// ============================================================================

/// Фундамент для любого соединения.
/// Инициализирует и хранит каналы связи между smoltcp и Muxer'ом.
pub struct ConnectionCore {
    pub handle: SocketHandle,
    pub tx: mpsc::Sender<Bytes>,
    pub rx: mpsc::Receiver<Bytes>,
}

impl ConnectionCore {
    pub fn new(handle: SocketHandle) -> (Self, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>) {
        let (tx_to_net, rx_from_smol) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);
        let (tx_to_smol, rx_from_net) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);

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

pub enum ConnectionState {
    Established,
    Handshaking,
    Active,
    Closed,
}

const MAX_PENDING: usize = 64 * 1024;
const TCP_CHUNK_SIZE: usize = 1024 * 16;

pub struct TcpConnection {
    core: ConnectionCore,
    state: ConnectionState,
    pending_data: BytesMut,
    handshake_rx: Option<oneshot::Receiver<()>>,
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
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle);
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let conn = Self {
            core,
            state: ConnectionState::Handshaking,
            pending_data: BytesMut::new(),
            handshake_rx: Some(handshake_rx),
        };

        (conn, rx_from_smol, tx_to_smol, handshake_tx)
    }

    pub fn is_finished(&self, socket: &tcp::Socket) -> bool {
        matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
    }

    pub fn _is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }

    pub fn tick(&mut self, socket: &mut tcp::Socket) -> bool {
        let state = socket.state();

        match self.state {
            ConnectionState::Handshaking => {
                if let Some(rx) = &mut self.handshake_rx {
                    match rx.try_recv() {
                        Ok(_) => {
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

                if state == tcp::State::CloseWait {
                    socket.close();
                    self.state = ConnectionState::Closed;
                    return false;
                }

                if self.is_finished(socket) {
                    self.state = ConnectionState::Closed;
                    socket.close();
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
        // 1. Вычитываем данные из smoltcp и шлем в Muxer
        while socket.can_recv() {
            let mut full = false;
            let mut temp = [0u8; TCP_CHUNK_SIZE];

            if let Ok(n) = socket.peek_slice(&mut temp) {
                if n == 0 {
                    break;
                }

                let chunk = Bytes::copy_from_slice(&temp[..n]);
                match self.core.tx.try_send(chunk) {
                    Ok(_) => {
                        socket.recv_slice(&mut temp[..n]).unwrap();
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        full = true;
                    }
                    Err(_) => {
                        self.state = ConnectionState::Closed;
                        return;
                    }
                }
            } else {
                break;
            }

            if full {
                break;
            }
        }

        // 2. Читаем данные из Muxer'а с учетом Backpressure
        let current_pending = self.pending_data.len();
        let fill_ratio = (current_pending as f32 / MAX_PENDING as f32) * 100.0;

        if current_pending >= MAX_PENDING {
            netrunner_logger::warn!(
                %self.core.handle,
                "Backpressure ACTIVE: Buffer is FULL ({} bytes). Stalling RX channel.",
                current_pending
            );
        } else if fill_ratio > 80.0 {
            netrunner_logger::info!(
                %self.core.handle,
                "Bufferbloat Warning: Buffer {:.1}% full ({} bytes). Latency increasing.",
                fill_ratio, current_pending
            );

            while let Ok(data) = self.core.rx.try_recv() {
                self.pending_data.extend_from_slice(&data);
                if self.pending_data.len() >= MAX_PENDING {
                    break;
                }
            }
        } else {
            while let Ok(data) = self.core.rx.try_recv() {
                self.pending_data.extend_from_slice(&data);
                if self.pending_data.len() >= MAX_PENDING {
                    break;
                }
            }
        }

        // 3. Отправляем буферизированные данные в smoltcp
        if !self.pending_data.is_empty() && socket.can_send() {
            match socket.send_slice(&self.pending_data) {
                Ok(n) => {
                    self.pending_data.advance(n);

                    if n > 0 && self.pending_data.len() < (MAX_PENDING / 2) && fill_ratio > 90.0 {
                        netrunner_logger::info!(
                            %self.core.handle,
                            "Backpressure RELIEVED: Buffer drained to {} bytes",
                            self.pending_data.len()
                        );
                    }
                }
                Err(e) => {
                    netrunner_logger::debug!(%self.core.handle, "Smoltcp socket send error: {:?}", e);
                }
            }
        }
    }
}

// ============================================================================
// 3. UDP СОЕДИНЕНИЕ (UdpConnection)
// ============================================================================

const UDP_TIMEOUT: Duration = Duration::from_secs(60);

pub struct UdpConnection {
    core: ConnectionCore,
    client_endpoint: Option<IpEndpoint>,
    last_activity: Instant,
}

impl UdpConnection {
    pub fn new(handle: SocketHandle) -> (Self, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>) {
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle);

        let conn = Self {
            core,
            client_endpoint: None,
            last_activity: Instant::now(),
        };

        (conn, rx_from_smol, tx_to_smol)
    }

    pub fn tick(&mut self, socket: &mut udp::Socket) -> bool {
        // Проверка таймаута
        if self.last_activity.elapsed() > UDP_TIMEOUT {
            netrunner_logger::debug!(%self.core.handle, "UDP Session closed due to timeout");
            socket.close();
            return false;
        }

        // Читаем из smoltcp и шлем в сеть
        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv() {
                self.client_endpoint = Some(metadata.endpoint);

                if self.core.tx.try_send(Bytes::copy_from_slice(data)).is_ok() {
                    self.last_activity = Instant::now();
                }
            }
        }

        // Читаем из сети и шлем в smoltcp
        if socket.can_send() {
            if let Some(endpoint) = self.client_endpoint {
                while let Ok(data) = self.core.rx.try_recv() {
                    if data.is_empty() {
                        socket.close();
                        return false;
                    }

                    if socket.send_slice(&data, endpoint).is_ok() {
                        self.last_activity = Instant::now();
                    } else {
                        break;
                    }
                }
            }
        }

        true
    }
}
