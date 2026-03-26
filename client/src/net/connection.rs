use bytes::{Buf, Bytes, BytesMut};
use netrunner_core::net::network::NetworkConfig;
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
// Добавили trace для частых логов (попакетно) и debug для состояний
use netrunner_logger::{debug, info, trace, warn};

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
        trace!(%handle, "Creating ConnectionCore channels");
        let (tx_to_net, rx_from_smol) =
            mpsc::channel::<Bytes>(NetworkConfig::global().channel_capacity);
        let (tx_to_smol, rx_from_net) =
            mpsc::channel::<Bytes>(NetworkConfig::global().channel_capacity);

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
        debug!(%handle, "Initializing new TCP Connection (State -> Handshaking)");
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

    pub fn tick(&mut self, socket: &mut tcp::Socket) -> bool {
        let state = socket.state();

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
                        Err(oneshot::error::TryRecvError::Empty) => return true, // Ждем
                        Err(oneshot::error::TryRecvError::Closed) => {
                            debug!(%self.core.handle, "TCP Handshake channel dropped/aborted, State -> Closed");
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
                    debug!(%self.core.handle, "TCP Socket reached CloseWait state, closing");
                    socket.close();
                    self.state = ConnectionState::Closed;
                    return false;
                }

                if self.is_finished(socket) {
                    debug!(%self.core.handle, "TCP Socket is finished (Closed/TimeWait), state -> Closed");
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
                        trace!(%self.core.handle, "Forwarded {} bytes from smoltcp to Muxer", n);
                        socket.recv_slice(&mut temp[..n]).unwrap();
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(%self.core.handle, "Muxer TX channel full, backpressure applied to smoltcp read");
                        full = true;
                    }
                    Err(_) => {
                        debug!(%self.core.handle, "Muxer TX channel closed unexpectedly, state -> Closed");
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
            warn!(
                %self.core.handle,
                "Backpressure ACTIVE: Buffer is FULL ({} bytes). Stalling RX channel.",
                current_pending
            );
        } else if fill_ratio > 80.0 {
            info!(
                %self.core.handle,
                "Bufferbloat Warning: Buffer {:.1}% full ({} bytes). Latency increasing.",
                fill_ratio, current_pending
            );

            while let Ok(data) = self.core.rx.try_recv() {
                trace!(%self.core.handle, "Received {} bytes from Muxer (high buffer)", data.len());
                self.pending_data.extend_from_slice(&data);
                if self.pending_data.len() >= MAX_PENDING {
                    break;
                }
            }
        } else {
            while let Ok(data) = self.core.rx.try_recv() {
                trace!(%self.core.handle, "Received {} bytes from Muxer", data.len());
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
                    trace!(%self.core.handle, "Wrote {} bytes from buffer to smoltcp", n);
                    self.pending_data.advance(n);

                    if n > 0 && self.pending_data.len() < (MAX_PENDING / 2) && fill_ratio > 90.0 {
                        info!(
                            %self.core.handle,
                            "Backpressure RELIEVED: Buffer drained to {} bytes",
                            self.pending_data.len()
                        );
                    }
                }
                Err(e) => {
                    debug!(%self.core.handle, "Smoltcp socket send error: {:?}", e);
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
        debug!(%handle, "Initializing new UDP Connection");
        let (core, rx_from_smol, tx_to_smol) = ConnectionCore::new(handle);

        let conn = Self {
            core,
            client_endpoint: None,
            last_activity: Instant::now(),
        };

        (conn, rx_from_smol, tx_to_smol)
    }

    pub fn tick(&mut self, socket: &mut udp::Socket) -> bool {
        if self.last_activity.elapsed() > UDP_TIMEOUT {
            debug!(%self.core.handle, "UDP Session closed due to {}s timeout", UDP_TIMEOUT.as_secs());
            socket.close();
            return false;
        }

        if socket.can_recv() {
            let target_endpoint = socket.endpoint();
            while let Ok((data, metadata)) = socket.recv() {
                let source_endpoint = metadata.endpoint;

                if self.client_endpoint.is_none() {
                    info!(
                        %self.core.handle,
                        source = %source_endpoint,
                        target = %target_endpoint,
                        "UDP Session Established. Pinning endpoint."
                    );
                }
                self.client_endpoint = Some(source_endpoint);

                trace!(
                    %self.core.handle,
                    source = %source_endpoint,
                    target = %target_endpoint,
                    bytes = data.len(),
                    "Forwarded UDP datagram from smoltcp to Muxer"
                );

                if self.core.tx.try_send(Bytes::copy_from_slice(data)).is_ok() {
                    self.last_activity = Instant::now();
                } else {
                    debug!(%self.core.handle, "Muxer TX channel full or closed, dropping UDP datagram");
                }
            }
        }

        if socket.can_send() {
            if let Some(client_endpoint) = self.client_endpoint {
                while let Ok(data) = self.core.rx.try_recv() {
                    if data.is_empty() {
                        debug!(%self.core.handle, "Received empty datagram (Close signal) from Muxer, closing UDP socket");
                        socket.close();
                        return false;
                    }

                    match socket.send_slice(&data, client_endpoint) {
                        Ok(_) => {
                            let proxy_endpoint = socket.endpoint();
                            info!(
                                %self.core.handle,
                                source = %proxy_endpoint,
                                target = %client_endpoint,
                                bytes = data.len(),
                                "Wrote UDP reply from Muxer back to smoltcp"
                            );
                            self.last_activity = Instant::now();
                        }
                        Err(e) => {
                            debug!(%self.core.handle, "Failed to send UDP datagram to smoltcp: {:?}", e);
                            break;
                        }
                    }
                }
            }
        }

        true
    }
}
