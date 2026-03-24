use bytes::{Buf, Bytes, BytesMut};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::sync::{mpsc, oneshot};

use crate::connections::CHANNEL_CAPACITY;

pub enum ConnectionState {
    Established,
    Handshaking,
    Active,
    Closed,
}

pub struct TcpConnection {
    pub handle: SocketHandle,
    state: ConnectionState,
    tx: mpsc::Sender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
    pending_data: BytesMut,
    handshake_rx: Option<oneshot::Receiver<()>>,
}

const MAX_PENDING: usize = 64 * 1024;
const TCP_CHUNK_SIZE: usize = 1024 * 16;

impl TcpConnection {
    pub fn new(
        handle: SocketHandle,
    ) -> (
        Self,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<Bytes>,
        oneshot::Sender<()>,
    ) {
        let (tx_to_net, rx_from_smol) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);
        let (tx_to_smol, rx_from_net) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let conn = Self {
            handle,
            state: ConnectionState::Handshaking,
            tx: tx_to_net,
            rx: rx_from_net,
            pending_data: BytesMut::new(),
            handshake_rx: Some(handshake_rx),
        };

        (conn, rx_from_smol, tx_to_smol, handshake_tx)
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

    pub fn is_finished(&self, socket: &tcp::Socket) -> bool {
        use tcp::State;
        matches!(socket.state(), State::Closed | State::TimeWait)
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }

    fn poll_and_process(&mut self, socket: &mut tcp::Socket) {
        while socket.can_recv() {
            let mut full = false;

            let mut temp = [0u8; TCP_CHUNK_SIZE];

            if let Ok(n) = socket.peek_slice(&mut temp) {
                if n == 0 {
                    break;
                }

                let chunk = Bytes::copy_from_slice(&temp[..n]);
                match self.tx.try_send(chunk) {
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

        let current_pending = self.pending_data.len();

        let fill_ratio = (current_pending as f32 / MAX_PENDING as f32) * 100.0;

        if current_pending >= MAX_PENDING {
            netrunner_logger::warn!(
                %self.handle,
                "Backpressure ACTIVE: Buffer is FULL ({} bytes). Stalling RX channel.",
                current_pending
            );
        } else if fill_ratio > 80.0 {
            netrunner_logger::info!(
                %self.handle,
                "Bufferbloat Warning: Buffer {:.1}% full ({} bytes). Latency increasing.",
                fill_ratio, current_pending
            );

            while let Ok(data) = self.rx.try_recv() {
                self.pending_data.extend_from_slice(&data);
                if self.pending_data.len() >= MAX_PENDING {
                    break;
                }
            }
        } else {
            while let Ok(data) = self.rx.try_recv() {
                self.pending_data.extend_from_slice(&data);
                if self.pending_data.len() >= MAX_PENDING {
                    break;
                }
            }
        }

        if !self.pending_data.is_empty() && socket.can_send() {
            match socket.send_slice(&self.pending_data) {
                Ok(n) => {
                    self.pending_data.advance(n);

                    if n > 0 && self.pending_data.len() < (MAX_PENDING / 2) && fill_ratio > 90.0 {
                        netrunner_logger::info!(%self.handle, "Backpressure RELIEVED: Buffer drained to {} bytes", self.pending_data.len());
                    }
                }
                Err(e) => {
                    netrunner_logger::debug!(%self.handle, "Smoltcp socket send error: {:?}", e);
                }
            }
        }
    }
}
