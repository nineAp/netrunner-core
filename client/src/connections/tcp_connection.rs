use bytes::{Buf, Bytes, BytesMut};
use netrunner_core::proxy::connection::TCP_BUF_SIZE;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::sync::{mpsc, oneshot};

pub enum ConnectionState {
    Established,
    Handshaking,
    Active,
    Closed,
}

pub struct TcpConnection {
    pub handle: SocketHandle,
    state: ConnectionState,
    // UPLOAD: Ограниченный канал для передачи данных наружу
    tx: mpsc::Sender<Bytes>,
    // DOWNLOAD: Канал для приема данных из сети
    rx: mpsc::Receiver<Bytes>,
    pending_data: BytesMut,
    handshake_rx: Option<oneshot::Receiver<()>>,
}

const MAX_PENDING: usize = 32 * 512 * 1024;
const TCP_CHUNK_SIZE: usize = 65536;

impl TcpConnection {
    pub fn new(
        handle: SocketHandle,
    ) -> (
        Self,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<Bytes>,
        oneshot::Sender<()>,
    ) {
        let (tx_to_net, rx_from_smol) = mpsc::channel::<Bytes>(TCP_BUF_SIZE);
        let (tx_to_smol, rx_from_net) = mpsc::channel::<Bytes>(TCP_BUF_SIZE);
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
        // 1. UPLOAD: Чанкинг и Backpressure
        if socket.can_recv() {
            while socket.can_recv() {
                let mut channel_full = false;
                let mut channel_closed = false;

                let _ = socket.recv(|data| {
                    if data.is_empty() {
                        return (0, ());
                    }

                    let chunk_size = std::cmp::min(data.len(), TCP_CHUNK_SIZE);
                    let chunk = &data[..chunk_size];

                    match self.tx.try_send(Bytes::copy_from_slice(chunk)) {
                        Ok(_) => (chunk_size, ()),
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            channel_full = true;
                            (0, ()) // Оставляем данные в smoltcp
                        }
                        Err(_) => {
                            channel_closed = true;
                            (0, ())
                        }
                    }
                });

                if channel_full || channel_closed {
                    break;
                }
            }
        }

        // 2. DOWNLOAD: Сброс ограниченного канала в буфер
        while let Ok(data) = self.rx.try_recv() {
            if self.pending_data.is_empty() && socket.can_send() {
                match socket.send_slice(&data) {
                    Ok(n) if n < data.len() => {
                        self.pending_data.extend_from_slice(&data[n..]);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        self.pending_data.extend_from_slice(&data);
                    }
                }
            } else {
                self.pending_data.extend_from_slice(&data);
            }

            if self.pending_data.len() > MAX_PENDING {
                netrunner_logger::error!(
                    %self.handle,
                    "TCP Buffer overflow ({} bytes). Dropping connection.",
                    self.pending_data.len()
                );
                socket.abort();
                self.state = ConnectionState::Closed;
                return;
            }
        }

        // 3. DOWNLOAD: Отправка буфера в smoltcp
        if !self.pending_data.is_empty() && socket.can_send() {
            match socket.send_slice(&self.pending_data) {
                Ok(n) => {
                    self.pending_data.advance(n);
                }
                Err(_) => {}
            }
        }
    }
}
