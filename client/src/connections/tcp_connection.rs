use netrunner_core::protocol::codec::socks::{SocksRequest, TargetAddress};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub enum ConnectionState {
    Established,
    Handshaking,
    Active,
    Closed,
}

pub struct TcpConnection {
    handle: SocketHandle,
    state: ConnectionState,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pending_data: Vec<u8>,
    token: CancellationToken,
    handshake_rx: Option<oneshot::Receiver<()>>,
}

const MAX_PENDING: usize = 256 * 1024;

impl TcpConnection {
    pub fn new(handle: SocketHandle, proxy_addr: String, target_addr: TargetAddress) -> Self {
        let (tx_to_proxy, mut rx_from_smol) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_to_smol, rx_from_proxy) = mpsc::unbounded_channel::<Vec<u8>>();
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let token = CancellationToken::new();
        let task_token = token.clone();

        tokio::spawn(async move {
            let mut stream = match TcpStream::connect(&proxy_addr).await {
                Ok(s) => {
                    netrunner_logger::debug!(%handle, "Connected to proxy successfully");
                    s
                }
                Err(e) => {
                    netrunner_logger::debug!(%handle, error = %e, "Failed to connect to proxy");
                    return;
                }
            };

            if let Err(e) = SocksRequest::perform_client_handshake(&mut stream, &target_addr).await
            {
                netrunner_logger::debug!(%handle, error = %e, "SOCKS handshake failed");
                return;
            }

            let _ = handshake_tx.send(());

            netrunner_logger::debug!(%handle, "SOCKS handshake successful, starting data bridge");

            let (mut reader, mut writer) = stream.into_split();

            let to_proxy = async {
                while let Some(data) = rx_from_smol.recv().await {
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
            };

            let from_proxy = async {
                let mut buf = [0u8; 65536];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx_to_smol.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            };

            tokio::select! {
                _ = to_proxy => {}
                _ = from_proxy => {}
                _ = task_token.cancelled() => { netrunner_logger::debug!(%handle, "Task cancelled by Manager"); }
            }
        });

        Self {
            handle,
            state: ConnectionState::Active,
            tx: tx_to_proxy,
            rx: rx_from_proxy,
            pending_data: vec![],
            token,
            handshake_rx: Some(handshake_rx),
        }
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
        if socket.can_recv() {
            let _ = socket.recv(|data| {
                let len = data.len();
                if len > 0 {
                    let _ = self.tx.send(data.to_vec());
                }
                (len, ())
            });
        }

        if !self.pending_data.is_empty() {
            if self.pending_data.len() > MAX_PENDING {
                netrunner_logger::warn!(%self.handle, "Buffer overflow! Aborting connection.");
                socket.abort();
                self.token.cancel();
                return;
            }

            match socket.send_slice(&self.pending_data) {
                Ok(n) => {
                    self.pending_data.drain(0..n);
                }
                Err(_) => {}
            }
        }

        if socket.can_send() {
            while let Ok(data) = self.rx.try_recv() {
                match socket.send_slice(&data) {
                    Ok(n) if n < data.len() => {
                        self.pending_data = data[n..].to_vec();
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        self.pending_data = data;
                        break;
                    }
                }
            }
        }
    }
}
