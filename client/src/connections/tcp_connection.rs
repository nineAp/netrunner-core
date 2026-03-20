use std::time::Duration;

use bytes::Bytes;
use netrunner_core::protocol::codec::frame::FrameType;
use netrunner_core::protocol::codec::socks::TargetAddress;
use netrunner_core::proxy::connection::muxer::{MuxMessage, Muxer};
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
    handle: SocketHandle,
    state: ConnectionState,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pending_data: Vec<u8>,
    handshake_rx: Option<oneshot::Receiver<()>>,
}

const MAX_PENDING: usize = 2 * 1024 * 1024;

impl TcpConnection {
    pub fn new(handle: SocketHandle, target_addr: TargetAddress, muxer: Muxer) -> Self {
        let (tx_to_mux, mut rx_from_smol) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_to_smol, rx_from_proxy) = mpsc::unbounded_channel::<Vec<u8>>();
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let stream_id = muxer.next_id();

        tokio::spawn(async move {
            let (v_tx, mut v_rx) = mpsc::channel(1024);
            muxer.register_stream(stream_id, v_tx).await;

            let connect_payload = target_addr.to_string();
            if muxer
                .send_to_netwrok(MuxMessage {
                    stream_id,
                    frame_type: FrameType::Connect,
                    data: Bytes::from(connect_payload),
                })
                .await
                .is_err()
            {
                muxer.remove_stream(stream_id).await;
                return;
            }

            let first_payload = tokio::time::timeout(Duration::from_secs(10), v_rx.recv()).await;
            match first_payload {
                Ok(Some(data)) => {
                    if data.len() >= 2 && data[1] == 0x00 {
                        let _ = handshake_tx.send(());
                    } else {
                        netrunner_logger::warn!(stream_id, "Server rejected TCP connection");
                        muxer.remove_stream(stream_id).await;
                        return;
                    }
                }
                _ => {
                    netrunner_logger::error!(stream_id, "Timeout waiting for proxy response");
                    muxer.remove_stream(stream_id).await;
                    return;
                }
            }

            let to_proxy = async {
                while let Some(data) = rx_from_smol.recv().await {
                    let msg = MuxMessage {
                        stream_id,
                        frame_type: FrameType::Data,
                        data: Bytes::from(data),
                    };
                    if muxer.send_to_netwrok(msg).await.is_err() {
                        break;
                    }
                }
            };

            let from_proxy = async {
                while let Some(data) = v_rx.recv().await {
                    if data.is_empty() {
                        break;
                    }
                    if tx_to_smol.send(data.to_vec()).is_err() {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = to_proxy => {}
                _ = from_proxy => {}
            }

            let _ = muxer
                .send_to_netwrok(MuxMessage {
                    stream_id,
                    frame_type: FrameType::Close,
                    data: Bytes::new(),
                })
                .await;
            muxer.remove_stream(stream_id).await;
        });

        Self {
            handle,
            state: ConnectionState::Handshaking,
            tx: tx_to_mux,
            rx: rx_from_proxy,
            pending_data: vec![],
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
            let mut total_read = 0;
            let _ = socket.recv(|data| {
                if !data.is_empty() {
                    if self.tx.send(data.to_vec()).is_ok() {
                        total_read = data.len();
                    }
                }
                (total_read, ())
            });
        }

        if self.pending_data.len() > MAX_PENDING {
            netrunner_logger::error!(%self.handle, "TCP Buffer overflow ({} bytes). Dropping connection.", self.pending_data.len());
            socket.abort();
            self.state = ConnectionState::Closed;
            return;
        }

        if !self.pending_data.is_empty() && socket.can_send() {
            match socket.send_slice(&self.pending_data) {
                Ok(n) => {
                    self.pending_data.drain(..n);
                }
                Err(_) => {}
            }
        }

        if self.pending_data.is_empty() && socket.can_send() {
            if let Ok(data) = self.rx.try_recv() {
                match socket.send_slice(&data) {
                    Ok(n) if n < data.len() => {
                        self.pending_data.extend_from_slice(&data[n..]);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        self.pending_data = data;
                    }
                }
            }
        }
    }
}
