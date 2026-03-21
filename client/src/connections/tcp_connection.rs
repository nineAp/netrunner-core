use std::time::Duration;

use bytes::Bytes;
use netrunner_core::protocol::codec::frame::FrameType;
use netrunner_core::protocol::codec::socks::TargetAddress;
use netrunner_core::proxy::connection::BUF_SIZE;
use netrunner_core::proxy::connection::muxer::{MuxMessage, Muxer};
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
    handle: SocketHandle,
    state: ConnectionState,
    // UPLOAD: Ограниченный канал (Bounded) для Backpressure (128)
    tx: mpsc::Sender<Vec<u8>>,
    // DOWNLOAD: Безлимитный канал (Unbounded), чтобы Муксер НИКОГДА не зависал
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pending_data: Vec<u8>,
    handshake_rx: Option<oneshot::Receiver<()>>,
}

const MAX_PENDING: usize = 4 * 1024 * 1024;

impl TcpConnection {
    pub fn new(handle: SocketHandle, target_addr: TargetAddress, muxer: Muxer) -> Self {
        // UPLOAD: Ограничиваем очередь
        let (tx_to_mux, mut rx_from_smol) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);

        // DOWNLOAD: Безлимитный канал до синхронного tick()
        let (tx_to_smol, rx_from_proxy) = mpsc::unbounded_channel::<Vec<u8>>();
        let (handshake_tx, handshake_rx) = oneshot::channel();

        let stream_id = muxer.next_id();

        tokio::spawn(async move {
            // ИСПРАВЛЕНИЕ: Даем Муксеру ограниченный канал, как он и просит (тип mpsc::Sender)
            // Делаем его достаточно вместительным (1024)
            let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(BUF_SIZE);
            muxer.register_stream(stream_id, v_tx);

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
                muxer.remove_stream(stream_id);
                return;
            }

            let first_payload = tokio::time::timeout(Duration::from_secs(10), v_rx.recv()).await;
            match first_payload {
                Ok(Some(data)) => {
                    if data.len() >= 2 && data[1] == 0x00 {
                        let _ = handshake_tx.send(());
                    } else {
                        netrunner_logger::warn!(stream_id, "Server rejected TCP connection");
                        muxer.remove_stream(stream_id);
                        return;
                    }
                }
                _ => {
                    netrunner_logger::error!(stream_id, "Timeout waiting for proxy response");
                    muxer.remove_stream(stream_id);
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

            // МАГИЯ ЗДЕСЬ: Мы мгновенно читаем из ограниченного v_rx и переливаем
            // в безлимитный tx_to_smol. send() у безлимитного канала никогда не блокируется.
            // Поэтому v_rx всегда пустой, и Муксер никогда не зависнет!
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
            muxer.remove_stream(stream_id);
        });

        Self {
            handle,
            state: ConnectionState::Handshaking,
            tx: tx_to_mux,
            rx: rx_from_proxy, // Это UnboundedReceiver, здесь ничего менять не надо
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
        // 1. UPLOAD: Чанкинг и Backpressure (Защита от краша сервера)
        if socket.can_recv() {
            while socket.can_recv() {
                let mut channel_full = false;
                let mut channel_closed = false;

                let _ = socket.recv(|data| {
                    if data.is_empty() {
                        return (0, ());
                    }

                    let chunk_size = std::cmp::min(data.len(), 16000);
                    let chunk = &data[..chunk_size];

                    match self.tx.try_send(chunk.to_vec()) {
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

        // 2. DOWNLOAD: Сброс безлимитного канала в буфер
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

            // Защита от OOM. 32MB более чем достаточно.
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
                    self.pending_data.drain(..n);
                }
                Err(_) => {}
            }
        }
    }
}
