use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use bytes::Bytes;
use netrunner_core::{
    protocol::codec::{frame::FrameType, socks::TargetAddress},
    proxy::connection::muxer::{MuxMessage, Muxer},
};

use crate::connections::CHANNEL_CAPACITY;

pub struct UdpConnection {
    pub handle: SocketHandle,
    stream_id: u32,
    tx_to_net: mpsc::Sender<MuxMessage>,
    rx_from_net: mpsc::UnboundedReceiver<Bytes>, // <-- ТУТ
    client_endpoint: Option<IpEndpoint>,
    last_activity: Instant,
    token: CancellationToken,
}

const UDP_TIMEOUT: Duration = Duration::from_secs(60);

impl UdpConnection {
    pub fn new(handle: SocketHandle, target_addr: TargetAddress, muxer: Muxer) -> Self {
        let stream_id = muxer.next_id();
        let token = CancellationToken::new();
        let task_token = token.clone();

        let (tx_to_net, mut rx_from_smol) = mpsc::channel::<MuxMessage>(CHANNEL_CAPACITY);

        // ИСПРАВЛЕНИЕ: Внутренний безлимитный канал
        let (internal_tx, internal_rx) = mpsc::unbounded_channel::<Bytes>();

        let m_clone = muxer.clone();

        tokio::spawn(async move {
            // Даем Муксеру ограниченный канал (тип Sender), чтобы компилятор пропустил
            let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(1024);
            m_clone.register_stream(stream_id, v_tx).await;

            let _ = m_clone
                .send_to_netwrok(MuxMessage {
                    stream_id,
                    frame_type: FrameType::UdpConnect,
                    data: Bytes::from(target_addr.to_string()),
                })
                .await;

            let to_proxy = async {
                while let Some(msg) = rx_from_smol.recv().await {
                    if m_clone.send_to_netwrok(msg).await.is_err() {
                        break;
                    }
                }
            };

            // Мгновенно выкачиваем данные из Муксера в безлимитный внутренний канал
            let from_proxy = async {
                while let Some(data) = v_rx.recv().await {
                    if internal_tx.send(data).is_err() {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = to_proxy => {}
                _ = from_proxy => {} // Не забудь добавить этот блок в select!
                _ = task_token.cancelled() => {}
            }

            let _ = m_clone
                .send_to_netwrok(MuxMessage {
                    stream_id,
                    frame_type: FrameType::Close,
                    data: Bytes::new(),
                })
                .await;
            m_clone.remove_stream(stream_id).await;
        });

        Self {
            handle,
            stream_id,
            tx_to_net,
            rx_from_net: internal_rx, // Сохраняем безлимитный ресивер
            client_endpoint: None,
            last_activity: Instant::now(),
            token,
        }
    }

    pub fn tick(&mut self, socket: &mut udp::Socket) -> bool {
        if self.last_activity.elapsed() > UDP_TIMEOUT {
            netrunner_logger::debug!(%self.handle, "UDP Session closed due to timeout");
            self.token.cancel();
            socket.close();
            return false;
        }

        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv() {
                self.client_endpoint = Some(metadata.endpoint);

                let msg = MuxMessage {
                    stream_id: self.stream_id,
                    frame_type: FrameType::UdpData,
                    data: Bytes::copy_from_slice(data),
                };

                if self.tx_to_net.try_send(msg).is_ok() {
                    self.last_activity = Instant::now();
                }
            }
        }

        if socket.can_send() {
            if let Some(endpoint) = self.client_endpoint {
                while let Ok(data) = self.rx_from_net.try_recv() {
                    if data.is_empty() {
                        self.token.cancel();
                        break;
                    }

                    match socket.send_slice(&data, endpoint) {
                        Ok(_) => {
                            self.last_activity = Instant::now();
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
        }

        true
    }
}
