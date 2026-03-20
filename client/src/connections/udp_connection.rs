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

pub struct UdpConnection {
    pub handle: SocketHandle,
    stream_id: u32,
    tx_to_net: mpsc::Sender<MuxMessage>, // Прямой канал кадров
    rx_from_net: mpsc::Receiver<Bytes>,  // Прямое чтение из муксера
    client_endpoint: Option<IpEndpoint>,
    last_activity: Instant,
    token: CancellationToken,
}

const UDP_TIMEOUT: Duration = Duration::from_secs(60);
// Ограничиваем очередь: для UDP дроп пакета при перегрузке — это норма
const CHANNEL_CAPACITY: usize = 1024;

impl UdpConnection {
    pub fn new(handle: SocketHandle, target_addr: TargetAddress, muxer: Muxer) -> Self {
        let stream_id = muxer.next_id();
        let token = CancellationToken::new();
        let task_token = token.clone();

        // Канал из tick в асинхронную таску (сразу в формате MuxMessage)
        let (tx_to_net, mut rx_from_smol) = mpsc::channel::<MuxMessage>(CHANNEL_CAPACITY);

        // Канал из муксера напрямую в tick
        let (v_tx, v_rx) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);

        let m_clone = muxer.clone();

        tokio::spawn(async move {
            m_clone.register_stream(stream_id, v_tx).await;

            // 1. Устанавливаем соединение
            let _ = m_clone
                .send_to_netwrok(MuxMessage {
                    stream_id,
                    frame_type: FrameType::UdpConnect,
                    data: Bytes::from(target_addr.to_string()),
                })
                .await;

            // 2. Слушаем только один канал (на отправку в сеть)
            let to_proxy = async {
                while let Some(msg) = rx_from_smol.recv().await {
                    if m_clone.send_to_netwrok(msg).await.is_err() {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = to_proxy => {}
                _ = task_token.cancelled() => {}
            }

            // 3. Закрываем стрим
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
            rx_from_net: v_rx, // Сохраняем Receiver напрямую
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

        // 1. Читаем из TUN (приложение -> прокси)
        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv() {
                self.client_endpoint = Some(metadata.endpoint);

                // Избегаем двойной аллокации, сразу копируем в Bytes
                let msg = MuxMessage {
                    stream_id: self.stream_id,
                    frame_type: FrameType::UdpData,
                    data: Bytes::copy_from_slice(data),
                };

                // try_send не блокирует цикл. Если буфер забит - пакет отбрасывается.
                // QUIC мгновенно поймет потерю и адаптирует битрейт видео.
                if self.tx_to_net.try_send(msg).is_ok() {
                    self.last_activity = Instant::now();
                }
            }
        }

        // 2. Пишем в TUN (прокси -> приложение)
        if socket.can_send() {
            if let Some(endpoint) = self.client_endpoint {
                // Читаем напрямую из канала муксера, минуя промежуточные таски
                while let Ok(data) = self.rx_from_net.try_recv() {
                    if data.is_empty() {
                        self.token.cancel(); // Сервер прислал сигнал закрытия
                        break;
                    }

                    match socket.send_slice(&data, endpoint) {
                        Ok(_) => {
                            self.last_activity = Instant::now();
                        }
                        Err(_) => {
                            // Буфер smoltcp переполнен
                            break;
                        }
                    }
                }
            }
        }

        true
    }
}
