use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::connections::CHANNEL_CAPACITY;
use bytes::Bytes;

pub struct UdpConnection {
    pub handle: SocketHandle,
    // UPLOAD: Ограниченный канал для передачи данных наружу
    tx: mpsc::Sender<Bytes>,
    // DOWNLOAD: Канал для приема данных из сети
    rx: mpsc::Receiver<Bytes>,
    client_endpoint: Option<IpEndpoint>,
    last_activity: Instant,
}

const UDP_TIMEOUT: Duration = Duration::from_secs(60);

impl UdpConnection {
    /// Возвращает:
    /// 1. Экземпляр UdpConnection
    /// 2. Receiver (для чтения данных, отправляемых ИЗ smoltcp В сеть)
    /// 3. Sender (для записи данных ИЗ сети В smoltcp)
    pub fn new(handle: SocketHandle) -> (Self, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>) {
        let (tx_to_net, rx_from_smol) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);
        let (tx_to_smol, rx_from_net) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);

        let conn = Self {
            handle,
            tx: tx_to_net,
            rx: rx_from_net,
            client_endpoint: None,
            last_activity: Instant::now(),
        };

        (conn, rx_from_smol, tx_to_smol)
    }

    pub fn tick(&mut self, socket: &mut udp::Socket) -> bool {
        // Проверка таймаута бездействия
        if self.last_activity.elapsed() > UDP_TIMEOUT {
            netrunner_logger::debug!(%self.handle, "UDP Session closed due to timeout");
            socket.close();
            return false;
        }

        // 1. UPLOAD: Читаем из smoltcp и отправляем в виртуальный канал
        if socket.can_recv() {
            while let Ok((data, metadata)) = socket.recv() {
                self.client_endpoint = Some(metadata.endpoint);

                // Копируем данные в Bytes и пытаемся протолкнуть.
                // Если канал забит (Full), пакет дропается — это штатное поведение UDP.
                if self.tx.try_send(Bytes::copy_from_slice(data)).is_ok() {
                    self.last_activity = Instant::now();
                }
            }
        }

        // 2. DOWNLOAD: Читаем из виртуального канала и пишем в smoltcp
        if socket.can_send() {
            if let Some(endpoint) = self.client_endpoint {
                while let Ok(data) = self.rx.try_recv() {
                    // Сигнал закрытия стрима
                    if data.is_empty() {
                        socket.close();
                        return false;
                    }

                    match socket.send_slice(&data, endpoint) {
                        Ok(_) => {
                            self.last_activity = Instant::now();
                        }
                        Err(_) => {
                            // Если сокет smoltcp переполнен, прерываем цикл.
                            // Пакет теряется, что опять же является нормой для UDP.
                            break;
                        }
                    }
                }
            }
        }

        true
    }
}
