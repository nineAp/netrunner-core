use netrunner_common::protocol::codec::socks::SocksRequest;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream; // Твой код парсера
use tokio::sync::mpsc;

pub enum ConnectionState {
    /// Сокет только что принял соединение (SYN-ACK завершен)
    Established,
    /// Мы в процессе SOCKS5 рукопожатия с локальным прокси
    Handshaking,
    /// Соединение готово к передаче данных (Bridge)
    Active,
    /// Ошибка или закрытие
    Closed,
}

pub struct TcpConnection {
    handle: SocketHandle,
    state: ConnectionState,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl TcpConnection {
    pub fn new(
        handle: SocketHandle,
        proxy_addr: String,
        target_addr: std::net::SocketAddr,
    ) -> Self {
        let (tx_to_proxy, mut rx_from_smol) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_to_smol, rx_from_proxy) = mpsc::unbounded_channel::<Vec<u8>>();

        // Запускаем асинхронную логику в фоне
        tokio::spawn(async move {
            // 1. Подключаемся
            let mut stream = match TcpStream::connect(&proxy_addr).await {
                Ok(s) => s,
                Err(_) => return, // Тут можно добавить логирование
            };

            // 2. SOCKS Handshake
            if SocksRequest::perform_client_handshake(&mut stream, &target_addr)
                .await
                .is_err()
            {
                return;
            }

            // 3. Копирование данных (Bridge)
            let (mut reader, mut writer) = stream.into_split();

            // Читаем из канала -> Пишем в прокси
            let to_proxy = async {
                while let Some(data) = rx_from_smol.recv().await {
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
            };

            // Читаем из прокси -> Пишем в канал для smoltcp
            let from_proxy = async {
                let mut buf = [0u8; 4096];
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
                _ = to_proxy => {},
                _ = from_proxy => {},
            }
        });

        Self {
            handle,
            state: ConnectionState::Active, // Сразу переходим в Active, т.к. задача пошла
            tx: tx_to_proxy,
            rx: rx_from_proxy,
        }
    }

    pub fn poll_and_process(&mut self, socket: &mut tcp::Socket) {
        // 1. Из smoltcp -> В канал задачи
        if socket.can_recv() {
            let mut buf = [0u8; 4096];
            if let Ok(n) = socket.recv_slice(&mut buf) {
                if n > 0 {
                    let _ = self.tx.send(buf[..n].to_vec());
                }
            }
        }

        // 2. Из канала задачи -> В smoltcp
        if socket.can_send() {
            // try_recv не блокирует поток, что нам и нужно
            if let Ok(data) = self.rx.try_recv() {
                let _ = socket.send_slice(&data);
            }
        }
    }
}
