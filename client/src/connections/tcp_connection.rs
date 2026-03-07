use netrunner_common::protocol::codec::socks::{SocksRequest, TargetAddress};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream; // Твой код парсера
use tokio::sync::mpsc;
use tracing::{debug, info, trace};

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
    pending_data: Option<Vec<u8>>,
}

impl TcpConnection {
    pub fn new(handle: SocketHandle, proxy_addr: String, target_addr: TargetAddress) -> Self {
        let (tx_to_proxy, mut rx_from_smol) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_to_smol, rx_from_proxy) = mpsc::unbounded_channel::<Vec<u8>>();

        let proxy_addr_clone = proxy_addr.clone();
        let target_addr_clone = target_addr.clone();

        tokio::spawn(async move {
            debug!(
                %handle,
                target = ?target_addr_clone,
                proxy = %proxy_addr_clone,
                "Attempting to connect through proxy"
            );

            let mut stream = match TcpStream::connect(&proxy_addr).await {
                Ok(s) => {
                    debug!(%handle, "Connected to proxy successfully");
                    s
                }
                Err(e) => {
                    debug!(%handle, error = %e, "Failed to connect to proxy");
                    return;
                } // Тут можно добавить логирование
            };

            // 2. SOCKS Handshake
            if let Err(e) =
                SocksRequest::perform_client_handshake(&mut stream, &target_addr_clone).await
            {
                debug!(%handle, error = %e, "SOCKS handshake failed");
                return;
            }

            debug!(%handle, "SOCKS handshake successful, starting data bridge");

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
            state: ConnectionState::Handshaking, // Сразу переходим в Active, т.к. задача пошла
            tx: tx_to_proxy,
            rx: rx_from_proxy,
            pending_data: None,
        }
    }

    pub fn tick(&mut self, socket: &mut tcp::Socket) -> bool {
        trace!(handle=%self.handle, state=?socket.state(), "Tick");
        match self.state {
            ConnectionState::Handshaking => {
                info!("Connection handshaking");
                return true;
            }
            ConnectionState::Active => {
                self.poll_and_process(socket);

                // Проверяем условия закрытия
                if self.is_finished(socket) {
                    self.state = ConnectionState::Closed;
                    socket.abort(); // Принудительно разрываем стек
                    return false; // Сигнализируем, что соединение мертво
                }
            }
            ConnectionState::Closed => return false,
            _ => {}
        }
        true
    }

    pub fn is_finished(&self, socket: &tcp::Socket) -> bool {
        use tcp::State;
        let socket_closed = matches!(
            socket.state(),
            State::Closed | State::TimeWait | State::FinWait1 | State::FinWait2
        );

        let task_finished = self.rx.is_closed();

        socket_closed || task_finished
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }

    fn poll_and_process(&mut self, socket: &mut tcp::Socket) {
        if let Some(data) = self.pending_data.take() {
            if socket.send_slice(&data).is_ok() {
            } else {
                self.pending_data = Some(data);
                return;
            }
        }

        if socket.can_recv() {
            let _ = socket.recv(|data| {
                let len = data.len();
                if len > 0 {
                    let _ = self.tx.send(data.to_vec());
                }
                (len, ())
            });
        }

        if socket.can_send() {
            while let Ok(data) = self.rx.try_recv() {
                match socket.send_slice(&data) {
                    Ok(_) => { /* Успешно */ }
                    Err(_) => {
                        // Стек полон, запоминаем данные для следующего вызова
                        self.pending_data = Some(data);
                        break;
                    }
                }
            }
        }

        if socket.state() == tcp::State::CloseWait {
            debug!(handle=%self.handle, "!!! Triggering socket.close() for CLOSE-WAIT");
            socket.close();
        }
    }
}
