use bytes::{Bytes, BytesMut};
use netrunner_common::protocol::codec::frame::FrameType;
use netrunner_common::protocol::codec::socks::{SocksReply, SocksRequest};
use netrunner_common::protocol::parser::parser::Parser;
use netrunner_common::proxy::connection::muxer::{MuxMessage, Muxer};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer};
use smoltcp::socket::AnySocket;
use smoltcp::time::Instant;
use smoltcp::wire::IpListenEndpoint;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use tracing::{debug, info, trace};

pub enum BridgeState {
    WaitingHandshake,
    WaitingConnect,
    DataTransferring {
        tx_to_muxer: tokio::sync::mpsc::Sender<MuxMessage>,
        stream_id: u32,
    },
}

pub struct NetStack<D: smoltcp::phy::Device + AsRawFd + 'static> {
    interface: Interface,
    device: &'static mut D,
    sockets: SocketSet<'static>,
    socket_buffers: HashMap<SocketHandle, BytesMut>,
    bridges: HashMap<SocketHandle, BridgeState>,
    muxer: Muxer,
    outbound_rx: tokio::sync::mpsc::UnboundedReceiver<(SocketHandle, Bytes)>,
    outbound_tx: tokio::sync::mpsc::UnboundedSender<(SocketHandle, Bytes)>,
}

lazy_static::lazy_static! {
    static ref START_TIME: std::time::Instant = std::time::Instant::now();
}

fn _current_smoltcp_time() -> Instant {
    let nanos = START_TIME.elapsed().as_micros() as i64;
    smoltcp::time::Instant::from_micros(nanos)
}

impl<D: smoltcp::phy::Device + AsRawFd> NetStack<D> {
    pub fn new(device_obj: D, muxer: Muxer) -> Self {
        let now = _current_smoltcp_time();
        let device: &'static mut D = Box::leak(Box::new(device_obj));

        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut interface = Interface::new(config, device, now);
        interface.set_any_ip(true);

        interface.update_ip_addrs(|addrs| {
            addrs
                .push(smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::v4(10, 0, 0, 2),
                    24,
                ))
                .unwrap();
        });

        interface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
            .unwrap();

        let rx_data = Box::leak(vec![0u8; 4096].into_boxed_slice());
        let tx_data = Box::leak(vec![0u8; 4096].into_boxed_slice());

        let mut socket = SmolTcpSocket::new(SocketBuffer::new(rx_data), SocketBuffer::new(tx_data));

        // 4. Теперь listen() сработает, так как у интерфейса есть адрес!
        let endpoint = IpListenEndpoint {
            addr: None, // ВАЖНО: Принимаем пакеты для ЛЮБОГО IP назначения
            port: 443,  // Для HTTPS
        };
        socket.listen(endpoint).unwrap();

        let storage: Vec<SocketStorage> = (0..16).map(|_| SocketStorage::EMPTY).collect();
        let mut sockets = SocketSet::new(Box::leak(storage.into_boxed_slice()));
        sockets.add(socket);

        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel();

        Self {
            interface,
            device,
            sockets,
            socket_buffers: HashMap::new(),
            bridges: HashMap::new(),
            muxer,
            outbound_rx,
            outbound_tx,
        }
    }

    fn drive_interface(&mut self, timestamp: Instant) {
        match self
            .interface
            .poll(timestamp, self.device, &mut self.sockets)
        {
            smoltcp::iface::PollResult::None => {}
            res => debug!("Interface activity: {:?}", res),
        }
        let delay = self
            .interface
            .poll_delay(timestamp, &self.sockets)
            .map(|d| d.total_millis() as i32)
            .unwrap_or(10);
        let raw_fd = self.device.as_raw_fd();
        let mut fds = [libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN, // Ждем данные на вход
            revents: 0,
        }];

        unsafe {
            libc::poll(fds.as_mut_ptr(), 1, delay);
        }
    }

    fn manage_socket_lifecycle(&mut self) {
        for (_, any_socket) in self.sockets.iter_mut() {
            let socket = SmolTcpSocket::downcast_mut(any_socket).unwrap();

            // Если сокет закрылся или "отвисел" в TimeWait, возвращаем его в Listen
            if !socket.is_active() && !socket.is_listening() {
                let endpoint = IpListenEndpoint {
                    addr: None,
                    port: 443,
                };
                socket.listen(endpoint).unwrap();
                println!("DEBUG: Сокет готов к новому соединению");
            }
        }
    }

    fn process_socks_logic(&mut self, handle: SocketHandle) {
        let buf = self.socket_buffers.get_mut(&handle).unwrap();
        let state = self
            .bridges
            .entry(handle)
            .or_insert(BridgeState::WaitingHandshake);

        trace!(handle = ?handle, buf_len = buf.len(), "Processing SOCKS logic");
        match state {
            BridgeState::WaitingHandshake => {
                if let Ok(Some(SocksRequest::Handshake { .. })) = SocksRequest::parse(buf) {
                    let mut reply = BytesMut::with_capacity(2);
                    SocksReply::HandshakeSelect { method: 0x00 }.write_to(&mut reply);

                    let socket = self.sockets.get_mut::<SmolTcpSocket>(handle);
                    socket.send_slice(&reply).unwrap();

                    *state = BridgeState::WaitingConnect;
                    return; // <--- ВАЖНО: Выходим, чтобы smoltcp отправил этот пакет отдельно
                }
            }
            BridgeState::WaitingConnect => {
                // 1. Парсим запрос (парсер должен сам отрезать байты через advance/split_to)
                if let Ok(Some(SocksRequest::Connect { target, .. })) = SocksRequest::parse(buf) {
                    let stream_id = self.muxer.next_id();
                    let target_str = target.to_string();
                    info!(handle = ?handle, target = %target_str, stream_id, "SOCKS5 Connect request");

                    let (v_tx, mut v_rx) = tokio::sync::mpsc::channel::<Bytes>(1024);

                    // 2. Пытаемся зарегистрировать стрим СИНХРОННО
                    // Это гарантирует, что Muxer узнает об ID до того, как придет ответ из сети
                    if self.muxer.try_register_stream(stream_id, v_tx.clone()) {
                        debug!(stream_id, "Stream registered synchronously via try_write");

                        // Сразу шлем Connect в сеть
                        let _ = self.muxer.to_network.try_send(MuxMessage {
                            stream_id,
                            frame_type: FrameType::Connect,
                            data: Bytes::from(target_str),
                        });
                    } else {
                        // ПЛАН Б: Если лок занят, спавним асинхронную задачу.
                        // ВАЖНО: Мы НЕ шлем Connect здесь, его пришлет сама задача ПОСЛЕ регистрации.
                        let muxer_clone = self.muxer.clone();
                        let target_bytes = Bytes::from(target_str);
                        let v_tx_clone = v_tx.clone();

                        tokio::spawn(async move {
                            muxer_clone.register_stream(stream_id, v_tx_clone).await;
                            let _ = muxer_clone
                                .to_network
                                .send(MuxMessage {
                                    stream_id,
                                    frame_type: FrameType::Connect,
                                    data: target_bytes,
                                })
                                .await;
                            debug!(
                                stream_id,
                                "Stream registered asynchronously (lock was busy)"
                            );
                        });
                    }

                    // 3. Запускаем задачу проброса данных из сети в smoltcp
                    let outbound_tx = self.outbound_tx.clone();
                    let handle_clone = handle;
                    tokio::spawn(async move {
                        while let Some(data) = v_rx.recv().await {
                            if outbound_tx.send((handle_clone, data)).is_err() {
                                break;
                            }
                        }
                    });

                    buf.clear();
                    // 4. Отвечаем клиенту (curl)
                    let mut reply = BytesMut::new();
                    SocksReply::ConnectResult {
                        reply_code: 0x00,
                        atyp: 0x01,
                        addr: [0, 0, 0, 0],
                        port: 0,
                    }
                    .write_to(&mut reply);

                    let socket = self.sockets.get_mut::<SmolTcpSocket>(handle);
                    socket
                        .send_slice(&reply)
                        .expect("Failed to send SOCKS reply");

                    // ПЕРЕХОД
                    *state = BridgeState::DataTransferring {
                        tx_to_muxer: self.muxer.to_network.clone(),
                        stream_id,
                    };
                    return;
                }
            }
            BridgeState::DataTransferring {
                tx_to_muxer,
                stream_id,
            } => {
                if !buf.is_empty() {
                    // Забираем все накопленные данные из буфера
                    let data = buf.split().freeze();
                    trace!(handle = ?handle, stream_id = *stream_id, bytes = data.len(), "Forwarding data smoltcp -> muxer");
                    // Отправляем в Muxer
                    let _ = tx_to_muxer.try_send(MuxMessage {
                        stream_id: *stream_id,
                        frame_type: FrameType::Data,
                        data,
                    });
                }
            }
        }
    }

    fn process_payloads(&mut self) {
        let handles: Vec<_> = self.sockets.iter().map(|(h, _)| h).collect();

        for handle in handles {
            let socket = self.sockets.get_mut::<SmolTcpSocket>(handle);

            // 1. СОСТОЯНИЕ: Соединение только что установилось
            if socket.is_active() && !self.bridges.contains_key(&handle) {
                if let Some(target) = socket.local_endpoint() {
                    let stream_id = self.muxer.next_id();
                    info!("TUN Intercept: Auto-initiating SOCKS for target {}", target);

                    // ВАЖНО: Мы САМИ инициируем процесс для локального прокси
                    // Регистрируем стрим в муксере
                    let (v_tx, mut v_rx) = tokio::sync::mpsc::channel::<Bytes>(1024);
                    self.muxer.try_register_stream(stream_id, v_tx);

                    // Шлем CONNECT (твой муксер/прокси поймет это как SOCKS-запрос)
                    let _ = self.muxer.to_network.try_send(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Connect,
                        data: Bytes::from(target.to_string()),
                    });

                    // Запускаем стандартную задачу проброса данных ИЗ сети в smoltcp
                    let outbound_tx = self.outbound_tx.clone();
                    tokio::spawn(async move {
                        while let Some(data) = v_rx.recv().await {
                            let _ = outbound_tx.send((handle, data));
                        }
                    });

                    // Переходим сразу в режим передачи данных
                    // Теперь всё, что пришлет Firefox, мы будем просто гнать в Muxer как FrameType::Data
                    self.bridges.insert(
                        handle,
                        BridgeState::DataTransferring {
                            stream_id,
                            tx_to_muxer: self.muxer.to_network.clone(),
                        },
                    );

                    continue;
                }
            }

            // 2. СОСТОЯНИЕ: Передача данных (DataTransferring)
            if let Some(BridgeState::DataTransferring {
                stream_id,
                tx_to_muxer,
            }) = self.bridges.get(&handle)
            {
                if socket.can_recv() {
                    let mut temp_buf = vec![0u8; 2048];
                    if let Ok(size) = socket.recv_slice(&mut temp_buf) {
                        // Это РЕАЛЬНЫЕ данные от Firefox (например, TLS Client Hello)
                        // Мы их просто оборачиваем в твой протокол и шлем в муксер
                        let _ = tx_to_muxer.try_send(MuxMessage {
                            stream_id: *stream_id,
                            frame_type: FrameType::Data,
                            data: Bytes::copy_from_slice(&temp_buf[..size]),
                        });
                    }
                }
            }
        }
    }
    pub fn poll(&mut self) {
        let timestamp = _current_smoltcp_time();

        self.drive_interface(timestamp);

        self.process_payloads();

        while let Ok((handle, data)) = self.outbound_rx.try_recv() {
            if let Some(socket_state) = self.bridges.get(&handle) {
                // ПИШЕМ ТОЛЬКО ЕСЛИ МЫ УЖЕ В DATA TRANSFER
                if let BridgeState::DataTransferring { .. } = socket_state {
                    if self.sockets.iter().any(|(h, _)| h == handle) {
                        let socket = self.sockets.get_mut::<SmolTcpSocket>(handle);
                        if socket.can_send() {
                            debug!(handle = ?handle, len = data.len(), head = ?&data[..std::cmp::min(data.len(), 10)], "Writing to curl");
                            let _ = socket.send_slice(&data);
                        }
                    }
                } else {
                    // Если мы еще в WaitingConnect, возвращаем данные в очередь
                    // или просто игнорируем (они придут следующим тиком)
                    debug!(handle = ?handle, "Data arrived before SOCKS handshake finished, delaying...");
                    // Можно использовать self.outbound_tx.send(...) чтобы вернуть в хвост
                }
            }
        }

        self.manage_socket_lifecycle();
    }
}
