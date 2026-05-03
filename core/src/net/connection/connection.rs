use std::{net::Ipv4Addr, sync::Arc};

use crate::{
    crypto::{ChaChaCipher, SessionKeys},
    net::{
        connection::{
            engine::TunnelEngine,
            handler::{RemoteOpener, StreamHandler},
            muxer::{MuxMessage, Muxer},
        },
        NetworkConfig, FALLBACK_CONNECT_TIMEOUT, LEG_RECONNECT_DELAY, LEG_STAGGER_DELAY,
        MAX_TUNNEL_LEGS, SECURE_HANDSHAKE_TIMEOUT, STEALTH_FALLBACK_HOST, TLS_HELLO_TIMEOUT,
        TOPOLOGY_PRINT_INTERVAL,
    },
    nrxp::{Codec, Frame, FrameType, TlsBridge},
    rawcast::{LocalProtocol, RawCastAdapter, RawCastFrame},
    tlseng::{BrowserProfile, ServerProfile},
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use netrunner_logger::{
    debug, error, info, warn, AppError, ERR_AUTH_FAILED, ERR_INFRA_TIMEOUT, ERR_NET_TLS_TAMPER,
};
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc,
};

pub struct SessionManager {
    sessions: DashMap<String, Arc<Muxer>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn generate_id() -> String {
        let mut rng = rand::rng();
        format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64())
    }

    pub fn get_session(&self) -> &DashMap<String, Arc<Muxer>> {
        &self.sessions
    }

    pub fn get_or_create(&self, session_id: &str) -> Arc<Muxer> {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Muxer::new(false, session_id.to_string())))
            .clone()
    }

    pub fn remove(&self, session_id: &str) {
        if self.sessions.remove(session_id).is_some() {
            info!("🧹 Session {} completely closed and cleaned up", session_id);
        }
    }

    pub fn print_all_sessions(&self) {
        if self.sessions.is_empty() {
            return;
        }

        info!("📊 --- SERVER GLOBAL SESSIONS REPORT ---");
        for entry in self.sessions.iter() {
            let session_id = entry.key();
            let muxer = entry.value();

            // Вызываем уже существующий метод печати дерева у Muxer
            muxer.print_topology_tree();
        }
        info!("📊 ---------------------------------------");
    }
}

#[async_trait::async_trait]
pub trait TunnelHandler {
    async fn run(self) -> Result<(), AppError>;
}

pub struct Connection {
    pub(crate) inbound: OwnedReadHalf,
    pub(crate) outbound: OwnedWriteHalf,
    pub(crate) read_buf: BytesMut,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(NetworkConfig::global().connection_buf_size),
        }
    }
}

pub struct ClientHandler;
impl ClientHandler {
    fn get_local_ip() -> Option<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        socket.local_addr().ok().map(|a| a.ip())
    }

    async fn establish_leg(
        remote_proxy_addr: &str,
        leg_id: u32,
        muxer: Arc<Muxer>,
        session_id: &str,
    ) -> Result<(), AppError> {
        let leg_name = format!("TCP-Leg-{}", leg_id);

        let addrs_future = tokio::net::lookup_host(remote_proxy_addr);
        let mut addrs = tokio::time::timeout(std::time::Duration::from_secs(3), addrs_future)
            .await
            .map_err(|_| {
                AppError::new(ERR_INFRA_TIMEOUT, "Сервер недоступен", "DNS Lookup Timeout")
            })?
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Ошибка DNS", e.to_string()))?;

        let addr = addrs.next().ok_or_else(|| {
            AppError::new(
                ERR_INFRA_TIMEOUT,
                "Ошибка сети",
                format!("No IPs found for {}", remote_proxy_addr),
            )
        })?;

        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| {
            AppError::new(
                ERR_INFRA_TIMEOUT,
                "Таймаут подключения",
                "Connection timeout",
            )
        })?
        .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сокета", e.to_string()))?;

        stream.set_nodelay(true).unwrap_or_default();

        let mut conn = Connection::new(stream);
        let mut session_keys = SessionKeys::new(true);
        let ch =
            TlsBridge::wrap_client_hello(&BrowserProfile::CHROME_131, "ubuntu.com", &session_keys);

        conn.outbound
            .write_all(&ch)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", e.to_string()))?;

        loop {
            match TlsBridge::unpack_handshake(&mut conn.read_buf) {
                Ok(Some(msg)) => {
                    session_keys.update_keys(msg.random(), msg.extensions(), false)?;
                    break;
                }
                Ok(None) => {
                    let res = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        conn.inbound.read_buf(&mut conn.read_buf),
                    )
                    .await;
                    match res {
                        Ok(Ok(0)) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Разрыв соединения",
                                format!("EOF on {}", leg_name),
                            ))
                        }
                        Ok(Ok(_)) => continue,
                        Ok(Err(e)) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Ошибка чтения",
                                e.to_string(),
                            ))
                        }
                        Err(_) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Таймаут handshake",
                                "Handshake read timeout",
                            ))
                        }
                    }
                }
                Err(e) => {
                    return Err(AppError::new(
                        ERR_NET_TLS_TAMPER,
                        "Ошибка TLS",
                        format!("TLS error on {}: {:?}", leg_name, e.stage),
                    ))
                }
            }
        }

        let (tx_key, tx_iv, rx_key, rx_iv) = session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::new();
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);
        let codec = Codec::new(cipher, session_keys.get_auth_key());
        let (rx_codec, mut tx_codec) = codec.split();

        let auth_payload = Bytes::from(format!("{}:{}", session_id, leg_id));
        let encrypted_auth = tx_codec
            .encode_frame(0, FrameType::Heartbeat, auth_payload)
            .map_err(|e| {
                AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Сбой шифрования",
                    format!("Failed to encrypt Auth: {:?}", e),
                )
            })?;

        conn.outbound
            .write_all(&encrypted_auth)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой отправки", e.to_string()))?;

        let cap = NetworkConfig::global().channel_capacity;
        let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
        let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);

        let control_tx_clone = control_tx.clone();
        muxer.add_leg(leg_id, control_tx, data_tx);

        let handler = Arc::new(StreamHandler::new(muxer.clone(), None));
        let engine = TunnelEngine {
            leg_id,
            inbound: conn.inbound,
            outbound: conn.outbound,
            rx_codec,
            tx_codec,
            read_buf: conn.read_buf,
            control_rx,
            data_rx,
            handler,
            muxer: muxer.clone(),
        };

        let run_result = engine.run().await;
        muxer.remove_leg(leg_id, &control_tx_clone);

        run_result?;
        Err(AppError::new(
            ERR_INFRA_TIMEOUT,
            "Движок остановлен",
            format!("{} Engine stopped", leg_name),
        ))
    }

    pub async fn connect(
        remote_proxy_addr: &str,
        mut rx_from_engine: mpsc::Receiver<RawCastFrame>,
        tx_to_engine: mpsc::Sender<RawCastFrame>,
    ) -> Result<(), AppError> {
        let session_id = SessionManager::generate_id();
        let muxer = Arc::new(Muxer::new(true, session_id.clone()));
        let registry: Arc<DashMap<u32, (u64, Ipv4Addr, u16, LocalProtocol)>> =
            Arc::new(DashMap::new());
        let local_to_global: Arc<DashMap<u64, u32>> = Arc::new(DashMap::new());

        let watcher_muxer = muxer.clone();
        tokio::spawn(async move {
            let mut last_ip = Self::get_local_ip();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let current_ip = Self::get_local_ip();
                if current_ip != last_ip {
                    // ФИКС: Сбрасываем туннели только при реальном переходе (например, Wi-Fi на LTE)
                    // Игнорируем кратковременную потерю сети (None), TCP сам справится с задержкой
                    if current_ip.is_some() && last_ip.is_some() {
                        netrunner_logger::warn!(
                            "🌐 Network Change Detected: {:?} -> {:?}",
                            last_ip,
                            current_ip
                        );
                        watcher_muxer.remove_all_legs();
                    }
                    last_ip = current_ip;
                }
            }
        });

        for id in 0..MAX_TUNNEL_LEGS {
            let addr = remote_proxy_addr.to_string();
            let m = muxer.clone();
            let sid = session_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(LEG_STAGGER_DELAY * id).await;
                loop {
                    if let Err(e) = Self::establish_leg(&addr, id, m.clone(), &sid).await {
                        error!("Leg {} disconnected: {}. Reconnecting in 2s...", id, e);
                        tokio::time::sleep(LEG_RECONNECT_DELAY).await;
                    }
                }
            });
        }

        let m_weak = Arc::downgrade(&muxer);
        tokio::spawn(async move {
            while let Some(m_stats) = m_weak.upgrade() {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                if m_stats.active_legs_count() == 0 {
                    continue;
                }
                m_stats.perform_health_check().await;
                m_stats.print_topology_tree();
            }
        });

        let muxer_inner = muxer.clone();
        tokio::spawn(async move {
            while let Some(raw_frame) = rx_from_engine.recv().await {
                if let Ok(nrxp_frame) = RawCastAdapter::to_nrxp(raw_frame.clone()) {
                    let local_socket_id = raw_frame.socket_id;
                    let f_type = nrxp_frame.header.frame_type;
                    let payload = nrxp_frame.payload;

                    match f_type {
                        FrameType::Connect | FrameType::UdpConnect => {
                            let global_stream_id = muxer_inner.next_stream_id();
                            local_to_global.insert(local_socket_id, global_stream_id);
                            registry.insert(
                                global_stream_id,
                                (
                                    local_socket_id,
                                    raw_frame.dst_ip,
                                    raw_frame.dst_port,
                                    raw_frame.protocol,
                                ),
                            );

                            let cap = NetworkConfig::global().channel_capacity;
                            let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(cap);
                            muxer_inner.register_stream(global_stream_id, v_tx);

                            let tx_to_tun = tx_to_engine.clone();
                            let reg = registry.clone();
                            let l2g = local_to_global.clone(); // 🔥 Клонируем для очистки

                            tokio::spawn(async move {
                                while let Some(back_payload) = v_rx.recv().await {
                                    let route_info = reg.get(&global_stream_id).map(|r| *r);

                                    if let Some((orig_local_id, ip, port, proto)) = route_info {
                                        let out_f_type = if proto == LocalProtocol::Udp {
                                            FrameType::UdpData
                                        } else {
                                            FrameType::Data
                                        };
                                        let mock_nrxp = Frame::new(
                                            orig_local_id as u32,
                                            out_f_type,
                                            back_payload,
                                        );
                                        if let Ok(raw) = RawCastAdapter::from_nrxp(
                                            mock_nrxp,
                                            ip,
                                            port,
                                            proto == LocalProtocol::Udp,
                                        ) {
                                            let _ = tx_to_tun.send(raw).await;
                                        }
                                    }
                                }

                                // 🔥 ФИКС УТЕЧКИ ПАМЯТИ: Сборщик мусора
                                // Если цикл завершился (Muxer удалил v_tx), стираем мертвые сессии
                                if let Some((_, (orig_local_id, _, _, _))) =
                                    reg.remove(&global_stream_id)
                                {
                                    l2g.remove(&orig_local_id);
                                    debug!(
                                        global_stream_id,
                                        "🧹 Garbage Collector: Cleaned up dead registry stream"
                                    );
                                }
                            });

                            let _ = muxer_inner
                                .send_control(global_stream_id, f_type, payload)
                                .await;
                        }
                        FrameType::Data | FrameType::UdpData => {
                            let global_id = local_to_global.get(&local_socket_id).map(|id| *id);

                            if let Some(id) = global_id {
                                let _ = muxer_inner
                                    .send_data_safe(
                                        id,
                                        payload,
                                        raw_frame.protocol == LocalProtocol::Udp,
                                    )
                                    .await;
                            }
                        }
                        FrameType::Close => {
                            if let Some(kv) = local_to_global.remove(&local_socket_id) {
                                let global_stream_id = kv.1;
                                let _ = muxer_inner
                                    .send_control(global_stream_id, FrameType::Close, Bytes::new())
                                    .await;
                                muxer_inner.remove_stream(global_stream_id);
                                registry.remove(&global_stream_id);
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        Ok(())
    }
}

pub struct ServerHandler {
    pub(crate) conn: Connection,
    pub(crate) session_manager: Arc<SessionManager>,
}

impl ServerHandler {
    pub fn new(connection: Connection, session_manager: Arc<SessionManager>) -> Self {
        Self {
            conn: connection,
            session_manager,
        }
    }

    async fn handle_stealth_fallback(
        mut client_inbound: OwnedReadHalf,
        mut client_outbound: OwnedWriteHalf,
        initial_data: Bytes,
    ) {
        info!(target = %STEALTH_FALLBACK_HOST, "Stealth fallback: bridging to Target");
        let target_stream = tokio::time::timeout(
            FALLBACK_CONNECT_TIMEOUT,
            TcpStream::connect(STEALTH_FALLBACK_HOST),
        )
        .await;

        if let Ok(Ok(target_server)) = target_stream {
            let (mut server_read, mut server_write) = target_server.into_split();

            if !initial_data.is_empty() {
                if server_write.write_all(&initial_data).await.is_err() {
                    return;
                }
            }

            let client_to_server = tokio::io::copy(&mut client_inbound, &mut server_write);
            let server_to_client = tokio::io::copy(&mut server_read, &mut client_outbound);

            let _ = tokio::join!(client_to_server, server_to_client);
            debug!("Stealth fallback connection closed.");
        } else {
            warn!("Failed to connect to fallback host.");
        }
    }
}

#[async_trait::async_trait]
impl TunnelHandler for ServerHandler {
    async fn run(self) -> Result<(), AppError> {
        info!("Acting as TLS Server with Stealth Fallback");

        let Connection {
            mut inbound,
            mut outbound,
            mut read_buf,
        } = self.conn;
        let mut session_keys = SessionKeys::new(false);

        let hello = loop {
            let buf_snapshot = read_buf.clone().freeze();

            match TlsBridge::unpack_handshake(&mut read_buf) {
                Ok(Some(client_msg)) => {
                    match TlsBridge::wrap_server_hello(
                        &client_msg,
                        &mut session_keys,
                        &ServerProfile::MODERN,
                    ) {
                        Ok(sh) => {
                            info!("✅ Valid Netrunner ClientHello detected");
                            break sh;
                        }
                        Err(e) => {
                            warn!("❌ Unauthorized/Invalid ClientHello. Triggering Stealth Fallback. Reason: {:?}", e.stage);
                            Self::handle_stealth_fallback(inbound, outbound, buf_snapshot).await;
                            return Ok(());
                        }
                    }
                }
                Ok(None) => {
                    let res =
                        tokio::time::timeout(TLS_HELLO_TIMEOUT, inbound.read_buf(&mut read_buf))
                            .await;
                    match res {
                        Ok(Ok(0)) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Клиент отключился",
                                "Client closed connection",
                            ))
                        }
                        Ok(Ok(_)) => continue,
                        _ => {
                            warn!("⏰ TLS_HELLO_TIMEOUT reached. Triggering fallback...");
                            Self::handle_stealth_fallback(inbound, outbound, buf_snapshot).await;
                            return Ok(());
                        }
                    }
                }
                Err(_) => {
                    warn!("❌ Handshake parse failed (Not a valid TLS probe). Triggering Stealth Fallback.");
                    Self::handle_stealth_fallback(inbound, outbound, buf_snapshot).await;
                    return Ok(());
                }
            }
        };

        outbound
            .write_all(&hello)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Ошибка отправки", e.to_string()))?;

        let (tx_key, tx_iv, rx_key, rx_iv) = session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::new();
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);

        let codec = Codec::new(cipher, session_keys.get_auth_key());
        let (mut rx_codec, tx_codec) = codec.split();

        let (session_id, leg_id) = loop {
            match rx_codec.decode_inbound(&mut read_buf) {
                Ok(Some(frame)) => {
                    if frame.header.frame_type == FrameType::Heartbeat {
                        let payload_str = std::str::from_utf8(&frame.payload).unwrap_or("");
                        let parts: Vec<&str> = payload_str.split(':').collect();
                        if parts.len() == 2 && parts[1].parse::<u32>().is_ok() {
                            let sid = parts[0].to_string();
                            let lid: u32 = parts[1].parse().unwrap();
                            info!("🤝 Secure Auth verified! Session: {}, Leg: {}", sid, lid);
                            break (sid, lid);
                        }
                    }
                    return Err(AppError::new(
                        ERR_AUTH_FAILED,
                        "Ошибка авторизации",
                        "Expected Auth payload in first Heartbeat frame",
                    ));
                }
                Ok(None) => {
                    let n = tokio::time::timeout(
                        SECURE_HANDSHAKE_TIMEOUT,
                        inbound.read_buf(&mut read_buf),
                    )
                    .await
                    .map_err(|_| {
                        AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Таймаут авторизации",
                            "Timeout waiting for Auth",
                        )
                    })?
                    .map_err(|e| {
                        AppError::new(ERR_INFRA_TIMEOUT, "Ошибка сокета", e.to_string())
                    })?;
                    if n == 0 {
                        return Err(AppError::new(
                            ERR_AUTH_FAILED,
                            "Отказ",
                            "Client closed connection before Auth",
                        ));
                    }
                }
                Err(e) => {
                    error!("❌ Secure Auth Failed: {:?}", e.stage);
                    return Err(AppError::new(
                        ERR_AUTH_FAILED,
                        "Доступ запрещен",
                        "Dropped by security strategy (Auth Phase)",
                    ));
                }
            }
        };

        let muxer = self.session_manager.get_or_create(&session_id);
        let cap = NetworkConfig::global().channel_capacity;
        let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
        let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);

        let control_tx_clone = control_tx.clone();
        muxer.add_leg(leg_id, control_tx, data_tx);

        let opener = Arc::new(RemoteOpener {
            muxer: muxer.clone(),
        });
        let handler = Arc::new(StreamHandler::new(muxer.clone(), Some(opener)));

        let engine = TunnelEngine {
            leg_id,
            inbound,
            outbound,
            rx_codec,
            tx_codec,
            read_buf,
            control_rx,
            data_rx,
            handler,
            muxer: muxer.clone(),
        };

        let res = engine.run().await;

        muxer.remove_leg(leg_id, &control_tx_clone);

        if muxer.active_legs_count() == 0 {
            let sm = self.session_manager.clone();
            let sid = session_id.clone();
            let m = muxer.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                if m.active_legs_count() == 0 {
                    sm.remove(&sid);
                }
            });
        }
        res
    }
}
