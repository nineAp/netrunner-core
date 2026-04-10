use std::{net::Ipv4Addr, sync::Arc};

use crate::{
    crypto::{ChaChaCipher, SessionKeys}, net::{
        FALLBACK_CONNECT_TIMEOUT, LEG_RECONNECT_DELAY, LEG_STAGGER_DELAY, MAX_TUNNEL_LEGS, NetworkConfig, SECURE_HANDSHAKE_TIMEOUT, STEALTH_FALLBACK_HOST, TLS_HELLO_TIMEOUT, TOPOLOGY_PRINT_INTERVAL, connection::{
            engine::TunnelEngine,
            handler::{RemoteOpener, StreamHandler},
            muxer::Muxer,
        }
    }, nrxp::{Codec, ErrorAction, Frame, FrameType, TlsBridge}, rawcast::{LocalProtocol, RawCastAdapter, RawCastFrame}, tlseng::{BrowserProfile, ServerProfile}
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use netrunner_logger::{debug, error, info, warn};
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
        Self { sessions: DashMap::new() }
    }

    pub fn generate_id() -> String {
        let mut rng = rand::rng();
        format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64())
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
}

#[async_trait::async_trait]
pub trait TunnelHandler {
    async fn run(self) -> Result<(), String>;
}

// ⚠️ Connection теперь содержит только транспорт, без Codec
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
            read_buf: BytesMut::with_capacity(NetworkConfig::global().tcp_buffer_size),
        }
    }
}

type StreamContext = (u32, Ipv4Addr, u16, LocalProtocol);

pub struct ClientHandler;
impl ClientHandler {
    async fn establish_leg(
        remote_proxy_addr: &str,
        leg_id: u32,
        muxer: Arc<Muxer>,
        session_id: &str,
    ) -> Result<(), String> {
        let leg_name = if leg_id % 2 == 0 { "TCP-Leg" } else { "UDP-Leg" };
        info!("Establishing dedicated {} (ID: {}) to {}...", leg_name, leg_id, remote_proxy_addr);

        let mut addrs = tokio::net::lookup_host(remote_proxy_addr)
            .await
            .map_err(|e| format!("DNS resolution failed: {}", e))?;

        let addr = addrs.next().ok_or_else(|| format!("No IPs found for {}", remote_proxy_addr))?;

        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4().map_err(|e| e.to_string())?
        } else {
            tokio::net::TcpSocket::new_v6().map_err(|e| e.to_string())?
        };

        let stream = socket.connect(addr).await.map_err(|e| format!("Connect failed: {}", e))?;
        let _ = stream.set_nodelay(true);
        let mut conn = Connection::new(stream);

        // --- 1. TLS Handshake Phase ---
        let mut session_keys = SessionKeys::new(true);
        let ch = TlsBridge::wrap_client_hello(&BrowserProfile::CHROME_131, "ubuntu.com", &session_keys);

        conn.outbound.write_all(&ch).await.map_err(|e| e.to_string())?;

        loop {
            // Проверяем, есть ли уже ServerHello в буфере
            match TlsBridge::unpack_handshake(&mut conn.read_buf) {
                Ok(Some(msg)) => {
                    session_keys.update_keys(msg.random(), msg.extensions(), false)
                        .map_err(|e| format!("Keys update error: {}", e))?;
                    break;
                }
                Ok(None) => {
                    let n = conn.inbound.read_buf(&mut conn.read_buf).await.map_err(|e| e.to_string())?;
                    if n == 0 { return Err(format!("EOF on {}", leg_name)); }
                }
                Err(e) => return Err(format!("TLS error on {}: {:?}", leg_name, e)),
            }
        }

        info!("{} TLS Handshake complete.", leg_name);

        // --- 2. Data Phase Initialization ---
        let (tx_key, tx_iv, rx_key, rx_iv) = session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::new();
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);

        // Забираем остатки из хендшейка в новый кодек
        let codec = Codec::new(cipher, session_keys.get_auth_key());
        let (rx_codec, mut tx_codec) = codec.split();

        // --- 3. Encrypted Handshake ---
        let handshake_payload = Bytes::from(format!("{}:{}", session_id, leg_id));
        let encrypted_handshake = tx_codec.encode_frame(0, FrameType::Handshake, handshake_payload)
            .map_err(|e| format!("Failed to encrypt Handshake: {:?}", e))?;

        conn.outbound.write_all(&encrypted_handshake).await.map_err(|e| e.to_string())?;

        let (control_tx, control_rx) = mpsc::channel(NetworkConfig::global().client_muxer_capacity);
        let (data_tx, data_rx) = mpsc::channel(NetworkConfig::global().client_muxer_capacity);
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

        engine.run().await.map_err(|e| e.to_string())?;
        Err(format!("{} Engine stopped", leg_name))
    }

    pub async fn connect(
        remote_proxy_addr: &str,
        mut rx_from_engine: mpsc::Receiver<RawCastFrame>,
        tx_to_engine: mpsc::Sender<RawCastFrame>,
    ) -> Result<(), String> {
        let session_id = SessionManager::generate_id();
        info!("🔑 Generated Master Session ID: {}", session_id);
        let muxer = Arc::new(Muxer::new(true, session_id.clone()));
        let registry: Arc<DashMap<u32, StreamContext>> = Arc::new(DashMap::new());
        let local_to_global: Arc<DashMap<u32, u32>> = Arc::new(DashMap::new());

        for id in 0..MAX_TUNNEL_LEGS {
            let addr = remote_proxy_addr.to_string();
            let m = muxer.clone();
            let sid = session_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(LEG_STAGGER_DELAY * id).await;
                loop {
                    if let Err(e) = Self::establish_leg(&addr, id, m.clone(), &sid).await {
                        error!("Leg {} disconnected: {}. Reconnecting in 3s...", id, e);
                        tokio::time::sleep(LEG_RECONNECT_DELAY).await;
                    }
                }
            });
        }

        let m_weak = Arc::downgrade(&muxer);
        tokio::spawn(async move {
            while let Some(m_stats) = m_weak.upgrade() {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                if m_stats.active_legs_count() == 0 { break; }
                m_stats.perform_health_check().await;
                m_stats.print_topology_tree();
            }
        });

        let muxer_inner = muxer.clone();
        tokio::spawn(async move {
            while let Some(raw_frame) = rx_from_engine.recv().await {
                let dst_ip = raw_frame.dst_ip;
                let dst_port = raw_frame.dst_port;
                let protocol = raw_frame.protocol;
                let is_udp = protocol == LocalProtocol::Udp;

                if let Ok(nrxp_frame) = RawCastAdapter::to_nrxp(raw_frame) {
                    let local_socket_id = nrxp_frame.header.stream_id;
                    let f_type = nrxp_frame.header.frame_type;
                    let payload = nrxp_frame.payload;

                    match f_type {
                        FrameType::Connect | FrameType::UdpConnect => {
                            let global_stream_id = muxer_inner.next_stream_id();
                            local_to_global.insert(local_socket_id, global_stream_id);
                            registry.insert(global_stream_id, (local_socket_id, dst_ip, dst_port, protocol));

                            let (v_tx, mut v_rx) = mpsc::channel(NetworkConfig::global().client_stream_capacity);
                            muxer_inner.register_stream(global_stream_id, v_tx);

                            let tx_to_tun = tx_to_engine.clone();
                            let reg = registry.clone();

                            tokio::spawn(async move {
                                while let Some(back_payload) = v_rx.recv().await {
                                    if let Some((orig_local_id, ip, port, proto)) = reg.get(&global_stream_id).map(|r| *r) {
                                        let out_f_type = if proto == LocalProtocol::Udp { FrameType::UdpData } else { FrameType::Data };
                                        let mock_nrxp = Frame::new(orig_local_id, out_f_type, back_payload);
                                        if let Ok(raw) = RawCastAdapter::from_nrxp(mock_nrxp, ip, port, proto == LocalProtocol::Udp) {
                                            let _ = tx_to_tun.send(raw).await;
                                        }
                                    }
                                }
                            });
                            let _ = muxer_inner.send_control(global_stream_id, f_type, payload).await;
                        }
                        FrameType::Data | FrameType::UdpData => {
                            if let Some(id) = local_to_global.get(&local_socket_id).map(|r| *r) {
                                let _ = muxer_inner.send_data_safe(id, payload, is_udp).await;
                            }
                        }
                        FrameType::Close => {
                            if let Some((_, global_stream_id)) = local_to_global.remove(&local_socket_id) {
                                let _ = muxer_inner.send_control(global_stream_id, FrameType::Close, Bytes::new()).await;
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
    pub fn new(connection: Connection) -> Self {
        Self { conn: connection, session_manager: Arc::new(SessionManager::new()) }
    }

    async fn handle_stealth_fallback(mut client_inbound: OwnedReadHalf, mut client_outbound: OwnedWriteHalf, initial_data: Bytes) {
        info!(target = %STEALTH_FALLBACK_HOST, "Stealth fallback: bridging to Target");
        let target_stream = tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(STEALTH_FALLBACK_HOST)).await;

        if let Ok(Ok(target_server)) = target_stream {
            let (mut server_read, mut server_write) = target_server.into_split();
            if !initial_data.is_empty() {
                let _ = server_write.write_all(&initial_data).await;
            }
            let _ = tokio::io::copy_bidirectional(
                &mut tokio::io::join(&mut client_inbound, &mut client_outbound),
                &mut tokio::io::join(&mut server_read, &mut server_write),
            ).await;
        }
    }
}

#[async_trait::async_trait]
impl TunnelHandler for ServerHandler {
    async fn run(self) -> Result<(), String> {
        info!("Acting as TLS Server with Stealth Fallback");

        let Connection { mut inbound, mut outbound, mut read_buf } = self.conn;
        let mut session_keys = SessionKeys::new(false);

        // --- PHASE 1: TLS Hello & Protocol Identification ---
        let hello = loop {
            let buf_snapshot = read_buf.clone().freeze();

            match TlsBridge::unpack_handshake(&mut read_buf) {
                Ok(Some(client_msg)) => {
                    info!("✅ Valid Netrunner ClientHello detected");
                    match TlsBridge::wrap_server_hello(&client_msg, &mut session_keys, &ServerProfile::MODERN) {
                        Ok(sh) => break sh,
                        Err(e) => {
                            if e.execute_strategy() == ErrorAction::Redirect {
                                Self::handle_stealth_fallback(inbound, outbound, buf_snapshot).await;
                                return Ok(());
                            }
                            return Err("ServerHello Generation Failed".into());
                        }
                    }
                }
                Ok(None) => {
                    let res = tokio::time::timeout(TLS_HELLO_TIMEOUT, inbound.read_buf(&mut read_buf)).await;
                    match res {
                        Ok(Ok(0)) => return Err("Client closed".into()),
                        Ok(Ok(_)) => continue,
                        _ => {
                            warn!("⏰ TLS_HELLO_TIMEOUT reached. Triggering fallback...");
                            Self::handle_stealth_fallback(inbound, outbound, buf_snapshot).await;
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    let strategy = e.execute_strategy();
                    if strategy == ErrorAction::Redirect {
                        Self::handle_stealth_fallback(inbound, outbound, buf_snapshot).await;
                    }
                    return Ok(());
                }
            }
        };

        // --- PHASE 2: Send Server Hello ---
        outbound.write_all(&hello).await.map_err(|e| e.to_string())?;

// --- PHASE 3: Secure Handshake & Engine Startup ---
        let (tx_key, tx_iv, rx_key, rx_iv) = session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::new();
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);

        let codec = Codec::new(cipher, session_keys.get_auth_key());
        let (mut rx_codec, tx_codec) = codec.split();

        let (session_id, leg_id) = loop {
            // ✅ ИСПРАВЛЕНИЕ: Теперь мы не игнорируем Err!
            match rx_codec.decode_inbound(&mut read_buf) {
                Ok(Some(frame)) => {
                    if frame.header.frame_type == FrameType::Handshake {
                        let parts: Vec<&str> = std::str::from_utf8(&frame.payload).unwrap_or("").split(':').collect();
                        if parts.len() == 2 {
                            let sid = parts[0].to_string();
                            let lid: u32 = parts[1].parse().unwrap_or(0);
                            info!("🤝 Secure Handshake verified! Session: {}, Leg: {}", sid, lid);
                            break (sid, lid);
                        }
                    }
                    return Err("Expected Handshake frame".into());
                }
                Ok(None) => {
                    // Ждем новых данных из сети
                    let n = tokio::time::timeout(SECURE_HANDSHAKE_TIMEOUT, inbound.read_buf(&mut read_buf)).await
                        .map_err(|_| "Timeout waiting for Handshake")?.map_err(|e| e.to_string())?;

                    if n == 0 { 
                        return Err("Client closed connection before Handshake".into()); 
                    }
                }
                Err(e) => {
                    // Если криптография сломалась, сразу рвем соединение и логируем
                    error!("❌ Secure Handshake Failed: {:?}", e);
                    return Err("Dropped by security strategy (Auth Phase)".into());
                }
            }
        };

        // --- PHASE 4: Engine Startup ---
        let muxer = self.session_manager.get_or_create(&session_id);
        let (control_tx, control_rx) = mpsc::channel(NetworkConfig::global().server_muxer_capacity);
        let (data_tx, data_rx) = mpsc::channel(NetworkConfig::global().server_muxer_capacity);
        muxer.add_leg(leg_id, control_tx, data_tx);

        let opener = Arc::new(RemoteOpener { muxer: muxer.clone() });
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
        muxer.remove_leg(leg_id);
        if muxer.active_legs_count() == 0 { self.session_manager.remove(&session_id); }
        res
    }
}