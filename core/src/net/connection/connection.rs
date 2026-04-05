use std::{net::Ipv4Addr, sync::Arc};

use crate::{
    net::{
        connection::{
            engine::TunnelEngine,
            handler::{RemoteOpener, StreamHandler},
            muxer::Muxer,
        },
        NetworkConfig, FALLBACK_CONNECT_TIMEOUT, LEG_RECONNECT_DELAY, LEG_STAGGER_DELAY,
        MAX_TUNNEL_LEGS, SECURE_HANDSHAKE_TIMEOUT, TLS_HELLO_TIMEOUT, TOPOLOGY_PRINT_INTERVAL,
    },
    nrxp::{Codec, ErrorAction, Frame, FrameType},
    rawcast::{LocalProtocol, RawCastAdapter, RawCastFrame},
    tlseng::BrowserProfile,
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use netrunner_logger::{error, info, warn};
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

    pub fn get_or_create(&self, session_id: &str) -> Arc<Muxer> {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Muxer::new(false, session_id.to_string())))
            .clone()
    }

    pub fn remove(&self, session_id: &str) {
        if self.sessions.remove(session_id).is_some() {
            netrunner_logger::info!("🧹 Session {} completely closed and cleaned up", session_id);
        }
    }
}

#[async_trait::async_trait]
pub trait TunnelHandler {
    async fn run(self) -> Result<(), String>;
}

pub struct Connection {
    pub(crate) inbound: OwnedReadHalf,
    pub(crate) outbound: OwnedWriteHalf,
    pub(crate) read_buf: BytesMut,
    pub(crate) codec: Codec,
}

impl Connection {
    pub fn new(stream: TcpStream, init: bool) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(NetworkConfig::global().tcp_buffer_size),
            codec: Codec::new(init),
        }
    }

    pub fn new_raw(inbound: OwnedReadHalf, outbound: OwnedWriteHalf) -> Self {
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(NetworkConfig::global().tcp_buffer_size),
            codec: Codec::new(false),
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
        let leg_name = if leg_id % 2 == 0 {
            "TCP-Leg"
        } else {
            "UDP-Leg"
        };

        info!(
            "Establishing dedicated {} (ID: {}) to {}...",
            leg_name, leg_id, remote_proxy_addr
        );

        let stream = TcpStream::connect(remote_proxy_addr)
            .await
            .map_err(|e| format!("Failed to connect: {}", e))?;
        let _ = stream.set_nodelay(true);
        let (inbound, outbound) = stream.into_split();
        let mut conn = Connection::new_raw(inbound, outbound);

        let ch = conn
            .codec
            .make_client_handshake(&BrowserProfile::CHROME_131, "ubuntu.com")
            .map_err(|e| format!("Handshake generation failed: {:?}", e))?;

        conn.outbound
            .write_all(&ch)
            .await
            .map_err(|e| e.to_string())?;

        loop {
            match conn.codec.process_handshake(&mut conn.read_buf) {
                Ok(_) => break,
                Err(e) if e.action == ErrorAction::Wait => {
                    let n = conn
                        .inbound
                        .read_buf(&mut conn.read_buf)
                        .await
                        .map_err(|e| e.to_string())?;
                    if n == 0 {
                        return Err(format!("EOF on {}", leg_name));
                    }
                }
                Err(e) => return Err(format!("TLS error on {}: {:?}", leg_name, e)),
            }
        }

        info!("{} TLS Handshake complete.", leg_name);
        let handshake_payload = Bytes::from(format!("{}:{}", session_id, leg_id));

        let encrypted_handshake = conn
            .codec
            .encrypt_data(0, FrameType::Handshake, handshake_payload)
            .map_err(|e| format!("Failed to encrypt Handshake: {:?}", e))?;

        conn.outbound
            .write_all(&encrypted_handshake)
            .await
            .map_err(|e| format!("Failed to send Handshake: {}", e))?;

        info!(
            "{} Sent Encrypted Handshake (Leg: {}). Starting engine...",
            leg_name, leg_id
        );

        let (control_tx, control_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);
        let (data_tx, data_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);

        muxer.add_leg(leg_id, control_tx, data_tx);

        let handler = Arc::new(StreamHandler::new(muxer.clone(), None));

        let engine = TunnelEngine {
            leg_id,
            inbound: conn.inbound,
            outbound: conn.outbound,
            codec: conn.codec,
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

        info!("🚀 Netrunner Multi-Path Tunnel Initializing (10 Legs max).");

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
                if m_stats.active_legs_count() == 0 {
                    break;
                }

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

                            info!(
                                "🔗 [Muxer] Forwarding {} request to {} (Local ID: {} -> Global ID: {})",
                                if is_udp { "UDP" } else { "TCP" },
                                String::from_utf8_lossy(&payload),
                                local_socket_id,
                                global_stream_id
                            );

                            local_to_global.insert(local_socket_id, global_stream_id);
                            registry.insert(
                                global_stream_id,
                                (local_socket_id, dst_ip, dst_port, protocol),
                            );

                            let (v_tx, mut v_rx) =
                                mpsc::channel(NetworkConfig::global().tcp_stream_capacity);

                            muxer_inner.register_stream(global_stream_id, v_tx);

                            let tx_to_tun = tx_to_engine.clone();
                            let reg = registry.clone();

                            tokio::spawn(async move {
                                while let Some(back_payload) = v_rx.recv().await {
                                    // ✅ ИСПРАВЛЕНИЕ 1: Копируем данные и отпускаем DashMap до .await
                                    let ctx = reg.get(&global_stream_id).map(|r| *r);

                                    if let Some((orig_local_id, ip, port, proto)) = ctx {
                                        let out_f_type = if proto == LocalProtocol::Udp {
                                            FrameType::UdpData
                                        } else {
                                            FrameType::Data
                                        };

                                        let mock_nrxp =
                                            Frame::new(orig_local_id, out_f_type, back_payload);

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
                            });

                            // ✅ Добавлен .await
                            let _ = muxer_inner
                                .send_control(global_stream_id, f_type, payload)
                                .await;
                        }
                        FrameType::Data | FrameType::UdpData => {
                            // ✅ ИСПРАВЛЕНИЕ 2: Сброс блокировки DashMap
                            let global_stream_id =
                                local_to_global.get(&local_socket_id).map(|r| *r);

                            if let Some(id) = global_stream_id {
                                // ✅ Добавлен .await
                                let _ = muxer_inner.send_data_safe(id, payload, is_udp).await;
                            } else {
                                warn!(
                                    "Data received for unknown local socket_id: {}",
                                    local_socket_id
                                );
                            }
                        }
                        FrameType::Close => {
                            // .remove() сам по себе возвращает владение данными и снимает лок мгновенно,
                            // поэтому здесь дедлока не было, но мы добавляем .await для вызова Муксера.
                            if let Some((_, global_stream_id)) =
                                local_to_global.remove(&local_socket_id)
                            {
                                // ✅ Добавлен .await
                                let _ = muxer_inner
                                    .send_control(global_stream_id, FrameType::Close, Bytes::new())
                                    .await;

                                muxer_inner.remove_stream(global_stream_id);
                                registry.remove(&global_stream_id);
                            }
                        }
                        _ => {
                            warn!("Unhandled FrameType from adapter: {:?}", f_type);
                        }
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
        Self {
            conn: connection,
            session_manager: Arc::new(SessionManager::new()),
        }
    }

    async fn handle_stealth_fallback(
        mut client_inbound: OwnedReadHalf,
        mut client_outbound: OwnedWriteHalf,
        initial_data: bytes::Bytes,
    ) {
        let target_host = "ubuntu.com:443";
        info!(target = %target_host, "Stealth fallback: bridging to Target");

        let target_stream =
            tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(target_host)).await;

        match target_stream {
            Ok(Ok(target_server)) => {
                let (mut server_read, mut server_write) = target_server.into_split();

                if !initial_data.is_empty() {
                    if let Err(e) = server_write.write_all(&initial_data).await {
                        warn!("Failed to push initial data to fallback: {}", e);
                        return;
                    }
                }

                let res = tokio::io::copy_bidirectional(
                    &mut tokio::io::join(&mut client_inbound, &mut client_outbound),
                    &mut tokio::io::join(&mut server_read, &mut server_write),
                )
                .await;

                match res {
                    Ok((from_client, from_server)) => {
                        info!(
                            "Fallback closed. Sent: {} bytes, Recv: {} bytes",
                            from_client, from_server
                        );
                    }
                    Err(e) => warn!("Fallback bridge error: {}", e),
                }
            }
            Ok(Err(e)) => warn!("Fallback connect error: {}", e),
            Err(_) => warn!("Fallback connection timed out (Target unreachable)"),
        }
    }
}

#[async_trait::async_trait]
impl TunnelHandler for ServerHandler {
    async fn run(mut self) -> Result<(), String> {
        info!("Acting as TLS Server with Stealth Fallback");

        let hello = loop {
            let buf_snapshot = self.conn.read_buf.clone().freeze();
            match self
                .conn
                .codec
                .make_server_handshake(&mut self.conn.read_buf)
            {
                Ok(b) => break b,
                Err(e) => match e.execute_strategy() {
                    ErrorAction::Wait => {
                        let res = tokio::time::timeout(
                            TLS_HELLO_TIMEOUT,
                            self.conn.inbound.read_buf(&mut self.conn.read_buf),
                        )
                        .await;

                        match res {
                            Ok(Ok(0)) => return Err("Client closed".into()),
                            Ok(Ok(_)) => continue,
                            _ => {
                                Self::handle_stealth_fallback(
                                    self.conn.inbound,
                                    self.conn.outbound,
                                    buf_snapshot,
                                )
                                .await;
                                return Ok(());
                            }
                        }
                    }
                    ErrorAction::Redirect => {
                        Self::handle_stealth_fallback(
                            self.conn.inbound,
                            self.conn.outbound,
                            buf_snapshot,
                        )
                        .await;
                        return Ok(());
                    }
                    ErrorAction::Drop => {
                        return Err("Dropped by security strategy (TLS Phase)".into());
                    }
                },
            }
        };

        self.conn
            .outbound
            .write_all(&hello)
            .await
            .map_err(|e| e.to_string())?;

        let (session_id, leg_id) = loop {
            let n = tokio::time::timeout(
                SECURE_HANDSHAKE_TIMEOUT,
                self.conn.inbound.read_buf(&mut self.conn.read_buf),
            )
            .await
            .map_err(|_| "Timeout waiting for Handshake".to_string())?
            .map_err(|e| e.to_string())?;

            if n == 0 {
                return Err("Client closed connection before Handshake".into());
            }

            match self.conn.codec.inbound(&mut self.conn.read_buf) {
                Ok(Some(frame)) => {
                    if frame.header.frame_type == FrameType::Handshake {
                        let payload_str = String::from_utf8_lossy(&frame.payload).to_string();
                        let parts: Vec<&str> = payload_str.split(':').collect();

                        if parts.len() == 2 {
                            let sid = parts[0].to_string();
                            let lid: u32 = parts[1].parse().unwrap_or(0);
                            info!(
                                "🤝 Secure Handshake verified! Session: {}, Leg: {}",
                                sid, lid
                            );
                            break (sid, lid);
                        }
                        return Err("Invalid Handshake format".into());
                    }
                    return Err("Expected Handshake frame".into());
                }
                Ok(None) => continue,
                Err(e) => {
                    let buf_snapshot = self.conn.read_buf.clone().freeze();
                    match e.execute_strategy() {
                        ErrorAction::Redirect => {
                            Self::handle_stealth_fallback(
                                self.conn.inbound,
                                self.conn.outbound,
                                buf_snapshot,
                            )
                            .await;
                            return Ok(());
                        }
                        _ => {
                            return Err("Dropped by security strategy (Auth Phase)".into());
                        }
                    }
                }
            }
        };

        let muxer = self.session_manager.get_or_create(&session_id);

        let (control_tx, control_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);
        let (data_tx, data_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);
        muxer.add_leg(leg_id, control_tx, data_tx);

        let opener = Arc::new(RemoteOpener {
            muxer: muxer.clone(),
        });
        let handler = Arc::new(StreamHandler::new(muxer.clone(), Some(opener)));

        let m_weak = Arc::downgrade(&muxer);
        tokio::spawn(async move {
            while let Some(m_stats) = m_weak.upgrade() {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                if m_stats.active_legs_count() == 0 {
                    break;
                }
                m_stats.print_topology_tree();
            }
        });

        let engine = TunnelEngine {
            leg_id,
            inbound: self.conn.inbound,
            outbound: self.conn.outbound,
            codec: self.conn.codec,
            read_buf: self.conn.read_buf,
            control_rx,
            data_rx,
            handler,
            muxer: muxer.clone(),
        };

        let res = engine.run().await;

        muxer.remove_leg(leg_id);
        if muxer.active_legs_count() == 0 {
            self.session_manager.remove(&session_id);
        }

        res
    }
}
