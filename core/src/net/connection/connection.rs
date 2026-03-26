use crate::{
    net::{
        connection::{engine::TunnelEngine, handler::StreamHandler, muxer::Muxer},
        network::NetworkConfig,
    },
    nrxp::{Codec, ErrorAction, FrameType},
    rawcast::{LocalProtocol, RawCastEvent, RawCastFrame},
    tlseng::BrowserProfile,
};
use bytes::{Bytes, BytesMut};
use netrunner_logger::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionRole {
    Client,
    Server,
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

pub struct ClientHandler;

impl ClientHandler {
    /// Вспомогательная функция: устанавливает одно физическое TLS-соединение
    /// и возвращает готовый Muxer для работы с ним.
    async fn establish_leg(remote_proxy_addr: &str, leg_name: &str) -> Result<Muxer, String> {
        info!(
            "Establishing dedicated {} tunnel to {}...",
            leg_name, remote_proxy_addr
        );

        let stream = TcpStream::connect(remote_proxy_addr)
            .await
            .map_err(|e| format!("Failed to connect: {}", e))?;

        if let Err(e) = stream.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY on {} leg: {}", leg_name, e);
        }
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
                        return Err(format!("EOF during handshake on {} leg", leg_name));
                    }
                }
                Err(e) => return Err(format!("TLS error on {} leg: {:?}", leg_name, e)),
            }
        }

        info!("{} TLS Handshake complete. Starting Engine.", leg_name);

        let (control_tx, control_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);
        let (data_tx, data_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);

        let muxer = Muxer::new(control_tx, data_tx, true);
        let handler =
            std::sync::Arc::new(StreamHandler::new(muxer.clone(), ConnectionRole::Client));

        let engine = TunnelEngine {
            inbound: conn.inbound,
            outbound: conn.outbound,
            codec: conn.codec,
            read_buf: conn.read_buf,
            control_rx,
            data_rx,
            handler,
        };

        tokio::spawn(async move { engine.run().await });

        Ok(muxer)
    }

    /// Главная функция запуска клиента
    pub async fn connect(
        remote_proxy_addr: &str,
        mut rx_from_engine: mpsc::Receiver<RawCastFrame>,
        tx_to_engine: mpsc::Sender<RawCastFrame>,
    ) -> Result<(), String> {
        // 1. Устанавливаем ДВА независимых соединения
        // Мы можем сделать это параллельно через tokio::try_join! для скорости
        let (tcp_muxer, udp_muxer) = tokio::try_join!(
            Self::establish_leg(remote_proxy_addr, "TCP"),
            Self::establish_leg(remote_proxy_addr, "UDP"),
        )?;

        info!("Dual-tunnel architecture established successfully!");

        // 2. ЗАПУСКАЕМ МОСТ-РОУТЕР
        tokio::spawn(async move {
            while let Some(raw_frame) = rx_from_engine.recv().await {
                let stream_id = raw_frame.socket_id as u32;
                let is_udp = raw_frame.protocol == LocalProtocol::Udp;

                // РОУТИНГ: Выбираем нужный физический канал
                let muxer = if is_udp {
                    udp_muxer.clone()
                } else {
                    tcp_muxer.clone()
                };

                match raw_frame.event {
                    RawCastEvent::Connect => {
                        let (v_tx, mut v_rx) =
                            mpsc::channel(NetworkConfig::global().tcp_buffer_size);
                        muxer.register_stream(stream_id, v_tx);

                        // Читаем домен, который мы прокинули в предыдущем шаге
                        let target = if !raw_frame.payload.is_empty() {
                            String::from_utf8_lossy(&raw_frame.payload).to_string()
                        } else {
                            format!("{}:{}", raw_frame.dst_ip, raw_frame.dst_port)
                        };

                        let frame_type = if is_udp {
                            FrameType::UdpConnect
                        } else {
                            FrameType::Connect
                        };

                        if let Err(e) = muxer
                            .send_control(stream_id, frame_type, Bytes::from(target))
                            .await
                        {
                            error!("Failed to send connect control frame: {}", e);
                            continue;
                        }

                        let tx_engine_clone = tx_to_engine.clone();
                        let mut muxer_clone = muxer.clone();
                        let dst_ip = raw_frame.dst_ip;
                        let dst_port = raw_frame.dst_port;
                        let protocol = raw_frame.protocol;
                        let socket_id = raw_frame.socket_id;

                        tokio::spawn(async move {
                            while let Some(payload) = v_rx.recv().await {
                                let data_frame = RawCastFrame::data(
                                    protocol,
                                    socket_id,
                                    dst_ip,
                                    dst_port,
                                    payload.to_vec(),
                                );
                                if tx_engine_clone.send(data_frame).await.is_err() {
                                    break;
                                }
                            }
                            muxer_clone.remove_stream(stream_id);
                        });
                    }

                    RawCastEvent::Data => {
                        let frame_type = if is_udp {
                            FrameType::UdpData
                        } else {
                            FrameType::Data
                        };

                        if let Err(e) = muxer
                            .send_control(stream_id, frame_type, raw_frame.payload)
                            .await
                        {
                            error!("Failed to send data frame: {}", e);
                        }
                    }

                    RawCastEvent::Close => {
                        let _ = muxer
                            .send_control(stream_id, FrameType::Close, Bytes::new())
                            .await;
                        muxer.remove_stream(stream_id);
                    }
                }
            }
            info!("ClientHandler bridge task terminated.");
        });

        Ok(())
    }
}
pub struct ServerHandler {
    pub(crate) conn: Connection,
}

impl ServerHandler {
    async fn handle_stealth_fallback(
        mut client_inbound: OwnedReadHalf,
        mut client_outbound: OwnedWriteHalf,
        initial_data: bytes::Bytes,
    ) {
        let target_host = "ubuntu.com:443";
        info!(target = %target_host, "Stealth fallback: bridging to Target");

        let target_stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            TcpStream::connect(target_host),
        )
        .await;

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

        let (control_tx, control_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);
        let (data_tx, data_rx) = mpsc::channel(NetworkConfig::global().muxer_capacity);
        let muxer = Muxer::new(control_tx, data_tx, false);

        let handshake_timeout = std::time::Duration::from_secs(1);

        let hello = loop {
            let buf_snapshot = self.conn.read_buf.clone().freeze();

            match self
                .conn
                .codec
                .make_server_handshake(&mut self.conn.read_buf)
            {
                Ok(b) => break b,
                Err(e) if e.action == ErrorAction::Wait => {
                    let read_res = tokio::time::timeout(
                        handshake_timeout,
                        self.conn.inbound.read_buf(&mut self.conn.read_buf),
                    )
                    .await;

                    match read_res {
                        Ok(Ok(n)) if n == 0 => return Err("Client closed".into()),
                        Ok(Ok(_)) => continue,
                        Ok(Err(e)) => return Err(e.to_string()),
                        Err(_) => {
                            warn!("Handshake timeout. Going stealth.");

                            ServerHandler::handle_stealth_fallback(
                                self.conn.inbound,
                                self.conn.outbound,
                                buf_snapshot,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    warn!("Auth/Format failed: {:?}. Going stealth.", e);

                    info!(
                        "DEBUG: Restoring {} bytes from snapshot for fallback",
                        buf_snapshot.len()
                    );

                    ServerHandler::handle_stealth_fallback(
                        self.conn.inbound,
                        self.conn.outbound,
                        buf_snapshot,
                    )
                    .await;
                    return Ok(());
                }
            }
        };

        self.conn
            .outbound
            .write_all(&hello)
            .await
            .map_err(|e| e.to_string())?;

        let handler = std::sync::Arc::new(StreamHandler::new(muxer, ConnectionRole::Server));

        TunnelEngine {
            inbound: self.conn.inbound,
            outbound: self.conn.outbound,
            codec: self.conn.codec,
            read_buf: self.conn.read_buf,
            control_rx,
            data_rx,
            handler,
        }
        .run()
        .await
    }
}
