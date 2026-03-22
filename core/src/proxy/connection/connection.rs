use crate::{
    protocol::{
        codec::{
            codec::Codec,
            frame::FrameType,
            socks::{SocksReply, SocksRequest},
        },
        errors::ErrorAction,
        parser::parser::Parser,
    },
    proxy::connection::{
        bridge::run_proxy_bridge,
        engine::TunnelEngine,
        handler::StreamHandler,
        muxer::{MuxMessage, Muxer},
        MESSAGE_CHANNEL_SIZE, TCP_BUF_SIZE,
    },
    tlseng::profile::BrowserProfile,
};
use bytes::{Bytes, BytesMut};
use netrunner_logger::{info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

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
    pub inbound: OwnedReadHalf,
    pub outbound: OwnedWriteHalf,
    pub read_buf: BytesMut,
    pub codec: Codec,
}

impl Connection {
    pub fn new(stream: TcpStream, init: bool) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(TCP_BUF_SIZE),
            codec: Codec::new(init),
        }
    }

    pub fn new_raw(inbound: OwnedReadHalf, outbound: OwnedWriteHalf) -> Self {
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(TCP_BUF_SIZE),
            codec: Codec::new(false),
        }
    }

    pub async fn read_socks_request(&mut self) -> Result<SocksRequest, String> {
        loop {
            match SocksRequest::parse(&mut self.read_buf) {
                Ok(Some(req)) => return Ok(req),
                Ok(None) => {}
                Err(e) => return Err(format!("Socks parse error: {}", e)),
            }
            let n = self
                .inbound
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("Client closed connection".into());
            }
        }
    }

    pub async fn send_socks_reply(&mut self, reply: SocksReply) -> Result<(), String> {
        let mut buf = BytesMut::with_capacity(24);
        reply.write_to(&mut buf);
        self.outbound
            .write_all(&buf)
            .await
            .map_err(|e| e.to_string())
    }
}

pub struct ClientHandler {
    pub conn: Connection,
    pub muxer: Muxer,
}

impl ClientHandler {
    pub async fn connect(
        remote_proxy_addr: &str,
        token: CancellationToken,
    ) -> Result<Muxer, String> {
        let stream = TcpStream::connect(remote_proxy_addr)
            .await
            .map_err(|e| e.to_string())?;
        let (inbound, outbound) = stream.into_split();

        let mut conn = Connection::new_raw(inbound, outbound);

        let ch = conn
            .codec
            .make_client_handshake(&BrowserProfile::CHROME_131, "ubuntu.com")
            .map_err(|e| format!("{:?}", e))?;
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
                        return Err("EOF during handshake".into());
                    }
                }
                Err(e) => return Err(format!("TLS error: {:?}", e)),
            }
        }

        // --- ИЗМЕНЕНИЕ ДЛЯ НОВОГО MUXER ---
        let (control_tx, control_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);
        let (data_tx, data_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);

        let muxer = Muxer::new(control_tx, data_tx, true);

        let handler =
            std::sync::Arc::new(StreamHandler::new(muxer.clone(), ConnectionRole::Client));

        let engine = TunnelEngine {
            inbound: conn.inbound,
            outbound: conn.outbound,
            codec: conn.codec,
            read_buf: conn.read_buf,
            control_rx, // Передаем оба ресивера в Engine
            data_rx,    // Передаем оба ресивера в Engine
            handler,
            token: token.clone(),
        };

        tokio::spawn(async move { engine.run().await });

        Ok(muxer)
    }

    async fn handle_udp_associate(&mut self) -> Result<(), String> {
        let reply = SocksReply::ConnectResult {
            reply_code: 0x00,
            atyp: 0x01,
            addr: [0, 0, 0, 0],
            port: 0,
        };
        self.conn.send_socks_reply(reply).await?;

        let mut buf = [0u8; 1024];
        loop {
            if self
                .conn
                .inbound
                .read(&mut buf)
                .await
                .map_err(|e| e.to_string())?
                == 0
            {
                break;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl TunnelHandler for ClientHandler {
    async fn run(mut self) -> Result<(), String> {
        info!("Starting SOCKS multiplexed handling");

        self.conn.read_socks_request().await?;
        self.conn
            .send_socks_reply(SocksReply::HandshakeSelect { method: 0x00 })
            .await?;

        let req = self.conn.read_socks_request().await?;

        match req {
            SocksRequest::Connect {
                command: 0x01,
                target,
            } => {
                let stream_id = self.muxer.next_id();
                let (v_tx, mut v_rx) = mpsc::channel::<bytes::Bytes>(TCP_BUF_SIZE);
                self.muxer.register_stream(stream_id, v_tx);

                // Используем send_control для отправки FrameType::Connect
                self.muxer
                    .send_control(
                        stream_id,
                        FrameType::Connect,
                        bytes::Bytes::from(target.to_string()),
                    )
                    .await?;

                let first_payload =
                    tokio::time::timeout(std::time::Duration::from_secs(10), v_rx.recv())
                        .await
                        .map_err(|_| "Timeout waiting for proxy response")?
                        .ok_or("No data from proxy")?;

                if first_payload.len() >= 2 && first_payload[1] == 0x00 {
                    self.conn
                        .outbound
                        .write_all(&first_payload)
                        .await
                        .map_err(|e| e.to_string())?;
                } else {
                    self.conn.outbound.write_all(&first_payload).await.ok();
                    return Err("Proxy rejected connection".into());
                }

                let browser_in = self.conn.inbound;
                let browser_out = self.conn.outbound;
                let muxer = self.muxer;

                tokio::spawn(async move {
                    run_proxy_bridge(stream_id, browser_in, browser_out, muxer, v_rx).await;
                });
                Ok(())
            }

            SocksRequest::Connect { command: 0x03, .. } => {
                info!("Handling UDP Associate request");
                self.handle_udp_associate().await
            }

            _ => Err("Unsupported SOCKS command".into()),
        }
    }
}

pub struct ServerHandler {
    pub conn: Connection,
    pub token: CancellationToken,
}
impl ServerHandler {
    async fn handle_stealth_fallback(
        mut client_inbound: OwnedReadHalf,
        mut client_outbound: OwnedWriteHalf,
        initial_data: bytes::Bytes,
    ) {
        let target_host = "ubuntu.com:443";
        info!(target = %target_host, "Stealth fallback: bridging to Target");

        // 1. Пытаемся подключиться с коротким таймаутом
        let target_stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            TcpStream::connect(target_host),
        )
        .await;

        match target_stream {
            Ok(Ok(mut target_server)) => {
                let (mut server_read, mut server_write) = target_server.into_split();

                // 2. Скармливаем те байты, которые уже вычитали (Client Hello)
                if !initial_data.is_empty() {
                    if let Err(e) = server_write.write_all(&initial_data).await {
                        warn!("Failed to push initial data to fallback: {}", e);
                        return;
                    }
                }

                // 3. Запускаем bidirectional copy
                // Это создаст две задачи, которые будут перекачивать байты, пока одна сторона не закроется
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

        let (control_tx, control_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);
        let (data_tx, data_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);
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
                            // Используем наш снимок, так как основной буфер мог быть частично съеден
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
                    // ВАЖНО: используем сохраненный buf_snapshot
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

        // Если дошли сюда — значит это наш клиент, шлем Server Hello
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
            token: self.token,
        }
        .run()
        .await
    }
}
