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
    },
    tlseng::profile::BrowserProfile,
};
use bytes::BytesMut;
use netrunner_logger::info;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

pub const BUF_SIZE: usize = 16384;

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
            read_buf: BytesMut::with_capacity(BUF_SIZE),
            codec: Codec::new(init),
        }
    }

    pub fn new_raw(inbound: OwnedReadHalf, outbound: OwnedWriteHalf) -> Self {
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(BUF_SIZE),
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
            .make_client_handshake(&BrowserProfile::CHROME_131, "google.com")
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

        let (mux_tx, mux_rx) = mpsc::channel(BUF_SIZE);
        let muxer = Muxer::new(mux_tx, true);

        let handler =
            std::sync::Arc::new(StreamHandler::new(muxer.clone(), ConnectionRole::Client));

        let engine = TunnelEngine {
            inbound: conn.inbound,
            outbound: conn.outbound,
            codec: conn.codec,
            read_buf: conn.read_buf,
            mux_rx,
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
                let (v_tx, mut v_rx) = mpsc::channel::<bytes::Bytes>(1024);
                self.muxer.register_stream(stream_id, v_tx).await;

                self.muxer
                    .send_to_netwrok(MuxMessage {
                        stream_id,
                        frame_type: FrameType::Connect,
                        data: bytes::Bytes::from(target.to_string()),
                    })
                    .await
                    .map_err(|e| e.to_string())?;

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

#[async_trait::async_trait]
impl TunnelHandler for ServerHandler {
    async fn run(mut self) -> Result<(), String> {
        info!("Acting as TLS Server");
        let (mux_tx, mux_rx) = mpsc::channel(BUF_SIZE);
        let muxer = Muxer::new(mux_tx, false);

        let hello = loop {
            match self
                .conn
                .codec
                .make_server_handshake(&mut self.conn.read_buf)
            {
                Ok(b) => break b,
                Err(e) if e.action == ErrorAction::Wait => {
                    if self
                        .conn
                        .inbound
                        .read_buf(&mut self.conn.read_buf)
                        .await
                        .map_err(|e| e.to_string())?
                        == 0
                    {
                        return Err("Closed".into());
                    }
                }
                Err(e) => return Err(format!("{:?}", e)),
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
            mux_rx,
            handler,
            token: self.token,
        }
        .run()
        .await
    }
}
