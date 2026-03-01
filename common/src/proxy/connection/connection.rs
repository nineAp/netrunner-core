use bytes::{Bytes, BytesMut};
use tracing::{instrument, info, debug, error, trace, warn};
use std::{net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc::{self},
};

use crate::{
    protocol::{
        codec::{
            codec::Codec,
            frame::FrameType,
            socks::{SocksReply, SocksRequest, SocksTarget},
        },
        errors::ErrorAction,
        parser::parser::Parser,
    },
    proxy::connection::{
        bridge::run_proxy_bridge, engine::TunnelEngine, handler::StreamHandler, muxer::{MuxMessage, Muxer}
    },
};

pub const BUF_SIZE: usize = 16384;


#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionRole {
    Client,
    Server,
}

pub struct Connection {
    addr: SocketAddr,
    pub inbound: OwnedReadHalf,
    pub outbound: OwnedWriteHalf,
    pub read_buf: BytesMut,
    pub codec: Codec,
}

impl Connection {
    pub fn new(
        stream: TcpStream,
        addr: SocketAddr,
        init: bool,
    ) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            addr,
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(BUF_SIZE),
            codec: Codec::new(init),
        }
    }

    /// Читает и парсит запрос SOCKS5 из входящего потока
    async fn read_socks_request(&mut self) -> Result<SocksRequest, String> {
        loop {
            // Попытка парсинга из текущего буфера
            match SocksRequest::parse(&mut self.read_buf) {
                Ok(Some(req)) => {
                    // Используем Debug-вывод (?req), так как SocksRequest обычно Enum
                    info!(client = %self.addr, request = ?req, "SOCKS request successfully parsed");
                    return Ok(req);
                }
                Ok(None) => {
                    // Это не ошибка, просто данных в сокете пока меньше, чем размер структуры SOCKS
                    trace!(client = %self.addr, buffer_len = self.read_buf.len(), "SOCKS parse: need more data");
                } 
                Err(e) => {
                    error!(client = %self.addr, error = %e, "SOCKS protocol violation");
                    return Err(format!("Socks parse error: {}", e));
                }
            }

            // Чтение новых данных из сокета
            let n = self
                .inbound
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| {
                    error!(client = %self.addr, error = %e, "Failed to read from socket during SOCKS handshake");
                    e.to_string()
                })?;

            if n == 0 {
                warn!(client = %self.addr, "Client closed connection prematurely during SOCKS handshake");
                return Err("Client closed connection during SOCKS handshake".into());
            }
            
            trace!(client = %self.addr, read_bytes = n, "Read data from client for SOCKS handshake");
        }
    }

    /// Отправляет SOCKS ответ
    async fn send_socks_reply(&mut self, reply: SocksReply) -> Result<(), String> {
        let mut buf = BytesMut::with_capacity(24);
        debug!(client = %self.addr, reply = ?reply, "Sending SOCKS reply to client");
        reply.write_to(&mut buf);



        self.outbound
            .write_all(&buf)
            .await
            .map_err(|e| {
                error!(client = %self.addr, error = %e, "Failed to send SOCKS reply");
                e.to_string()
            })?;

        Ok(())
    }

    #[instrument(
        name = "socks_handler",
        skip(self, muxer), 
        fields(addr = %self.addr)
    )]
    pub async fn handle_socks_client(mut self, muxer: Muxer) -> Result<(), String> {
        info!("Starting SOCKS multiplexed handling");

        // 1. SOCKS Handshake
        debug!("Reading SOCKS handshake request");
        let _ = self.read_socks_request().await.map_err(|e| {
            error!("SOCKS handshake failed: {}", e);
            e
        })?;
        
        self.send_socks_reply(SocksReply::HandshakeSelect { method: 0x00 }).await?;

        // 2. SOCKS Connect
    // 2. SOCKS Connect - читаем, КУДА хочет браузер
        let req = self.read_socks_request().await?;
        let target = if let SocksRequest::Connect { target, .. } = req {
            target
        } else {
            return Err("Expected Connect".into());
        };

        let stream_id = muxer.next_id();
        let target_str = match &target {
            SocksTarget { host, port } => format!("{}:{}", String::from_utf8_lossy(host), port),
        };

        // --- НОВАЯ ЛОГИКА ОЖИДАНИЯ ---
        // Регистрируем временный канал, чтобы получить Connect-подтверждение от сервера
        let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(1024);
        muxer.register_stream(stream_id, v_tx).await;

        // Отправляем Connect-кадр на сервер
        muxer.to_network.send(MuxMessage {
            stream_id,
            frame_type: FrameType::Connect,
            data: Bytes::from(target_str),
        }).await.map_err(|e| e.to_string())?;

        let first_payload = match tokio::time::timeout(std::time::Duration::from_secs(10), v_rx.recv()).await {
            Ok(Some(data)) => data,
            _ => {
                error!(stream_id, "Server timeout or failed to send Connect confirmation");
                // Шлем браузеру ошибку, если сервер промолчал
                self.send_socks_reply(SocksReply::ConnectResult {
                    reply_code: 0x01, atyp: 0x01, addr: [0, 0, 0, 0], port: 0,
                }).await.ok();
                return Err("Target connection failed".into());
            }
        };

        // Проверяем код ответа (второй байт в SOCKS5)
        if first_payload.len() >= 2 && first_payload[1] == 0x00 {
            debug!(stream_id, "Server confirmed connection, forwarding SOCKS reply to browser");
            
            // ВАЖНО: Отправляем браузеру ТО, что прислал сервер (те самые 10 байт)
            // Не создаем новый SocksReply вручную, а пробрасываем байты сервера
            self.outbound.write_all(&first_payload).await.map_err(|e| e.to_string())?;
        } else {
            // Если сервер прислал ошибку (reply_code != 0), тоже пробрасываем её браузеру и выходим
            self.outbound.write_all(&first_payload).await.ok();
            return Err("Server rejected connection".into());
        }

        // 4. Разбираем self и запускаем хендлер
        let Self { inbound: browser_in, outbound: browser_out, .. } = self;
        
        let muxer_clone = muxer.clone();
        tokio::spawn(async move {
            run_proxy_bridge(stream_id, browser_in, browser_out, muxer_clone, v_rx).await;
        });

        Ok(())
    }

    #[instrument(
        name = "server_tunnel",
        skip(self), 
        fields(addr = %self.addr)
    )]
    pub async fn handle_server_tunnel(mut self) -> Result<(), String> {
        info!("Acting as TLS Server, waiting for ClientHello");

        // Создаем Muxer для сервера
        let (mux_tx, mux_rx) = mpsc::channel(BUF_SIZE);
        let muxer = Muxer::new(mux_tx.clone(), false); // false, так как это Сервер

        // 1. TLS Handshake
        let server_hello_bytes = loop {
            match self.codec.make_server_handshake(&mut self.read_buf) {
                Ok(bytes) => {
                    info!("ClientHello received, sending ServerHello");
                    break bytes;
                },
                Err(e) if e.action == ErrorAction::Wait => {
                    let n = self.inbound.read_buf(&mut self.read_buf).await
                        .map_err(|err| format!("Read error: {}", err))?;

                    if n == 0 { return Err("Client closed connection".into()); }
                }
                Err(e) => return Err(format!("TLS error: {:?}", e)),
            }
        };

        self.outbound.write_all(&server_hello_bytes).await.map_err(|e| e.to_string())?;
        info!("TLS Tunnel established as server");

        let handler = std::sync::Arc::new(StreamHandler::new(muxer.clone(), ConnectionRole::Server));

        // 2. Передача управления в TunnelEngine
        debug!("Handover to TunnelEngine");
        let engine = TunnelEngine {
            inbound: self.inbound,
            outbound: self.outbound,    
            codec: self.codec,
            read_buf: self.read_buf,
            mux_rx,
            handler
        };

        engine.run().await.map_err(|e| {
            error!("TunnelEngine error: {}", e);
            e
        })
    }

}
