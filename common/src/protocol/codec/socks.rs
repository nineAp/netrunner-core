use bytes::{BufMut, Bytes, BytesMut};

use crate::protocol::parser::parser::Parser;

pub const SOCKS5_VERSION: u8 = 0x05;
pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_AUTH_FAILURE: u8 = 0xFF;
pub const SOCKS5_MIN_HEADER: usize = 4;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const IPV4_SIZE: usize = 4;
pub const IPV6_SIZE: usize = 16;
pub const PORT_SIZE: usize = 2;

#[derive(Debug)]
pub enum SocksRequest {
    Handshake { methods: Vec<u8> },
    Connect { command: u8, target: SocksTarget },
    Unknown,
}
impl SocksRequest {
    pub async fn handle_handshake<S>(
        stream: &mut S,
        buf: &mut BytesMut,
    ) -> Result<SocksTarget, String>
    where
        S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
    {
        // 1. Handshake Phase
        loop {
            // Используем трейт Parser
            if let Some(req) = Self::parse(buf)? {
                if let SocksRequest::Handshake { .. } = req {
                    let mut reply = BytesMut::with_capacity(2);
                    SocksReply::HandshakeSelect { method: 0x00 }.write_to(&mut reply);
                    stream.write_all(&reply).await.map_err(|e| e.to_string())?;
                    break;
                }
                return Err("Expected Handshake, got something else".into());
            }
            if stream.read_buf(buf).await.map_err(|e| e.to_string())? == 0 {
                return Err("Client closed during greeting".into());
            }
        }

        // 2. Connect Request Phase
        loop {
            if let Some(req) = Self::parse(buf)? {
                if let SocksRequest::Connect { command, target } = req {
                    // Проверяем, что это именно CONNECT (0x01)
                    if command != 0x01 {
                        return Err(format!("Unsupported SOCKS command: 0x{:02X}", command));
                    }
                    return Ok(target);
                }
            }
            if stream.read_buf(buf).await.map_err(|e| e.to_string())? == 0 {
                return Err("Client closed during connect request".into());
            }
        }
    }

    pub async fn perform_client_handshake<S>(
        stream: &mut S,
        target_addr: &std::net::SocketAddr,
    ) -> Result<(), String>
    where
        S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
    {
        // 1. Отправляем Greeting (SOCKS5, 1 метод: No Auth)
        let greeting = [SOCKS5_VERSION, 0x01, 0x00];
        stream
            .write_all(&greeting)
            .await
            .map_err(|e| e.to_string())?;

        // 2. Читаем выбор метода (должно быть 0x05 0x00)
        let mut method_selection = [0u8; 2];
        stream
            .read_exact(&mut method_selection)
            .await
            .map_err(|e| e.to_string())?;

        if method_selection[0] != SOCKS5_VERSION || method_selection[1] != 0x00 {
            return Err(format!(
                "Proxy rejected auth method or version: {:02X?}",
                method_selection
            ));
        }

        // 3. Формируем CONNECT запрос
        let mut connect_req = BytesMut::with_capacity(10);
        connect_req.put_u8(SOCKS5_VERSION);
        connect_req.put_u8(0x01); // CMD: Connect
        connect_req.put_u8(0x00); // RSV

        match target_addr {
            std::net::SocketAddr::V4(a) => {
                connect_req.put_u8(ATYP_IPV4);
                connect_req.put_slice(&a.ip().octets());
            }
            std::net::SocketAddr::V6(a) => {
                connect_req.put_u8(ATYP_IPV6);
                connect_req.put_slice(&a.ip().octets());
            }
        }
        connect_req.put_u16(target_addr.port());

        stream
            .write_all(&connect_req)
            .await
            .map_err(|e| e.to_string())?;

        // 4. Читаем ответ на Connect (REP)
        // Нам нужно как минимум 4 байта, чтобы узнать статус (REPLY_SUCCESS)
        let mut reply_header = [0u8; 4];
        stream
            .read_exact(&mut reply_header)
            .await
            .map_err(|e| e.to_string())?;

        if reply_header[1] != REPLY_SUCCESS {
            return Err(format!(
                "Proxy failed to connect, code: {:02X}",
                reply_header[1]
            ));
        }

        // Дочитываем оставшуюся часть адреса в ответе (BND.ADDR + BND.PORT),
        // чтобы очистить поток перед передачей данных.
        let atyp = reply_header[3];
        let remain_len = match atyp {
            ATYP_IPV4 => IPV4_SIZE + PORT_SIZE,
            ATYP_IPV6 => IPV6_SIZE + PORT_SIZE,
            ATYP_DOMAIN => {
                let len = stream.read_u8().await.map_err(|e| e.to_string())?;
                len as usize + PORT_SIZE
            }
            _ => return Err("Unknown ATYP in proxy response".into()),
        };

        let mut discard = vec![0u8; remain_len];
        stream
            .read_exact(&mut discard)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum SocksReply {
    HandshakeSelect {
        method: u8,
    },
    ConnectResult {
        reply_code: u8,
        atyp: u8,
        addr: [u8; 4],
        port: u16,
    },
}
#[derive(Debug)]
pub struct SocksTarget {
    pub host: Bytes,
    pub port: u16,
}

impl SocksReply {
    pub fn write_to(self, buf: &mut BytesMut) {
        match self {
            SocksReply::HandshakeSelect { method } => {
                buf.put_u8(SOCKS5_VERSION);
                buf.put_u8(method);
            }
            SocksReply::ConnectResult {
                reply_code,
                atyp,
                addr,
                port,
            } => {
                buf.put_u8(SOCKS5_VERSION);
                buf.put_u8(reply_code);
                buf.put_u8(0x00); // Reserved
                buf.put_u8(atyp);
                buf.put_slice(&addr);
                buf.put_u16(port);
            }
        }
    }
}

impl SocksTarget {
    pub fn to_string(&self) -> String {
        if self.host.len() == 4 {
            // Похоже на IPv4
            let ip =
                std::net::Ipv4Addr::new(self.host[0], self.host[1], self.host[2], self.host[3]);
            format!("{}:{}", ip, self.port)
        } else if self.host.len() == 16 {
            // Похоже на IPv6
            format!("[...]:{}", self.port)
        } else {
            // Считаем, что это домен (текст)
            let host_str = String::from_utf8_lossy(&self.host);
            format!("{}:{}", host_str, self.port)
        }
    }
}
