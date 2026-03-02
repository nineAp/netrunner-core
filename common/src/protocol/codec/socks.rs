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
