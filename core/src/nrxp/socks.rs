use std::fmt;

use bytes::{Buf, BufMut, BytesMut};

use crate::parser::Parser;

const SOCKS5_VERSION: u8 = 0x05;
const REPLY_SUCCESS: u8 = 0x00;
const REPLY_AUTH_FAILURE: u8 = 0xFF;
const SOCKS5_MIN_HEADER: usize = 4;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const IPV4_SIZE: usize = 4;
const IPV6_SIZE: usize = 16;
const PORT_SIZE: usize = 2;

#[derive(Debug)]
pub(crate) enum SocksRequest {
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
        loop {
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

        loop {
            if let Some(req) = Self::parse(buf)? {
                if let SocksRequest::Connect { command, target } = req {
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
        target_addr: &TargetAddress,
    ) -> Result<(), String>
    where
        S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
    {
        let greeting = [SOCKS5_VERSION, 0x01, 0x00];
        stream
            .write_all(&greeting)
            .await
            .map_err(|e| e.to_string())?;

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

        let mut connect_req = BytesMut::with_capacity(32);
        connect_req.put_u8(SOCKS5_VERSION);
        connect_req.put_u8(0x01);
        connect_req.put_u8(0x00);

        match target_addr {
            TargetAddress::Ipv4(ip, port) => {
                connect_req.put_u8(ATYP_IPV4);
                connect_req.put_slice(&ip.octets());
                connect_req.put_u16(*port);
            }
            TargetAddress::Ipv6(ip, port) => {
                connect_req.put_u8(ATYP_IPV6);
                connect_req.put_slice(&ip.octets());
                connect_req.put_u16(*port);
            }
            TargetAddress::Domain(host, port) => {
                connect_req.put_u8(ATYP_DOMAIN);

                let host_bytes = host.as_bytes();
                connect_req.put_u8(host_bytes.len() as u8);
                connect_req.put_slice(host_bytes);
                connect_req.put_u16(*port);
            }
        }

        stream
            .write_all(&connect_req)
            .await
            .map_err(|e| e.to_string())?;

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
pub(crate) enum SocksReply {
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

#[derive(Debug, Clone)]
pub enum TargetAddress {
    Ipv4(std::net::Ipv4Addr, u16),
    Domain(String, u16),
    Ipv6(std::net::Ipv6Addr, u16),
}

impl fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddress::Ipv4(addr, port) => write!(f, "{}:{}", addr, port),
            TargetAddress::Domain(domain, port) => write!(f, "{}:{}", domain, port),
            TargetAddress::Ipv6(addr, port) => write!(f, "[{}]:{}", addr, port),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SocksTarget {
    pub addr: TargetAddress,
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
                buf.put_u8(0x00);
                buf.put_u8(atyp);
                buf.put_slice(&addr);
                buf.put_u16(port);
            }
        }
    }
}

impl SocksTarget {
    pub fn to_string(&self) -> String {
        match &self.addr {
            TargetAddress::Ipv4(ip, port) => {
                format!("{}:{}", ip, port)
            }

            TargetAddress::Ipv6(ip, port) => {
                format!("[{}]:{}", ip, port)
            }

            TargetAddress::Domain(domain, port) => {
                let clean_domain = domain.replace('\0', "");
                format!("{}:{}", clean_domain, port)
            }
        }
    }
}

impl Parser for SocksTarget {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < 4 {
            return false;
        }

        let atyp = bytes[3];
        match atyp {
            ATYP_IPV4 => bytes.len() >= 4 + 4 + 2,

            ATYP_IPV6 => bytes.len() >= 4 + 16 + 2,

            ATYP_DOMAIN => {
                if bytes.len() < 5 {
                    return false;
                }
                let domain_len = bytes[4] as usize;
                bytes.len() >= 4 + 1 + domain_len + 2
            }
            _ => false,
        }
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let atyp = bytes[3];

        let total_len = match atyp {
            ATYP_IPV4 => SOCKS5_MIN_HEADER + IPV4_SIZE + PORT_SIZE,
            ATYP_DOMAIN => SOCKS5_MIN_HEADER + 1 + (bytes[4] as usize) + PORT_SIZE,
            ATYP_IPV6 => SOCKS5_MIN_HEADER + IPV6_SIZE + PORT_SIZE,
            _ => return Err("Unsupported address type".to_string()),
        };

        let mut packet = bytes.split_to(total_len);
        packet.advance(4);

        let addr = match atyp {
            ATYP_IPV4 => {
                let octets: [u8; 4] = packet.split_to(4)[..].try_into().unwrap();
                let port = packet.get_u16();
                TargetAddress::Ipv4(octets.into(), port)
            }
            ATYP_DOMAIN => {
                let len = packet.get_u8() as usize;
                let domain_bytes = packet.split_to(len);
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|_| "Invalid UTF-8 domain".to_string())?;
                let port = packet.get_u16();
                TargetAddress::Domain(domain, port)
            }
            ATYP_IPV6 => {
                let octets: [u8; 16] = packet.split_to(16)[..].try_into().unwrap();
                let port = packet.get_u16();
                TargetAddress::Ipv6(octets.into(), port)
            }
            _ => unreachable!(),
        };

        Ok(Some(SocksTarget { addr }))
    }
}

impl Parser for SocksRequest {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < 2 || bytes[0] != SOCKS5_VERSION {
            return false;
        }

        let nmethods = bytes[1] as usize;
        if bytes.len() >= 2 + nmethods {
            if bytes.len() >= SOCKS5_MIN_HEADER && SocksTarget::can_parse(bytes) {
                return true;
            }

            return true;
        }

        false
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if bytes.len() < 2 || bytes[0] != SOCKS5_VERSION {
            return Ok(None);
        }

        if bytes.len() >= SOCKS5_MIN_HEADER && SocksTarget::can_parse(bytes) {
            let command = bytes[1];
            if let Some(target) = SocksTarget::parse(bytes)? {
                return Ok(Some(SocksRequest::Connect { command, target }));
            }
        }

        let nmethods = bytes[1] as usize;
        let total_handshake = 2 + nmethods;

        if bytes.len() >= total_handshake {
            let mut packet = bytes.split_to(total_handshake);
            packet.advance(2);
            let mut methods = vec![0u8; nmethods];
            packet.copy_to_slice(&mut methods);

            return Ok(Some(SocksRequest::Handshake { methods }));
        }

        Ok(None)
    }
}
