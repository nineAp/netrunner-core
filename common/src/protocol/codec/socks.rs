use bytes::{BufMut, Bytes, BytesMut};

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
        let host_str = String::from_utf8_lossy(&self.host);
        format!("{}:{}", host_str, self.port)
    }
}
