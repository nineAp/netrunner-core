use bytes::{Buf, BytesMut};

use crate::protocol::{codec::socks::*, parser::parser::Parser};

impl Parser for SocksTarget {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < SOCKS5_MIN_HEADER {
            return false;
        }

        let atyp = bytes[3];
        match atyp {
            ATYP_IPV4 => bytes.len() >= SOCKS5_MIN_HEADER + IPV4_SIZE + PORT_SIZE,
            ATYP_DOMAIN => {
                if bytes.len() < SOCKS5_MIN_HEADER + 1 {
                    return false;
                }
                let domain_len = bytes[4] as usize;
                bytes.len() >= SOCKS5_MIN_HEADER + 1 + domain_len + PORT_SIZE
            }
            ATYP_IPV6 => bytes.len() >= SOCKS5_MIN_HEADER + IPV6_SIZE + PORT_SIZE,
            _ => false,
        }
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let atyp = bytes[3];

        // Вычисляем длину еще раз для split_to (либо можно вынести в хелпер)
        let total_len = match atyp {
            ATYP_IPV4 => SOCKS5_MIN_HEADER + IPV4_SIZE + PORT_SIZE,
            ATYP_DOMAIN => SOCKS5_MIN_HEADER + 1 + (bytes[4] as usize) + PORT_SIZE,
            ATYP_IPV6 => SOCKS5_MIN_HEADER + IPV6_SIZE + PORT_SIZE,
            _ => return Err("Unsupported address type".to_string()),
        };

        let mut packet = bytes.split_to(total_len);
        packet.advance(SOCKS5_MIN_HEADER);

        let addr = match atyp {
            ATYP_IPV4 => {
                let octets: [u8; 4] = packet.split_to(4)[..].try_into().unwrap();
                TargetAddress::Ipv4(octets.into())
            }
            ATYP_DOMAIN => {
                let len = packet.get_u8() as usize;
                let domain_bytes = packet.split_to(len);
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|_| "Invalid UTF-8 domain".to_string())?;
                TargetAddress::Domain(domain)
            }
            ATYP_IPV6 => {
                let octets: [u8; 16] = packet.split_to(16)[..].try_into().unwrap();
                TargetAddress::Ipv6(octets.into())
            }
            _ => unreachable!(),
        };

        let port = packet.get_u16();
        Ok(Some(SocksTarget { addr, port }))
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
            // Это может быть Handshake. Проверяем, не Connect ли это (мин. 6-10 байт)
            if bytes.len() >= SOCKS5_MIN_HEADER && SocksTarget::can_parse(bytes) {
                return true;
            }
            // Если для Connect данных мало или структура не совпадает,
            // но для Handshake достаточно — ок.
            return true;
        }

        false
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if bytes.len() < 2 || bytes[0] != SOCKS5_VERSION {
            return Ok(None);
        }

        // 1. Пытаемся распарсить как Connect (у него строгая структура)
        if bytes.len() >= SOCKS5_MIN_HEADER && SocksTarget::can_parse(bytes) {
            let command = bytes[1];
            if let Some(target) = SocksTarget::parse(bytes)? {
                return Ok(Some(SocksRequest::Connect { command, target }));
            }
        }

        // 2. Если не Connect, пробуем Handshake
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
