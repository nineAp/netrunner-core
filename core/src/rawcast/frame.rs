use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;

use crate::parser::Parser;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum LocalProtocol {
    Tcp = 0x01,
    Udp = 0x02,
    Icmp = 0x03,
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum RawCastEvent {
    Connect = 0x01,
    Data = 0x02,
    Close = 0x03,
}

#[derive(Debug, Clone)]
pub struct RawCastFrame {
    pub protocol: LocalProtocol,
    pub event: RawCastEvent,
    pub socket_id: u64,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub payload: Bytes,
}

const LOCAL_HEADER_SIZE: usize = 16;

impl RawCastFrame {
    fn new(
        protocol: LocalProtocol,
        event: RawCastEvent,
        socket_id: u64,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: Bytes,
    ) -> Self {
        Self {
            protocol,
            event,
            socket_id,
            dst_ip,
            dst_port,
            payload,
        }
    }

    pub fn connect(protocol: LocalProtocol, id: u64, ip: Ipv4Addr, port: u16) -> Self {
        Self::new(protocol, RawCastEvent::Connect, id, ip, port, Bytes::new())
    }

    pub fn data(protocol: LocalProtocol, id: u64, ip: Ipv4Addr, port: u16, data: Vec<u8>) -> Self {
        Self::new(
            protocol,
            RawCastEvent::Data,
            id,
            ip,
            port,
            Bytes::from(data),
        )
    }

    pub fn close(protocol: LocalProtocol, id: u64, ip: Ipv4Addr, port: u16) -> Self {
        Self::new(protocol, RawCastEvent::Close, id, ip, port, Bytes::new())
    }

    pub fn into_bytes(self) -> BytesMut {
        let total_size = LOCAL_HEADER_SIZE + 2 + self.payload.len();
        let mut buf = BytesMut::with_capacity(total_size);

        buf.put_u8(self.protocol as u8);
        buf.put_u8(self.event as u8);
        buf.put_u64(self.socket_id);
        buf.put_slice(&self.dst_ip.octets());
        buf.put_u16(self.dst_port);
        buf.put_u16(self.payload.len() as u16);
        buf.put(self.payload);

        buf
    }
}

impl Parser for RawCastFrame {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < LOCAL_HEADER_SIZE + 2 {
            return false;
        }

        // читаем длину payload без сдвига буфера
        let payload_len_pos = LOCAL_HEADER_SIZE;
        let payload_len =
            u16::from_be_bytes([bytes[payload_len_pos], bytes[payload_len_pos + 1]]) as usize;

        bytes.len() >= LOCAL_HEADER_SIZE + 2 + payload_len
    }

    fn parse(buf: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(buf) {
            return Ok(None);
        }

        let mut header = buf.split_to(LOCAL_HEADER_SIZE);

        let protocol = match header.get_u8() {
            0x01 => LocalProtocol::Tcp,
            0x02 => LocalProtocol::Udp,
            0x03 => LocalProtocol::Icmp,
            p => return Err(format!("Unknown local protocol: {}", p)),
        };

        let event = match header.get_u8() {
            0x01 => RawCastEvent::Connect,
            0x02 => RawCastEvent::Data,
            0x03 => RawCastEvent::Close,
            e => return Err(format!("Unknown local event: {}", e)),
        };

        let socket_id = header.get_u64();

        let ip_bytes = [
            header.get_u8(),
            header.get_u8(),
            header.get_u8(),
            header.get_u8(),
        ];
        let dst_ip = Ipv4Addr::from(ip_bytes);

        let dst_port = header.get_u16();

        let payload_len = buf.get_u16() as usize;
        let payload = buf.split_to(payload_len).freeze();

        Ok(Some(Self {
            protocol,
            event,
            socket_id,
            dst_ip,
            dst_port,
            payload,
        }))
    }
}
