//! Кадр локального протокола RawCast и его (де)сериализация.
//!
//! Wire-формат: 16-байтовый фиксированный заголовок + 2 байта длины payload +
//! сам payload:
//!
//! ```text
//! ┌──────────┬───────┬───────────┬─────────┬──────────┬─────────────┬─────────┐
//! │ protocol │ event │ socket_id │ dst_ip  │ dst_port │ payload_len │ payload │
//! │ 1 байт   │ 1 б.  │ 8 байт    │ 4 байта │ 2 байта  │ 2 байта     │ N байт  │
//! └──────────┴───────┴───────────┴─────────┴──────────┴─────────────┴─────────┘
//!   └──────────────── LOCAL_HEADER_SIZE = 16 ────────────────┘
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::Ipv4Addr;

use crate::parser::Parser;

/// Транспортный протокол локального сокета.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum LocalProtocol {
    Tcp = 0x01,
    Udp = 0x02,
    /// ICMP распознаётся в формате, но ядром NRXP не поддерживается (см. адаптер).
    Icmp = 0x03,
}

/// Событие жизненного цикла локального сокета.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum RawCastEvent {
    /// Новое соединение/сессия к цели.
    Connect = 0x01,
    /// Полезные данные.
    Data = 0x02,
    /// Закрытие соединения.
    Close = 0x03,
}

/// Описание одного события локального сокета — единица обмена RawCast.
#[derive(Debug, Clone)]
pub struct RawCastFrame {
    /// TCP/UDP/ICMP.
    pub protocol: LocalProtocol,
    /// Connect/Data/Close.
    pub event: RawCastEvent,
    /// Идентификатор локального сокета (→ `stream_id` в NRXP).
    pub socket_id: u64,
    /// Адрес назначения.
    pub dst_ip: Ipv4Addr,
    /// Порт назначения.
    pub dst_port: u16,
    /// Полезные данные (пусто для Connect/Close).
    pub payload: Bytes,
}

/// Размер фиксированной части заголовка (без поля длины и payload) — 16 байт.
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

    /// Кадр-событие открытия соединения (без payload).
    pub fn connect(protocol: LocalProtocol, id: u64, ip: Ipv4Addr, port: u16) -> Self {
        Self::new(protocol, RawCastEvent::Connect, id, ip, port, Bytes::new())
    }

    /// Кадр с данными соединения.
    pub fn data(protocol: LocalProtocol, id: u64, ip: Ipv4Addr, port: u16, data: Bytes) -> Self {
        Self::new(protocol, RawCastEvent::Data, id, ip, port, data)
    }

    /// Кадр-событие закрытия соединения (без payload).
    pub fn close(protocol: LocalProtocol, id: u64, ip: Ipv4Addr, port: u16) -> Self {
        Self::new(protocol, RawCastEvent::Close, id, ip, port, Bytes::new())
    }

    /// Сериализует кадр в байты по wire-формату из обзора модуля.
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

/// Разбор кадра RawCast: `can_parse` подглядывает поле длины payload по
/// смещению `LOCAL_HEADER_SIZE` и проверяет, что весь кадр на месте; `parse`
/// читает фиксированный заголовок, затем payload.
impl Parser for RawCastFrame {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < LOCAL_HEADER_SIZE + 2 {
            return false;
        }

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
