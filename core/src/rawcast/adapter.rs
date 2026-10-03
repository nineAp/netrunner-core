//! Трансляция между локальным протоколом RawCast и протоколом туннеля NRXP.
//!
//! [`RawCastAdapter`] — чистый «переводчик» без состояния. Соответствия:
//! `socket_id` ⇄ `stream_id`, `(protocol, event)` ⇄ [`FrameType`]. Для `Connect`
//! без явного payload адрес назначения упаковывается строкой `"ip:port"` — это
//! то, что ожидает серверная сторона при открытии потока.

use bytes::Bytes;
use std::net::Ipv4Addr;

use crate::{
    nrxp::{Frame, FrameType},
    rawcast::frame::{LocalProtocol, RawCastEvent, RawCastFrame},
};

/// Безсостоятельный конвертер RawCast ⇄ NRXP.
pub struct RawCastAdapter;

impl RawCastAdapter {
    /// RawCast → NRXP. Маппит протокол+событие в [`FrameType`]; для `Connect`
    /// без payload подставляет адрес цели строкой `"ip:port"`. ICMP отвергается —
    /// ядро NRXP его не проксирует.
    pub(crate) fn to_nrxp(raw: RawCastFrame, strong_privacy: bool) -> Result<Frame, String> {
        let stream_id = raw.socket_id as u32;

        let (frame_type, payload) = match (raw.protocol, raw.event) {
            (LocalProtocol::Tcp, RawCastEvent::Connect) => {
                let final_payload = if !raw.payload.is_empty() {
                    raw.payload
                } else {
                    Bytes::from(format!("{}:{}", raw.dst_ip, raw.dst_port))
                };
                (
                    if strong_privacy {
                        FrameType::SecureConnect
                    } else {
                        FrameType::Connect
                    },
                    final_payload,
                )
            }
            (LocalProtocol::Udp, RawCastEvent::Connect) => {
                let final_payload = if !raw.payload.is_empty() {
                    raw.payload
                } else {
                    Bytes::from(format!("{}:{}", raw.dst_ip, raw.dst_port))
                };
                (
                    if strong_privacy {
                        FrameType::SecureUdpConnect
                    } else {
                        FrameType::UdpConnect
                    },
                    final_payload,
                )
            }
            (LocalProtocol::Tcp, RawCastEvent::Data) => (FrameType::Data, raw.payload),
            (LocalProtocol::Udp, RawCastEvent::Data) => (FrameType::UdpData, raw.payload),
            (_, RawCastEvent::Close) => (FrameType::Close, Bytes::new()),
            (LocalProtocol::Icmp, _) => {
                return Err("ICMP protocol is not supported by NRXP core".into())
            }
        };

        Ok(Frame::new(stream_id, frame_type, payload))
    }

    /// NRXP → RawCast. Обратный перевод; `is_udp` задаёт протокол локального
    /// сокета (в NRXP-кадре эта информация частично растворена в типе). Кадры
    /// `Heartbeat` сюда попадать не должны — их обрабатывает muxer, не мост.
    pub(crate) fn from_nrxp(
        nrxp_frame: Frame,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        is_udp: bool,
    ) -> Result<RawCastFrame, String> {
        let socket_id = nrxp_frame.header.stream_id as u64;
        let protocol = if is_udp {
            LocalProtocol::Udp
        } else {
            LocalProtocol::Tcp
        };

        let event = match nrxp_frame.header.frame_type {
            FrameType::Connect
            | FrameType::UdpConnect
            | FrameType::SecureConnect
            | FrameType::SecureUdpConnect
            | FrameType::MeshOnionConnect
            | FrameType::MeshOnionUdpConnect => RawCastEvent::Connect,
            FrameType::Data | FrameType::UdpData => RawCastEvent::Data,
            FrameType::Close => RawCastEvent::Close,
            FrameType::Heartbeat => return Err("Heartbeat should be handled by muxer".into()),
            FrameType::Diag => {
                return Err("Diag frame is handled by diagnostics, not the bridge".into())
            }
            FrameType::Credit => {
                return Err("Credit frame is handled by muxer, not the bridge".into())
            }
            FrameType::Cover => {
                return Err("Cover frame is discarded by the handler, not the bridge".into())
            }
        };

        Ok(RawCastFrame {
            protocol,
            event,
            socket_id,
            dst_ip,
            dst_port,
            payload: nrxp_frame.payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_privacy_uses_dedicated_tcp_and_udp_connect_bytes() {
        let tcp = RawCastAdapter::to_nrxp(
            RawCastFrame::connect(LocalProtocol::Tcp, 17, Ipv4Addr::new(203, 0, 113, 8), 443),
            true,
        )
        .unwrap();
        assert_eq!(tcp.header.frame_type, FrameType::SecureConnect);
        assert_eq!(tcp.header.stream_id, 17);

        let udp = RawCastAdapter::to_nrxp(
            RawCastFrame::connect(LocalProtocol::Udp, 18, Ipv4Addr::new(203, 0, 113, 9), 443),
            true,
        )
        .unwrap();
        assert_eq!(udp.header.frame_type, FrameType::SecureUdpConnect);
        assert_eq!(udp.header.stream_id, 18);
    }
}
