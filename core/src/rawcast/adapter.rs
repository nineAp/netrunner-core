use bytes::Bytes;
use std::net::Ipv4Addr;
// Добавили импорт логгеров для детального трейсинга
use netrunner_logger::{debug, trace};

use crate::{
    nrxp::{Frame, FrameType},
    rawcast::frame::{LocalProtocol, RawCastEvent, RawCastFrame},
};

pub struct RawCastAdapter;

impl RawCastAdapter {
    /// Перевод из RawCast (от локального TUN/smoltcp) в NRXP (в ядро/сеть)
    pub(crate) fn to_nrxp(raw: RawCastFrame) -> Result<Frame, String> {
        // Кастим ID сокета
        let stream_id = raw.socket_id as u32;

        let (frame_type, payload) = match (raw.protocol, raw.event) {
            // Открытие TCP соединения
            (LocalProtocol::Tcp, RawCastEvent::Connect) => {
                // Если payload не пустой (ConnectionManager положил туда домен) - используем его.
                // Иначе фоллбэк: собираем из сырого IP и порта.
                let final_payload = if !raw.payload.is_empty() {
                    raw.payload
                } else {
                    Bytes::from(format!("{}:{}", raw.dst_ip, raw.dst_port))
                };

                debug!(
                    "🧩 [Adapter TCP] Stream {}: Packing Connect target: {}",
                    stream_id,
                    String::from_utf8_lossy(&final_payload)
                );

                (FrameType::Connect, final_payload)
            }
            // Открытие UDP сессии
            (LocalProtocol::Udp, RawCastEvent::Connect) => {
                // Аналогичная логика защиты переданного таргета для UDP
                let final_payload = if !raw.payload.is_empty() {
                    raw.payload
                } else {
                    Bytes::from(format!("{}:{}", raw.dst_ip, raw.dst_port))
                };

                debug!(
                    "🧩 [Adapter UDP] Stream {}: Packing UdpConnect target: {}",
                    stream_id,
                    String::from_utf8_lossy(&final_payload)
                );

                (FrameType::UdpConnect, final_payload)
            }

            // Передача данных (TCP)
            (LocalProtocol::Tcp, RawCastEvent::Data) => (FrameType::Data, raw.payload),
            // Передача данных (UDP)
            (LocalProtocol::Udp, RawCastEvent::Data) => (FrameType::UdpData, raw.payload),

            // Закрытие соединения (одинаково для TCP и UDP)
            (_, RawCastEvent::Close) => {
                trace!("🧩 [Adapter] Stream {}: Packing Close frame", stream_id);
                (FrameType::Close, Bytes::new())
            }

            // ICMP пока не поддерживается в NRXP, отбрасываем
            (LocalProtocol::Icmp, _) => {
                return Err("ICMP protocol is not supported by NRXP core".into());
            }
        };

        // Используем твой новый удобный конструктор Frame!
        Ok(Frame::new(stream_id, frame_type, payload))
    }

    /// Перевод из NRXP (от сервера) обратно в RawCast (в smoltcp)
    ///
    /// ВАЖНО: Так как NRXP Frame не содержит IP и Port (только stream_id),
    /// локальный клиент должен помнить, какому stream_id какой IP/Port принадлежит.
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
            // Сервер прислал успешный коннект
            FrameType::Connect | FrameType::UdpConnect => {
                trace!(
                    "🧩 [Adapter] Stream {}: Unpacked Connect Ack from server",
                    socket_id
                );
                RawCastEvent::Connect
            }

            // Сервер прислал данные
            FrameType::Data | FrameType::UdpData => RawCastEvent::Data,

            // Сервер закрыл соединение
            FrameType::Close => {
                trace!(
                    "🧩 [Adapter] Stream {}: Unpacked Close signal from server",
                    socket_id
                );
                RawCastEvent::Close
            }

            FrameType::Handshake => {
                return Err(
                    "Handshake frame detected. Muxer should consume it, not the Adapter.".into(),
                );
            }

            FrameType::Heartbeat => return Err("Heartbeat should be handled by muxer".into()),
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
