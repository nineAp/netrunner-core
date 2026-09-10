//! RTP-заголовок (RFC 3550 §5.1) + SRTP-подобное шифрование поверх
//! [`crate::nrxp::datagram`].
//!
//! ## Почему структура заголовка почти не оставляет свободы
//!
//! RFC 7983 демультиплексирует STUN/DTLS/TURN/RTP/RTCP по значению ПЕРВОГО
//! байта датаграммы на общем порту: RTP/RTCP — диапазон 128..191. Версия
//! RTP (2 старших бита = `10`) сама по себе кладёт нас в этот диапазон —
//! никакого отдельного усилия не требуется, но и свободы в заголовке за
//! пределами того, что реально определяет RFC 3550, нет: это не мимикрия по
//! аналогии, а сам формат.
//!
//! ## AAD — весь RTP-заголовок, как в настоящем SRTP
//!
//! RFC 3711 §3.3/RFC 7714: associated data для AEAD-вариантов SRTP — это
//! байты RTP-заголовка пакета. Здесь то же самое: 12 байт заголовка идут в
//! `aad` [`crate::nrxp::datagram::DatagramTx::seal`] — подмена SSRC/seq/PT в
//! пути не пройдёт AEAD-проверку, даже не будучи частью самого шифртекста.
//!
//! ## Epoch как MKI, а не как отдельный бит
//!
//! У RTP нет запасного бита под "какой ключ" — в отличие от QUIC (у него
//! есть Key Phase). Настоящий SRTP решает эту же задачу необязательным полем
//! MKI (Master Key Identifier, RFC 3711 §3.2) сразу после шифртекста. Многие
//! реальные WebRTC-стеки MKI не используют (ключ на сессию один и она не
//! ротируется) — то есть наше **всегда присутствующее** MKI-подобное поле
//! само по себе слабый отличительный признак. Дешевле, чем изобретать
//! нестандартное поле, и калибруется отдельно (включать/выключать, размер) —
//! см. `docs/UDP_LEG_RESEARCH.md`.

use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

use crate::nrxp::{
    truncate_counter, DatagramRx, DatagramTx, ErrorAction, ErrorStage, Frame, FrameType, TlsError,
};
use crate::webrtceng::fingerprint::WebrtcProfile;

/// V(2)=2,P=0,X=0,CC=0 + M(1)+PT(7) + seq(16) + timestamp(32) + SSRC(32),
/// без CSRC-списка (CC=0) и без header extension (X=0) — RFC 3550 §5.1.
pub(crate) const RTP_HEADER_LEN: usize = 12;
const RTP_VERSION_BITS: u8 = 0x80;

/// MKI-подобный хвост: один байт `epoch_id` (см. докстринг модуля).
const TRAILER_LEN: usize = 1;

pub(crate) struct RtpHeader {
    pub(crate) marker: bool,
    pub(crate) payload_type: u8,
    pub(crate) sequence_number: u16,
    pub(crate) timestamp: u32,
    pub(crate) ssrc: u32,
}

impl RtpHeader {
    fn encode(&self) -> [u8; RTP_HEADER_LEN] {
        let mut buf = [0u8; RTP_HEADER_LEN];
        buf[0] = RTP_VERSION_BITS;
        buf[1] = (if self.marker { 0x80 } else { 0x00 }) | (self.payload_type & 0x7f);
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        buf
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RTP_HEADER_LEN {
            return None;
        }
        // Версия ДОЛЖНА быть 2 (RFC 3550 §5.1) — заодно проверяет, что байт
        // вообще похож на RTP, а не на что-то ещё из диапазона RFC 7983.
        if bytes[0] & 0xC0 != RTP_VERSION_BITS {
            return None;
        }
        Some(Self {
            marker: bytes[1] & 0x80 != 0,
            payload_type: bytes[1] & 0x7f,
            sequence_number: u16::from_be_bytes([bytes[2], bytes[3]]),
            timestamp: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            ssrc: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        })
    }
}

fn bad_packet(what: &'static str) -> TlsError {
    TlsError::new(ErrorStage::Tls(what), ErrorAction::Drop, Bytes::new())
}

/// Исходящая сторона одного направления webrtc-подобной UDP-ноги.
pub(crate) struct WebrtcTx {
    tx: DatagramTx,
    profile: &'static WebrtcProfile,
    ssrc: u32,
    timestamp: u32,
}

impl WebrtcTx {
    /// `ssrc` — НЕ рандомизируется здесь, в отличие от `timestamp`
    /// (настоящий RTP начинает таймстамп со случайного значения, и это
    /// нигде не используется для поиска сессии). SSRC — единственное поле
    /// заголовка, доступное ДО расшифровки, поэтому это то, по чему сервер
    /// демультиплексирует входящую датаграмму на сессию: он обязан быть
    /// детерминированной функцией уже согласованного секрета
    /// (`leg_token`), а не случайным числом, которое сервер не смог бы
    /// угадать заранее. Вызывающий код (клиент/сервер connection-слоя)
    /// выводит его из `leg_token` — см. `docs/UDP_LEG_RESEARCH.md` и
    /// докстринг на точке вызова за точным соглашением о срезе байт.
    pub(crate) fn new(tx: DatagramTx, profile: &'static WebrtcProfile, ssrc: u32) -> Self {
        Self {
            tx,
            profile,
            ssrc,
            timestamp: rand::rng().random(),
        }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.tx.leg_token()
    }

    /// Шифрует один кадр NRXP как одну RTP-подобную датаграмму.
    ///
    /// `marker` — RTP marker bit; у настоящих кодеков отмечает начало кадра
    /// (например, первый пакет видеокадра) — вызывающий движок сам решает,
    /// когда его выставлять, здесь нет своей логики кадрирования.
    pub(crate) fn seal(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
        marker: bool,
    ) -> Result<Bytes, TlsError> {
        let (epoch_id, counter) = self.tx.peek_next_epoch_and_counter();
        let _ = epoch_id; // используется только для debug_assert ниже

        let header = RtpHeader {
            marker,
            payload_type: self.profile.payload_type,
            sequence_number: truncate_counter(counter, 16) as u16,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
        };
        self.timestamp = self
            .timestamp
            .wrapping_add(self.profile.timestamp_increment);
        let header_bytes = header.encode();

        let sealed = self
            .tx
            .seal(stream_id, frame_type, payload, &header_bytes)?;
        debug_assert_eq!(
            sealed.counter, counter,
            "peek_next_epoch_and_counter must predict exactly what seal used — see its contract"
        );

        let mut wire =
            BytesMut::with_capacity(RTP_HEADER_LEN + sealed.ciphertext.len() + TRAILER_LEN);
        wire.put_slice(&header_bytes);
        wire.put_slice(&sealed.ciphertext);
        wire.put_u8(sealed.epoch_id);
        Ok(wire.freeze())
    }
}

/// Входящая сторона одного направления webrtc-подобной UDP-ноги.
pub(crate) struct WebrtcRx {
    rx: DatagramRx,
}

impl WebrtcRx {
    pub(crate) fn new(rx: DatagramRx) -> Self {
        Self { rx }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.rx.leg_token()
    }

    /// Разбирает и расшифровывает одну входящую датаграмму. Возвращает
    /// разобранный RTP-заголовок вместе с кадром — вызывающему коду он не
    /// нужен для маршрутизации (это делает `Frame::stream_id`), но полезен
    /// для диагностики/будущей калибровки таймингов (см.
    /// `docs/UDP_LEG_RESEARCH.md`, раздел про мимикрию всплесков трафика).
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<(RtpHeader, Frame), TlsError> {
        if wire.len() < RTP_HEADER_LEN + TRAILER_LEN {
            return Err(bad_packet("RTP-like datagram shorter than header+trailer"));
        }
        let header =
            RtpHeader::decode(wire).ok_or_else(|| bad_packet("not a version-2 RTP header"))?;

        let mut body = Bytes::copy_from_slice(wire);
        let header_bytes = body.split_to(RTP_HEADER_LEN);
        let epoch_id = body[body.len() - 1];
        let ciphertext = body.slice(..body.len() - TRAILER_LEN);

        let frame = self.rx.open(
            epoch_id,
            header.sequence_number as u64,
            16,
            &ciphertext,
            &header_bytes,
        )?;
        Ok((header, frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DatagramKeyMaterial, SessionKeys};
    use crate::nrxp::TlsBridge;
    use crate::tlseng::{BrowserProfile as TlsProfile, ServerProfile};

    fn handshaken_pair() -> (SessionKeys, SessionKeys) {
        let mut client = SessionKeys::new(true);
        let mut server = SessionKeys::new(false);

        let ch = TlsBridge::wrap_client_hello(&TlsProfile::CHROME_140, "example.com", &client);
        let mut ch_buf = BytesMut::from(&ch[..]);
        let client_msg = TlsBridge::unpack_handshake(&mut ch_buf).unwrap().unwrap();

        let (sh, _peer_version) =
            TlsBridge::wrap_server_hello(&client_msg, &mut server, &ServerProfile::MODERN).unwrap();
        let mut sh_buf = BytesMut::from(&sh[..]);
        let server_msg = TlsBridge::unpack_handshake(&mut sh_buf).unwrap().unwrap();

        client
            .update_keys(server_msg.random(), server_msg.extensions(), false)
            .unwrap();
        (client, server)
    }

    fn tx_rx_pair() -> (WebrtcTx, WebrtcRx) {
        let (client, server) = handshaken_pair();
        let tx = WebrtcTx::new(
            DatagramTx::new(DatagramKeyMaterial::derive(&client)),
            &WebrtcProfile::OPUS_48K,
            0xC2C2_C2C2, // произвольный тестовый ssrc — вывод из leg_token тестирует connection-слой, не этот модуль
        );
        let rx = WebrtcRx::new(DatagramRx::new(DatagramKeyMaterial::derive(&server)));
        (tx, rx)
    }

    #[test]
    fn header_starts_in_the_rtp_rfc7983_demux_range() {
        let header = RtpHeader {
            marker: true,
            payload_type: 111,
            sequence_number: 42,
            timestamp: 12345,
            ssrc: 0xdead_beef,
        };
        let bytes = header.encode();
        assert!(
            (128..=191).contains(&bytes[0]),
            "first byte {} not in RFC 7983 RTP/RTCP range",
            bytes[0]
        );
    }

    #[test]
    fn seal_open_round_trip_preserves_frame_and_header_fields() {
        let (mut tx, mut rx) = tx_rx_pair();
        let wire = tx
            .seal(
                5,
                FrameType::UdpData,
                Bytes::from_static(b"voice-ish payload"),
                true,
            )
            .unwrap();

        let (header, frame) = rx.open(&wire).unwrap();
        assert!(header.marker);
        assert_eq!(header.payload_type, 111);
        assert_eq!(frame.header.stream_id, 5);
        assert_eq!(&frame.payload[..], b"voice-ish payload");
    }

    #[test]
    fn sequence_numbers_increment_across_packets() {
        let (mut tx, mut rx) = tx_rx_pair();
        let mut seqs = Vec::new();
        for i in 0..3u8 {
            let wire = tx
                .seal(1, FrameType::UdpData, Bytes::from(vec![i]), false)
                .unwrap();
            let (header, _frame) = rx.open(&wire).unwrap();
            seqs.push(header.sequence_number);
        }
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[test]
    fn tampering_with_the_header_fails_authentication() {
        let (mut tx, mut rx) = tx_rx_pair();
        let wire = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"x"), false)
            .unwrap();
        let mut tampered = BytesMut::from(&wire[..]);
        tampered[8] ^= 0xFF; // один байт SSRC — часть заголовка, часть AAD
        assert!(
            rx.open(&tampered).is_err(),
            "flipping a header byte must break AEAD auth (header is AAD)"
        );
    }

    #[test]
    fn survives_a_rekey_via_the_mki_like_trailer_byte() {
        let (mut tx, mut rx) = tx_rx_pair();
        let before = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"before"), false)
            .unwrap();
        assert!(rx.open(&before).is_ok());

        tx.tx.force_rekey_for_test();

        let after = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"after"), false)
            .unwrap();
        let (_header, frame) = rx.open(&after).unwrap();
        assert_eq!(&frame.payload[..], b"after");
    }
}
