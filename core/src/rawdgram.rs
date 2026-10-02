//! Голый UDP-фолбэк: третья ступень лестницы приоритетов UDP-ноги, после
//! [`crate::quiceng`]/[`crate::webrtceng`] и перед откатом на TCP — см.
//! `docs/UDP_LEG_RESEARCH.md` §1.
//!
//! В отличие от `quiceng`/`webrtceng`, здесь нет попытки казаться чем-то
//! конкретным: заголовок — это буквально то, что нужно
//! [`crate::nrxp::datagram`], и ничего больше. Смысл существования этой
//! ступени не в маскировке, а в том, что чистый UDP кое-где проходит там,
//! где не проходит ни QUIC-, ни RTP-подобная форма (см. исследование,
//! группа II/III про то, когда это может быть так, и честные оговорки —
//! измерений нет).
//!
//! ## Формат провода
//!
//! ```text
//! ┌────────────┬───────────┬──────────────┬─────────────┐
//! │ leg_token  │ epoch_id  │ wire_counter │ ciphertext  │
//! │  16 байт   │  1 байт   │   4 байта    │  N байт     │
//! └────────────┴───────────┴──────────────┴─────────────┘
//! ```
//!
//! `leg_token` едет в открытую (он и так не секрет — тот же токен, что
//! `quiceng` кладёт в DCID, а `webrtceng` — в SSRC, просто здесь ему негде
//! больше спрятаться, раз нет чужого формата, под который маскируемся);
//! `epoch_id`+`wire_counter` — усечённое представление счётчика
//! [`crate::nrxp::datagram`] (32 бита — с огромным запасом относительно
//! [`crate::nrxp::truncate_counter`]'s ширины, используемой RTP-мимикрией).
//! AAD — весь префикс целиком, включая `leg_token`: так его подмена в пути
//! тоже не пройдёт AEAD-проверку.

use bytes::{BufMut, Bytes, BytesMut};

use crate::nrxp::{
    truncate_counter, DatagramRx, DatagramTx, ErrorAction, ErrorStage, Frame, FrameType, TlsError,
};

const WIRE_BITS: u32 = 32;
const PREFIX_LEN: usize = 16 + 1 + 4;
/// Maximum per-datagram overhead: raw wire prefix + NRXP frame header + AEAD tag.
pub(crate) const RAW_DGRAM_OVERHEAD: usize = PREFIX_LEN + 25 + 16;

fn bad_packet(what: &'static str) -> TlsError {
    TlsError::new(ErrorStage::Tls(what), ErrorAction::Drop, Bytes::new())
}

/// Исходящая сторона одной голой UDP-ноги.
pub(crate) struct RawDgramTx {
    tx: DatagramTx,
}

impl RawDgramTx {
    pub(crate) fn new(tx: DatagramTx) -> Self {
        Self { tx }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.tx.leg_token()
    }

    /// Шифрует один кадр NRXP как одну датаграмму.
    pub(crate) fn seal(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        let (epoch_id, counter) = self.tx.peek_next_epoch_and_counter();
        let wire_counter = truncate_counter(counter, WIRE_BITS) as u32;

        let mut prefix = BytesMut::with_capacity(PREFIX_LEN);
        prefix.put_slice(&self.tx.leg_token());
        prefix.put_u8(epoch_id);
        prefix.put_u32(wire_counter);

        let sealed = self.tx.seal(stream_id, frame_type, payload, &prefix)?;
        debug_assert_eq!(sealed.epoch_id, epoch_id);
        debug_assert_eq!(sealed.counter, counter);

        let mut wire = BytesMut::with_capacity(PREFIX_LEN + sealed.ciphertext.len());
        wire.put_slice(&prefix);
        wire.put_slice(&sealed.ciphertext);
        Ok(wire.freeze())
    }
}

/// Входящая сторона одной голой UDP-ноги.
pub(crate) struct RawDgramRx {
    rx: DatagramRx,
}

impl RawDgramRx {
    pub(crate) fn new(rx: DatagramRx) -> Self {
        Self { rx }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.rx.leg_token()
    }

    /// Читает `leg_token` из НЕРАСШИФРОВАННОЙ датаграммы — сервер использует
    /// это, чтобы найти нужную сессию (и, соответственно, нужный
    /// `RawDgramRx`) ДО того, как ему вообще есть с чем звать
    /// [`open`](Self::open). `None` — датаграмма короче собственного
    /// префикса, точно не наша.
    pub(crate) fn peek_leg_token(wire: &[u8]) -> Option<[u8; 16]> {
        wire.get(0..16)?.try_into().ok()
    }

    /// Разбирает и расшифровывает одну входящую датаграмму.
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<Frame, TlsError> {
        if wire.len() < PREFIX_LEN {
            return Err(bad_packet("raw datagram shorter than its own prefix"));
        }
        let prefix = &wire[..PREFIX_LEN];
        let epoch_id = wire[16];
        let wire_counter = u32::from_be_bytes(wire[17..21].try_into().unwrap()) as u64;
        let ciphertext = &wire[PREFIX_LEN..];
        self.rx
            .open(epoch_id, wire_counter, WIRE_BITS, ciphertext, prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DatagramKeyMaterial, SessionKeys};
    use crate::nrxp::TlsBridge;
    use crate::tlseng::{BrowserProfile, ServerProfile};

    fn handshaken_pair() -> (SessionKeys, SessionKeys) {
        let mut client = SessionKeys::new(true);
        let mut server = SessionKeys::new(false);

        let ch = TlsBridge::wrap_client_hello(&BrowserProfile::CHROME_140, "example.com", &client);
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

    fn tx_rx_pair() -> (RawDgramTx, RawDgramRx) {
        let (client, server) = handshaken_pair();
        let tx = RawDgramTx::new(DatagramTx::new(DatagramKeyMaterial::derive(&client)));
        let rx = RawDgramRx::new(DatagramRx::new(DatagramKeyMaterial::derive(&server)));
        (tx, rx)
    }

    #[test]
    fn seal_open_round_trip_preserves_frame_contents() {
        let (mut tx, mut rx) = tx_rx_pair();
        let wire = tx
            .seal(3, FrameType::UdpData, Bytes::from_static(b"hello raw"))
            .unwrap();
        let frame = rx.open(&wire).unwrap();
        assert_eq!(frame.header.stream_id, 3);
        assert_eq!(&frame.payload[..], b"hello raw");
    }

    #[test]
    fn peek_leg_token_matches_what_tx_and_rx_actually_use() {
        let (mut tx, rx) = tx_rx_pair();
        let wire = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"x"))
            .unwrap();
        assert_eq!(RawDgramRx::peek_leg_token(&wire), Some(tx.leg_token()));
        assert_eq!(RawDgramRx::peek_leg_token(&wire), Some(rx.leg_token()));
    }

    #[test]
    fn peek_leg_token_on_a_too_short_buffer_is_none() {
        assert_eq!(RawDgramRx::peek_leg_token(&[0u8; 10]), None);
    }

    #[test]
    fn tampering_with_the_leg_token_fails_authentication() {
        let (mut tx, mut rx) = tx_rx_pair();
        let wire = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"x"))
            .unwrap();
        let mut tampered = BytesMut::from(&wire[..]);
        tampered[0] ^= 0xFF;
        assert!(rx.open(&tampered).is_err(), "leg_token is part of the AAD");
    }

    #[test]
    fn survives_a_rekey() {
        let (mut tx, mut rx) = tx_rx_pair();
        let before = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"before"))
            .unwrap();
        assert!(rx.open(&before).is_ok());

        tx.tx.force_rekey_for_test();

        let after = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"after"))
            .unwrap();
        let frame = rx.open(&after).unwrap();
        assert_eq!(&frame.payload[..], b"after");
    }
}
