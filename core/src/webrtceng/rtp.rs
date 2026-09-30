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
//! ## Epoch БЕЗ поля на проводе — перебором
//!
//! У RTP нет запасного бита под "какой ключ". Раньше `epoch_id` ехал одним
//! байтом-трейлером сразу после шифртекста (MKI-подобно), но для первых 2²⁰
//! пакетов этот байт был `0x00` — сигнатура в один байт (bug #15): в настоящем
//! SRTP на этом месте auth tag с равномерно случайными байтами. Теперь трейлера
//! НЕТ вовсе: приёмник восстанавливает эпоху перебором соседних
//! (`current` → `current+1` → `current-1`), как и допускает
//! [`crate::nrxp::datagram::DatagramRx`]. На горячем пути срабатывает первая же
//! проба (та же эпоха); лишние попытки бывают только на редкой границе rekey
//! (раз в 2²⁰ пакетов), а неуспешная проба AEAD не имеет побочных эффектов.

use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

use crate::nrxp::{
    truncate_counter, DatagramRx, DatagramTx, ErrorAction, ErrorStage, Frame, FrameType, TlsError,
};
use crate::webrtceng::fingerprint::WebrtcProfile;

/// Фиксированная часть RTP-заголовка: V(2)=2,P=0,X,CC=0 + M(1)+PT(7) + seq(16)
/// + timestamp(32) + SSRC(32) — RFC 3550 §5.1.
pub(crate) const RTP_HEADER_LEN: usize = 12;
const RTP_VERSION_BITS: u8 = 0x80;
const EXTENSION_BIT: u8 = 0x10; // X в первом байте

/// Заголовочное расширение (X=1), одноbyte-header формат RFC 8285: profile
/// `0xBEDE`, длина 1 слово (4 байта), внутри — один элемент (напр. abs-send-time,
/// id=1). Браузеры почти всегда шлют расширения — X=0 сам по себе признак
/// (bug #16). Размер фиксирован у нас; на приёме длину читаем из поля.
const EXT_PROFILE: u16 = 0xBEDE;
const EXT_WORDS: u16 = 1; // 1 × 32-бита данных
/// Байты данных расширения (1 слово = 4 байта).
const EXT_DATA_LEN: usize = 4;
const EXTENSION_LEN: usize = 4 + EXT_DATA_LEN; // header(4) + data

pub(crate) struct RtpHeader {
    pub(crate) marker: bool,
    pub(crate) payload_type: u8,
    pub(crate) sequence_number: u16,
    pub(crate) timestamp: u32,
    pub(crate) ssrc: u32,
    /// Присутствует ли заголовочное расширение (бит X). На передаче всегда
    /// `true` (см. `EXTENSION_LEN`); на приёме — как прочитано с провода.
    pub(crate) has_extension: bool,
}

impl RtpHeader {
    /// Кодирует заголовок вместе с расширением, если `has_extension`. Возвращает
    /// байты переменной длины (12 или 12+`EXTENSION_LEN`).
    fn encode(&self, ext_data: &[u8; EXT_DATA_LEN]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(RTP_HEADER_LEN + EXTENSION_LEN);
        let x = if self.has_extension { EXTENSION_BIT } else { 0 };
        buf.put_u8(RTP_VERSION_BITS | x);
        buf.put_u8((if self.marker { 0x80 } else { 0x00 }) | (self.payload_type & 0x7f));
        buf.put_u16(self.sequence_number);
        buf.put_u32(self.timestamp);
        buf.put_u32(self.ssrc);
        if self.has_extension {
            buf.put_u16(EXT_PROFILE);
            buf.put_u16(EXT_WORDS);
            buf.put_slice(ext_data);
        }
        buf
    }

    /// Разбирает фиксированный заголовок и, если X=1, вычисляет полную длину
    /// заголовка (с расширением). Возвращает `(header, header_len)`.
    fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < RTP_HEADER_LEN {
            return None;
        }
        // Версия ДОЛЖНА быть 2 (RFC 3550 §5.1) — заодно проверяет, что байт
        // вообще похож на RTP, а не на что-то ещё из диапазона RFC 7983.
        if bytes[0] & 0xC0 != RTP_VERSION_BITS {
            return None;
        }
        let has_extension = bytes[0] & EXTENSION_BIT != 0;
        let mut header_len = RTP_HEADER_LEN;
        if has_extension {
            if bytes.len() < RTP_HEADER_LEN + 4 {
                return None;
            }
            let words = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
            header_len = RTP_HEADER_LEN + 4 + words * 4;
            if bytes.len() < header_len {
                return None;
            }
        }
        Some((
            Self {
                marker: bytes[1] & 0x80 != 0,
                payload_type: bytes[1] & 0x7f,
                sequence_number: u16::from_be_bytes([bytes[2], bytes[3]]),
                timestamp: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                ssrc: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
                has_extension,
            },
            header_len,
        ))
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
    /// Случайная база RTP timestamp (RFC 3550: старт случаен). Дальше timestamp
    /// растёт по РЕАЛЬНОМУ времени × тактовую (см. `seal`), а не на фиксированный
    /// шаг за пакет — иначе при загрузке он заметно расходился бы со временем
    /// прихода (bug #16). Значение косметическое: приёмник читает его с провода
    /// как AAD и никак не интерпретирует.
    ts_base: u32,
    start: Instant,
}

impl WebrtcTx {
    /// `ssrc` — единственное поле заголовка, доступное ДО расшифровки, поэтому по
    /// нему сервер демультиплексирует датаграмму на сессию: он обязан быть
    /// детерминированной функцией `leg_token`, а не случайным числом. Начальный
    /// RTP `seq` при этом рандомизируется (RFC 3550) — через сдвиг стартового
    /// счётчика [`DatagramTx::reseed_counter`], который приёмник восстанавливает
    /// сам (bug #16).
    pub(crate) fn new(mut tx: DatagramTx, profile: &'static WebrtcProfile, ssrc: u32) -> Self {
        // Случайный 16-битный старт `seq`. Полный счётчик = start + i
        // реконструируется приёмником из усечённого seq, nonce остаётся уникальным.
        let seq_start: u16 = rand::rng().random();
        tx.reseed_counter(seq_start as u64);
        Self {
            tx,
            profile,
            ssrc,
            ts_base: rand::rng().random(),
            start: Instant::now(),
        }
    }

    pub(crate) fn leg_token(&self) -> [u8; 16] {
        self.tx.leg_token()
    }

    /// Timestamp по реальному времени: `ts_base + elapsed_secs × clock_rate`.
    fn current_timestamp(&self) -> u32 {
        let ticks = (self.start.elapsed().as_secs_f64() * self.profile.clock_rate as f64) as u64;
        self.ts_base.wrapping_add(ticks as u32)
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
        let (_epoch_id, counter) = self.tx.peek_next_epoch_and_counter();

        // Заголовочное расширение (X=1): abs-send-time-подобные 3 байта из
        // текущего timestamp + 1 байт заполнителя. Косметика (уходит в AAD).
        let ts = self.current_timestamp();
        let ext_data: [u8; 4] = [(ts >> 16) as u8, (ts >> 8) as u8, ts as u8, 0x00];

        let header = RtpHeader {
            marker,
            payload_type: self.profile.payload_type,
            sequence_number: truncate_counter(counter, 16) as u16,
            timestamp: ts,
            ssrc: self.ssrc,
            has_extension: true,
        };
        let header_bytes = header.encode(&ext_data);

        let sealed = self
            .tx
            .seal(stream_id, frame_type, payload, &header_bytes)?;
        debug_assert_eq!(
            sealed.counter, counter,
            "peek_next_epoch_and_counter must predict exactly what seal used — see its contract"
        );

        // Без трейлера-эпохи (bug #15): приёмник восстанавливает эпоху перебором.
        let mut wire = BytesMut::with_capacity(header_bytes.len() + sealed.ciphertext.len());
        wire.put_slice(&header_bytes);
        wire.put_slice(&sealed.ciphertext);
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
    ///
    /// Эпоха восстанавливается ПЕРЕБОРОМ (`current` → `current+1` → `current-1`),
    /// потому что на проводе её больше нет (bug #15). Неуспешная проба AEAD не
    /// имеет побочных эффектов (см. `DatagramRx::open`), поэтому перебор
    /// безопасен; на горячем пути срабатывает первая же проба.
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<(RtpHeader, Frame), TlsError> {
        let (header, header_len) =
            RtpHeader::decode(wire).ok_or_else(|| bad_packet("not a version-2 RTP header"))?;
        if wire.len() < header_len {
            return Err(bad_packet("RTP-like datagram shorter than its header"));
        }
        // AAD — ВЕСЬ заголовок, включая расширение (как на передаче).
        let header_bytes = Bytes::copy_from_slice(&wire[..header_len]);
        let ciphertext = Bytes::copy_from_slice(&wire[header_len..]);
        let seq = header.sequence_number as u64;

        let current = self.rx.current_epoch_id();
        for epoch in [
            current,
            current.wrapping_add(1),
            current.wrapping_sub(1),
        ] {
            if let Ok(frame) = self.rx.open(epoch, seq, 16, &ciphertext, &header_bytes) {
                return Ok((header, frame));
            }
        }
        Err(bad_packet(
            "RTP-like AEAD open failed for current/next/previous epoch",
        ))
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
            &WebrtcProfile::VP8_VIDEO,
            0xC2C2_C2C2, // произвольный тестовый ssrc — вывод из leg_token тестирует connection-слой, не этот модуль
        );
        let rx = WebrtcRx::new(DatagramRx::new(DatagramKeyMaterial::derive(&server)));
        (tx, rx)
    }

    #[test]
    fn header_starts_in_the_rtp_rfc7983_demux_range_and_sets_the_extension_bit() {
        let header = RtpHeader {
            marker: true,
            payload_type: 96,
            sequence_number: 42,
            timestamp: 12345,
            ssrc: 0xdead_beef,
            has_extension: true,
        };
        let bytes = header.encode(&[0u8; 4]);
        assert!(
            (128..=191).contains(&bytes[0]),
            "first byte {} not in RFC 7983 RTP/RTCP range",
            bytes[0]
        );
        assert_ne!(bytes[0] & EXTENSION_BIT, 0, "X bit must be set (bug #16)");
        assert_eq!(bytes.len(), RTP_HEADER_LEN + EXTENSION_LEN);
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
        assert_eq!(header.payload_type, 96);
        assert!(header.has_extension, "sender always sets X=1");
        assert_eq!(frame.header.stream_id, 5);
        assert_eq!(&frame.payload[..], b"voice-ish payload");
    }

    #[test]
    fn sequence_numbers_start_random_but_increment_by_one() {
        let (mut tx, mut rx) = tx_rx_pair();
        let mut seqs = Vec::new();
        for i in 0..3u8 {
            let wire = tx
                .seal(1, FrameType::UdpData, Bytes::from(vec![i]), false)
                .unwrap();
            let (header, _frame) = rx.open(&wire).unwrap();
            seqs.push(header.sequence_number);
        }
        // Старт случаен (bug #16) — НЕ обязан быть 0, но растёт строго на 1
        // (с возможным 16-битным оборотом).
        assert_eq!(seqs[1], seqs[0].wrapping_add(1));
        assert_eq!(seqs[2], seqs[1].wrapping_add(1));
    }

    /// Хвостового байта эпохи больше нет (bug #15): длина провода — это ровно
    /// заголовок(+расширение) + шифртекст, без лишнего байта в конце.
    #[test]
    fn no_trailing_epoch_byte_on_the_wire() {
        let (mut tx, mut rx) = tx_rx_pair();
        let wire = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"payload"), false)
            .unwrap();
        // Разбираем длину заголовка сами и проверяем, что после шифртекста
        // ничего лишнего нет: open принимает ровно этот буфер.
        let (_h, frame) = rx.open(&wire).unwrap();
        assert_eq!(&frame.payload[..], b"payload");
        // Ещё раз тот же байтовый буфер, но с одним лишним байтом в конце —
        // AEAD не сойдётся (шифртекст изменился по длине).
        let mut with_extra = BytesMut::from(&wire[..]);
        with_extra.put_u8(0x00);
        assert!(
            rx.open(&with_extra).is_err(),
            "a stray trailing byte must not be silently accepted"
        );
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
    fn survives_a_rekey_via_epoch_trial() {
        let (mut tx, mut rx) = tx_rx_pair();
        let before = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"before"), false)
            .unwrap();
        assert!(rx.open(&before).is_ok());

        tx.tx.force_rekey_for_test();

        let after = tx
            .seal(1, FrameType::UdpData, Bytes::from_static(b"after"), false)
            .unwrap();
        // Приёмник восстанавливает новую эпоху перебором, без поля на проводе.
        let (_header, frame) = rx.open(&after).unwrap();
        assert_eq!(&frame.payload[..], b"after");
    }
}
