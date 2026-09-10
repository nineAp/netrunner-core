//! QUIC short-header (1-RTT) пакет: раскладка полей — RFC 9000 §17.3.1,
//! header protection — RFC 9001 §5.4.1 (общая процедура) и §5.4.4
//! (ChaCha20-вариант маски). Смещения и битовые маски сверены с текстом RFC,
//! не взяты по памяти — см. `docs/UDP_LEG_RESEARCH.md` за тем, где именно
//! это важно (Initial-секреты по тому же принципу — в `initial.rs`).
//!
//! Полезная нагрузка после снятия header protection — обычный шифртекст
//! [`crate::nrxp::datagram`]: у наблюдателя без ключей нет способа отличить
//! "настоящий QUIC 1-RTT, ключей нет" от этого — оба выглядят как корректно
//! устроенный заголовок поверх непрозрачных байт.

use bytes::{BufMut, Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

use crate::nrxp::{DatagramRx, DatagramTx, ErrorAction, ErrorStage, Frame, FrameType, TlsError};

/// Header Protection sample (RFC 9001 §5.4.2) — 16 байт для всех cipher
/// suite'ов TLS 1.3, кроме AES-128-CCM-8 (мы им не пользуемся нигде).
const SAMPLE_LEN: usize = 16;
/// Sample начинается через 4 байта ПОСЛЕ начала поля Packet Number — считается
/// от фиксированного смещения независимо от настоящей длины PN, что и решает
/// проблему курицы и яйца (длина PN сама под маской, см. [`ShortHeaderPacket::decode`]).
const SAMPLE_OFFSET_FROM_PN: usize = 4;
/// RFC 9000 §17.3.1: у short header маскируются 5 младших бит первого байта
/// (Reserved×2 + Key Phase×1 + PN Length×2). У long header их было бы 4
/// (нет Spin/Key Phase) — см. `initial.rs`.
const SHORT_HEADER_MASK: u8 = 0x1f;

/// Один QUIC-подобный 1-RTT пакет. Ровно один NRXP-кадр на пакет — как и
/// [`crate::nrxp::datagram`], этот файл не занимается коалессированием
/// нескольких QUIC-пакетов в одну UDP-датаграмму (реальный QUIC это умеет,
/// мы — нет; см. `docs/UDP_LEG_RESEARCH.md` за тем, что это упрощение).
pub(crate) struct ShortHeaderPacket {
    pub(crate) dcid: Bytes,
    /// Длина Packet Number в байтах, 1..=4 (RFC 9000 §17.1).
    pub(crate) pn_len: u8,
    pub(crate) key_phase: bool,
    /// На [`encode`](Self::encode) — полный локальный счётчик, младшие
    /// `pn_len` байт которого кладутся на провод. На [`decode`](Self::decode) —
    /// НАОБОРОТ, то, что реально было на проводе, БЕЗ реконструкции до
    /// полного счётчика: этот тип — чистый слой заголовка, он не хранит
    /// "наибольший принятый счётчик" ни для одной эпохи и потому не может
    /// сам восстановить исходное значение однозначно. Реконструкция —
    /// работа [`crate::nrxp::datagram::DatagramRx`] (через
    /// [`crate::nrxp::expand_counter`]), у которого это состояние
    /// действительно есть — см. [`QuicRx::open`] за тем, как они
    /// соединяются.
    pub(crate) packet_number: u64,
    /// Уже зашифрованный [`crate::nrxp::datagram::SealedDatagram::ciphertext`] —
    /// этот файл не шифрует данные сам, только раскладывает их в QUIC-форму
    /// и защищает заголовок.
    pub(crate) payload: Bytes,
}

impl ShortHeaderPacket {
    /// Заголовок ДО защиты и ДО payload'а: первый байт + DCID + байты PN.
    /// Общая точка для [`encode`](Self::encode) (пишет их как есть, потом
    /// защищает) и [`QuicTx::seal`] (нужны те же байты как AAD ДО того, как
    /// защита вообще накладывается, — см. RFC 9001 §5.3: AAD — это
    /// содержимое заголовка).
    fn header_bytes(&self) -> BytesMut {
        let pn_len = self.pn_len as usize;
        debug_assert!(
            (1..=4).contains(&pn_len),
            "QUIC packet number is 1..=4 bytes"
        );
        let pn_len_bits = (self.pn_len.saturating_sub(1)) & 0x03;
        // bit7=0 (short header) | bit6=1 (fixed bit, RFC 9000 §17.2) | key phase | pn_len
        let first_byte = 0x40 | if self.key_phase { 0x04 } else { 0x00 } | pn_len_bits;

        let mut header = BytesMut::with_capacity(1 + self.dcid.len() + pn_len);
        header.put_u8(first_byte);
        header.put_slice(&self.dcid);
        header.put_slice(&self.packet_number.to_be_bytes()[8 - pn_len..]);
        header
    }

    /// Собирает пакет и накладывает header protection.
    pub(crate) fn encode(&self, hp_key: &[u8; 32]) -> Bytes {
        let mut out = self.header_bytes();
        let pn_offset = out.len() - self.pn_len as usize;
        out.reserve(self.payload.len());
        out.put_slice(&self.payload);

        apply_mask(
            &mut out,
            pn_offset,
            self.pn_len as usize,
            SHORT_HEADER_MASK,
            hp_key,
        );
        out.freeze()
    }

    /// Снимает header protection и разбирает заголовок. `dcid_len` — длина
    /// DCID для ЭТОЙ UDP-ноги (короткий заголовок её не несёт на проводе,
    /// см. [`super::fingerprint::QuicProfile::dcid_len`]).
    ///
    /// `packet_number` в результате — то, что БУКВАЛЬНО было на проводе
    /// (`pn_len` младших байт, без реконструкции до полного счётчика) — см.
    /// докстринг поля.
    pub(crate) fn decode(wire: &[u8], dcid_len: usize, hp_key: &[u8; 32]) -> Option<Self> {
        let pn_offset = 1 + dcid_len;
        if wire.len() < pn_offset + SAMPLE_OFFSET_FROM_PN + SAMPLE_LEN {
            return None;
        }

        let mut buf = BytesMut::from(wire);
        // Один сэмпл, одна маска — используется в два приёма: сперва только
        // на первый байт (иначе `pn_len` неизвестен), затем, узнав `pn_len`,
        // на сами байты PN. Оба приёма читают один и тот же `mask`, потому
        // что sample лежит на фиксированном смещении и не пересекается ни с
        // первым байтом, ни с полем PN (не длиннее 4 байт).
        let mask = sample_mask(&buf, pn_offset, hp_key);
        buf[0] ^= mask[0] & SHORT_HEADER_MASK;
        let pn_len = ((buf[0] & 0x03) + 1) as usize;
        if buf.len() < pn_offset + pn_len {
            return None;
        }
        for i in 0..pn_len {
            buf[pn_offset + i] ^= mask[1 + i];
        }

        let key_phase = buf[0] & 0x04 != 0;
        let mut pn_bytes = [0u8; 8];
        pn_bytes[8 - pn_len..].copy_from_slice(&buf[pn_offset..pn_offset + pn_len]);
        let packet_number = u64::from_be_bytes(pn_bytes);

        Some(Self {
            dcid: Bytes::copy_from_slice(&buf[1..1 + dcid_len]),
            pn_len: pn_len as u8,
            key_phase,
            packet_number,
            payload: Bytes::copy_from_slice(&buf[pn_offset + pn_len..]),
        })
    }
}

/// Исходящая сторона одной QUIC-подобной UDP-ноги: [`crate::nrxp::datagram`]
/// плюс short-header обёртка вокруг него.
pub(crate) struct QuicTx {
    tx: DatagramTx,
    hp_key: [u8; 32],
    /// DCID, который МЫ кладём в СВОИ исходящие пакеты — фиксирован на всю
    /// жизнь ноги (без `NEW_CONNECTION_ID`, см. докстринг модуля `quiceng`).
    dcid: Bytes,
}

impl QuicTx {
    pub(crate) fn new(tx: DatagramTx, hp_key: [u8; 32], dcid: Bytes) -> Self {
        Self { tx, hp_key, dcid }
    }

    /// Шифрует один кадр NRXP как один короткозаголовочный QUIC-пакет.
    ///
    /// Всегда 4-байтный packet number — см. докстринг
    /// [`ShortHeaderPacket::encode`]'s caller-facing упрощение в
    /// `docs/UDP_LEG_RESEARCH.md` §4.3 (настоящий QUIC выбирает длину
    /// адаптивно, мы — нет).
    pub(crate) fn seal(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        const PN_LEN: u8 = 4;
        let (epoch_id, counter) = self.tx.peek_next_epoch_and_counter();
        let key_phase = epoch_id & 1 != 0;

        // Заголовок как AAD — RFC 9001 §5.3: AAD — это содержимое заголовка
        // пакета. Временный `payload: Bytes::new()` здесь ни на что не
        // влияет: `header_bytes()` не читает payload вообще.
        let header_only = ShortHeaderPacket {
            dcid: self.dcid.clone(),
            pn_len: PN_LEN,
            key_phase,
            packet_number: counter,
            payload: Bytes::new(),
        };
        let aad = header_only.header_bytes();

        let sealed = self.tx.seal(stream_id, frame_type, payload, &aad)?;
        debug_assert_eq!(sealed.epoch_id, epoch_id);
        debug_assert_eq!(sealed.counter, counter);

        let packet = ShortHeaderPacket {
            dcid: self.dcid.clone(),
            pn_len: PN_LEN,
            key_phase,
            packet_number: counter,
            payload: sealed.ciphertext,
        };
        Ok(packet.encode(&self.hp_key))
    }
}

/// Входящая сторона одной QUIC-подобной UDP-ноги.
pub(crate) struct QuicRx {
    rx: DatagramRx,
    hp_key: [u8; 32],
    dcid_len: usize,
}

fn bad_packet(what: &'static str) -> TlsError {
    TlsError::new(ErrorStage::Tls(what), ErrorAction::Drop, Bytes::new())
}

impl QuicRx {
    pub(crate) fn new(rx: DatagramRx, hp_key: [u8; 32], dcid_len: usize) -> Self {
        Self {
            rx,
            hp_key,
            dcid_len,
        }
    }

    /// Разбирает и расшифровывает один входящий короткозаголовочный пакет.
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<Frame, TlsError> {
        let packet = ShortHeaderPacket::decode(wire, self.dcid_len, &self.hp_key)
            .ok_or_else(|| bad_packet("not a decodable QUIC-like short header"))?;

        // Key Phase — ОДИН бит, а не байт: реконструкция полного epoch_id по
        // нему устроена ровно так же, как QUIC сам предписывает трактовать
        // смену фазы (RFC 9001 §6.1) — и ровно так же, как
        // `DatagramRx::open` уже ограничивает себя соседними эпохами
        // (current/current+1/previous): если бит совпадает с текущей
        // эпохой — эпоха та же, если нет — предполагаем "следующая",
        // третьего варианта наша реализация не поддерживает(и не
        // поддерживает настоящий QUIC — там это тоже единственная
        // трактовка одного бита).
        let current_epoch = self.rx.current_epoch_id();
        let epoch_id = if (packet.key_phase as u8) == (current_epoch & 1) {
            current_epoch
        } else {
            current_epoch.wrapping_add(1)
        };

        let aad = ShortHeaderPacket {
            dcid: packet.dcid.clone(),
            pn_len: packet.pn_len,
            key_phase: packet.key_phase,
            packet_number: packet.packet_number,
            payload: Bytes::new(),
        }
        .header_bytes();

        self.rx.open(
            epoch_id,
            packet.packet_number,
            (packet.pn_len as u32) * 8,
            &packet.payload,
            &aad,
        )
    }
}

/// Общая для Initial (`initial.rs`) и short-header часть: считает
/// ChaCha20-маску (RFC 9001 §5.4.4) из sample'а на фиксированном смещении и
/// накладывает её на первый байт (через `header_mask`, разный для long/short
/// заголовков) и на все `pn_len` байт packet number.
pub(super) fn apply_mask(
    buf: &mut [u8],
    pn_offset: usize,
    pn_len: usize,
    header_mask: u8,
    hp_key: &[u8; 32],
) {
    debug_assert!(
        buf.len() >= pn_offset + SAMPLE_OFFSET_FROM_PN + SAMPLE_LEN,
        "caller must guarantee at least {SAMPLE_OFFSET_FROM_PN}+{SAMPLE_LEN} bytes of payload after \
         the packet number field (real QUIC guarantees this with PADDING frames on short packets — \
         RFC 9001 §5.4.2); our payload is always at least an AEAD tag, so this should never trip \
         on real `nrxp::datagram` output"
    );
    let mask = sample_mask(buf, pn_offset, hp_key);
    buf[0] ^= mask[0] & header_mask;
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
    }
}

/// Sample считается от смещения `pn_offset + 4`, ФИКСИРОВАННОГО независимо от
/// настоящей длины PN — на этом и держится решение проблемы курицы и яйца.
fn sample_mask(buf: &[u8], pn_offset: usize, hp_key: &[u8; 32]) -> [u8; 5] {
    let sample_start = pn_offset + SAMPLE_OFFSET_FROM_PN;
    let sample: [u8; SAMPLE_LEN] = buf[sample_start..sample_start + SAMPLE_LEN]
        .try_into()
        .expect(
            "caller guarantees at least SAMPLE_OFFSET_FROM_PN + SAMPLE_LEN bytes after pn_offset",
        );
    chacha20_mask(hp_key, &sample)
}

/// RFC 9001 §5.4.4: маска — результат "шифрования" пяти нулевых байт ChaCha20
/// с ключом защиты заголовка; первые 4 байта сэмпла — little-endian счётчик
/// блока, оставшиеся 12 — nonce.
pub(super) fn chacha20_mask(hp_key: &[u8; 32], sample: &[u8; SAMPLE_LEN]) -> [u8; 5] {
    let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap());
    let nonce = chacha20::Nonce::from_slice(&sample[4..16]);
    let mut cipher = ChaCha20::new(chacha20::Key::from_slice(hp_key), nonce);
    cipher.seek(counter as u64 * 64);
    let mut mask = [0u8; 5];
    cipher.apply_keystream(&mut mask);
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    const HP_KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn encode_decode_round_trip_preserves_fields() {
        let pkt = ShortHeaderPacket {
            dcid: Bytes::from_static(b"12345678"),
            pn_len: 4,
            key_phase: true,
            packet_number: 12345,
            payload: Bytes::from(vec![0xABu8; 32]),
        };
        let wire = pkt.encode(&HP_KEY);
        let decoded = ShortHeaderPacket::decode(&wire, 8, &HP_KEY).unwrap();

        assert_eq!(decoded.dcid, pkt.dcid);
        assert_eq!(decoded.key_phase, pkt.key_phase);
        assert_eq!(decoded.packet_number, pkt.packet_number);
        assert_eq!(decoded.payload, pkt.payload);
    }

    #[test]
    fn key_phase_toggles_correctly_through_protection() {
        for key_phase in [false, true] {
            let pkt = ShortHeaderPacket {
                dcid: Bytes::from_static(b"abcdefgh"),
                pn_len: 2,
                key_phase,
                packet_number: 7,
                payload: Bytes::from_static(b"payload-bytes-here"),
            };
            let wire = pkt.encode(&HP_KEY);
            let decoded = ShortHeaderPacket::decode(&wire, 8, &HP_KEY).unwrap();
            assert_eq!(decoded.key_phase, key_phase);
        }
    }

    #[test]
    fn wrong_hp_key_fails_to_reconstruct_a_sane_pn_len() {
        // Без верного ключа снятая "защита" даёт мусорные биты pn_len —
        // decode либо вернёт None (буфер слишком короткий под "прочитанную"
        // длину), либо явно неверные поля. Мы проверяем только то, что
        // результат (если есть) НЕ совпадает с оригиналом — сам факт, что
        // защита от неверного ключа не восстанавливает исходные данные.
        let pkt = ShortHeaderPacket {
            dcid: Bytes::from_static(b"12345678"),
            pn_len: 4,
            key_phase: false,
            packet_number: 99,
            payload: Bytes::from(vec![0x11u8; 32]),
        };
        let wire = pkt.encode(&HP_KEY);
        let wrong_key = [0x99u8; 32];
        match ShortHeaderPacket::decode(&wire, 8, &wrong_key) {
            None => {}
            Some(decoded) => assert_ne!(decoded.packet_number, pkt.packet_number),
        }
    }

    #[test]
    fn decode_returns_the_wire_truncated_value_without_reconstruction() {
        // `decode` — чистый слой заголовка: он не хранит "наибольший
        // принятый счётчик" ни для одной эпохи, поэтому не может и не
        // должен восстанавливать полный счётчик сам — это работа
        // `QuicRx`/`DatagramRx` (см. `full_packet_numbers_reconstruct_correctly_through_quic_tx_rx` ниже).
        let pkt = ShortHeaderPacket {
            dcid: Bytes::from_static(b"12345678"),
            pn_len: 1, // только младший байт на проводе
            key_phase: false,
            packet_number: 300, // 300 % 256 = 44
            // Реалистичный размер: настоящий payload здесь всегда
            // `SealedDatagram::ciphertext` — как минимум 25-байтный `Frame`
            // плюс 16-байтный AEAD-тег. Однобайтовый payload (как раньше
            // стояло здесь) нарушает инвариант, на котором держится
            // sample — см. `debug_assert!` в `apply_mask`.
            payload: Bytes::from(vec![0u8; 41]),
        };
        let wire = pkt.encode(&HP_KEY);
        let decoded = ShortHeaderPacket::decode(&wire, 8, &HP_KEY).unwrap();
        assert_eq!(
            decoded.packet_number, 44,
            "1-byte PN field truncates 300 to 300 % 256"
        );
    }

    // ── QuicTx/QuicRx: сквозные тесты через nrxp::datagram ─────────────────

    use crate::crypto::{DatagramKeyMaterial, SessionKeys};
    use crate::nrxp::{DatagramRx as CoreDatagramRx, DatagramTx as CoreDatagramTx, TlsBridge};
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

    fn quic_tx_rx_pair() -> (QuicTx, QuicRx) {
        let (client, server) = handshaken_pair();
        let client_mat = DatagramKeyMaterial::derive(&client);
        let server_mat = DatagramKeyMaterial::derive(&server);

        let tx = QuicTx::new(
            CoreDatagramTx::new(DatagramKeyMaterial::derive(&client)),
            client_mat.hp_key_tx(),
            Bytes::copy_from_slice(&client_mat.leg_token()[0..8]),
        );
        let rx = QuicRx::new(
            CoreDatagramRx::new(DatagramKeyMaterial::derive(&server)),
            server_mat.hp_key_rx(),
            8,
        );
        (tx, rx)
    }

    #[test]
    fn quic_tx_rx_round_trip_preserves_frame_contents() {
        let (mut tx, mut rx) = quic_tx_rx_pair();
        let wire = tx
            .seal(3, FrameType::UdpData, Bytes::from_static(b"hello quic"))
            .unwrap();
        let frame = rx.open(&wire).unwrap();
        assert_eq!(frame.header.stream_id, 3);
        assert_eq!(&frame.payload[..], b"hello quic");
    }

    #[test]
    fn full_packet_numbers_reconstruct_correctly_through_quic_tx_rx() {
        // 300 датаграмм — с 1..=4-байтным полем PN усечение никогда не
        // проявилось бы в этом диапазоне; проверяем именно то, что слой
        // QuicRx/DatagramRx вместе всё равно восстанавливает монотонно
        // растущий локальный счётчик по датаграммам by construction (мы не
        // варьируем pn_len здесь — он у нас всегда 4 — но зато проверяем,
        // что цепочка reconstruct не ломается на реальном количестве вызовов).
        let (mut tx, mut rx) = quic_tx_rx_pair();
        for i in 0..300u32 {
            let wire = tx
                .seal(
                    1,
                    FrameType::UdpData,
                    Bytes::copy_from_slice(&i.to_be_bytes()),
                )
                .unwrap();
            let frame = rx.open(&wire).unwrap();
            assert_eq!(u32::from_be_bytes(frame.payload[..].try_into().unwrap()), i);
        }
    }

    #[test]
    fn quic_tx_rx_survives_a_rekey_via_the_key_phase_bit() {
        let (mut tx, mut rx) = quic_tx_rx_pair();
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
