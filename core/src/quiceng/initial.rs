//! QUIC Initial-пакет (RFC 9000 §17.2.2): единственный пакет UDP-ноги,
//! который несёт наш поддельный `ClientHello` вместо потока
//! [`crate::nrxp::datagram`]-трафика — ровно то, чем `ClientHello`+CCS
//! являются для TCP-ноги (см. `edge::EdgeHandshake`), только в QUIC-форме.
//!
//! ## Совпадение с RFC 9001 §5 — теперь байт-в-байт
//!
//! `INITIAL_SALT` и вывод `{client,server}_initial_secret` — чистая функция
//! версии протокола и **публичного** Destination Connection ID, без единого
//! нашего секрета. Дальше, в отличие от прежней версии, ключи Initial —
//! настоящие `AEAD_AES_128_GCM` (16-байтный ключ, 12-байтный IV) с
//! **AES-ECB** header protection (RFC 9001 §5.4.3), а не ChaCha20. Причина: ключи
//! Initial ПУБЛИЧНЫ, и любой DPI расшифровывает их на полной скорости канала
//! (так GFW блокирует по SNI) — раньше по содержимому пакет НЕ проходил проверку
//! как QUIC (bug #9). Теперь наш Initial расшифровывается стандартным QUIC-стеком
//! и содержит настоящий QUIC `ClientHello` (см. [`super::client_hello`]) с ALPN
//! `h3`, `quic_transport_parameters` и пустым `legacy_session_id` (bug #10).
//!
//! Остальной трафик ноги (1-RTT, `header.rs`) остаётся на ChaCha20 — там ключи
//! НЕ публичны, снять header protection без них нельзя, а значит алгоритм HP
//! ненаблюдаем, и разницы для DPI нет. AES нужен ровно для одного публично
//! расшифровываемого пакета — Initial.
//!
//! Граница мимикрии прежняя: глубокий разбор через кадр-другой упрётся в то,
//! что за `ClientHello` не следует настоящий Certificate/Finished (то же, что и
//! у `tlseng` поверх TCP). Активное зондирование этим не закрывается — для того
//! нужен настоящий QUIC (`QuicMode::Real`, см. `real.rs`).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use bytes::{BufMut, Bytes, BytesMut};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

use crate::quiceng::client_hello::build_quic_client_hello;

/// RFC 9001 §5.2: соль HKDF-Extract для QUIC версии 1 — публичная константа
/// протокола, не наш секрет.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Long header: маскируются только 4 младших бита первого байта (Reserved×2 +
/// PN Length×2 — нет Spin/Key Phase, тех у long header не существует).
const LONG_HEADER_MASK: u8 = 0x0f;

/// RFC 8446 §7.1 `HKDF-Expand-Label`: обёртка над `HKDF-Expand` с
/// TLS-специфичным форматом метки (`length‖"tls13 "+label‖context`). Нужен
/// именно ради байт-в-байт совпадения вывода `{client,server}_initial_secret`
/// с реальным QUIC — обычный [`crate::crypto`] этот формат не производит:
/// его метки принадлежат протоколу NRXP, а не TLS 1.3.
fn hkdf_expand_label<const N: usize>(secret: &Hkdf<Sha256>, label: &[u8]) -> [u8; N] {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    hkdf_label.put_u16(N as u16);
    hkdf_label.put_u8((6 + label.len()) as u8);
    hkdf_label.put_slice(b"tls13 ");
    hkdf_label.put_slice(label);
    hkdf_label.put_u8(0); // context — пуст для initial secrets (RFC 9001 §5.2)

    let mut out = [0u8; N];
    secret
        .expand(&hkdf_label, &mut out)
        .expect("fixed-length HKDF-expand cannot fail");
    out
}

struct InitialKeys {
    /// AES-128-GCM: 16-байтный ключ, 12-байтный IV, 16-байтный ключ header
    /// protection (RFC 9001 §5.1) — размеры суита `AEAD_AES_128_GCM`, а не
    /// ChaCha20 (32/32).
    aead_key: [u8; 16],
    aead_iv: [u8; 12],
    hp_key: [u8; 16],
}

/// RFC 9001 §5.2, шаг за шагом, до `{client,server}_initial_secret`, затем
/// §5.1 — ключи суита AES-128-GCM. Всё это чистая функция публичного DCID.
fn derive_initial_keys(dcid: &[u8], is_client: bool) -> InitialKeys {
    let initial_secret = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), dcid);
    let label: &[u8] = if is_client {
        b"client in"
    } else {
        b"server in"
    };
    let label_secret: [u8; 32] = hkdf_expand_label(&initial_secret, label);

    let secret_hkdf = Hkdf::<Sha256>::from_prk(&label_secret).expect("32-byte PRK is always valid");
    InitialKeys {
        aead_key: hkdf_expand_label::<16>(&secret_hkdf, b"quic key"),
        aead_iv: hkdf_expand_label::<12>(&secret_hkdf, b"quic iv"),
        hp_key: hkdf_expand_label::<16>(&secret_hkdf, b"quic hp"),
    }
}

/// AES-ECB header-protection маска (RFC 9001 §5.4.3): первые 5 байт
/// AES-128(hp_key, sample). У AES это ровно одно шифрование блока.
fn aes_hp_mask(hp_key: &[u8; 16], sample: &[u8; 16]) -> [u8; 5] {
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = *GenericArray::from_slice(sample);
    cipher.encrypt_block(&mut block);
    [block[0], block[1], block[2], block[3], block[4]]
}

/// Накладывает AES-header-protection на первый байт (4 младших бита) и на все
/// `pn_len` байт packet number. Sample берётся с фиксированного смещения
/// `pn_offset + 4` (RFC 9001 §5.4.2), как и в short-header пути.
fn apply_initial_hp(out: &mut BytesMut, pn_offset: usize, pn_len: usize, hp_key: &[u8; 16]) {
    let sample_start = pn_offset + 4;
    let sample: [u8; 16] = out[sample_start..sample_start + 16]
        .try_into()
        .expect("caller guarantees >= 4 + 16 bytes after the packet number field");
    let mask = aes_hp_mask(hp_key, &sample);
    out[0] ^= mask[0] & LONG_HEADER_MASK;
    for i in 0..pn_len {
        out[pn_offset + i] ^= mask[1 + i];
    }
}

/// RFC 9000 §14.1: UDP-датаграммы, несущие Initial-пакет клиента, обязаны
/// быть не короче 1200 байт (амплификационная защита) — настоящие браузеры
/// набивают PADDING-фреймами до этого порога, и его отсутствие само по себе
/// узнаваемо.
const MIN_INITIAL_DATAGRAM_LEN: usize = 1200;

/// Собирает клиентский QUIC Initial-пакет, несущий настоящий QUIC `ClientHello`
/// (см. [`super::client_hello`]) в CRYPTO-фрейме (RFC 9000 §19.6), зашифрованный
/// НАСТОЯЩИМ AES-128-GCM Initial-суитом (RFC 9001 §5) — расшифровывается любым
/// QUIC-стеком по публичному DCID. `session_keys` больше не нужен: `ClientHello`
/// здесь декоративный и не несёт нашего ключевого материала.
pub(crate) fn build_client_initial(
    profile: &super::QuicProfile,
    decoy_sni: &str,
    dcid: &[u8],
    scid: &[u8],
) -> Bytes {
    let client_hello = build_quic_client_hello(decoy_sni, scid);

    // CRYPTO frame (RFC 9000 §19.6): Type(1)=0x06, Offset varint=0, Length
    // varint, Crypto Data.
    let mut crypto_frame = BytesMut::new();
    crypto_frame.put_u8(0x06);
    put_varint(&mut crypto_frame, 0);
    put_varint(&mut crypto_frame, client_hello.len() as u64);
    crypto_frame.put_slice(&client_hello);

    let mut payload = crypto_frame;
    // PADDING-фреймы (type 0x00) до амплификационного минимума.
    let unpadded_len_estimate = 1 // first byte
        + 4 // version
        + 1 + dcid.len()
        + 1 + scid.len()
        + 1 // token length = 0
        + 2 // length varint (2-byte form)
        + 4 // packet number
        + payload.len()
        + 16; // AEAD tag
    if unpadded_len_estimate < MIN_INITIAL_DATAGRAM_LEN {
        payload.resize(
            payload.len() + (MIN_INITIAL_DATAGRAM_LEN - unpadded_len_estimate),
            0,
        );
    }

    let keys = derive_initial_keys(dcid, true);
    seal_initial_packet(profile.version, dcid, scid, &payload, &keys)
}

/// Собирает и защищает один Initial-пакет (тип Initial, Token Length 0, packet
/// number 0), зашифрованный AES-128-GCM Initial-ключами `keys`. Общий код
/// клиентского и серверного Initial — они различаются только содержимым
/// `payload` (у клиента — CRYPTO+PADDING, у сервера — ACK+CRYPTO) и тем, из
/// какого DCID выведены `keys`.
fn seal_initial_packet(
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    payload: &[u8],
    keys: &InitialKeys,
) -> Bytes {
    const PN_LEN: usize = 4;
    let mut out = BytesMut::new();
    let pn_len_bits = ((PN_LEN - 1) & 0x03) as u8;
    // bit7=1 (long) | bit6=1 (fixed) | type=00 (Initial) | reserved=00 | pn_len
    out.put_u8(0xC0 | pn_len_bits);
    out.put_u32(version);
    out.put_u8(dcid.len() as u8);
    out.put_slice(dcid);
    out.put_u8(scid.len() as u8);
    out.put_slice(scid);
    put_varint(&mut out, 0); // Token Length = 0 (мы никогда не несём retry token)
    put_varint(&mut out, (PN_LEN + payload.len() + 16) as u64); // PN + payload + AEAD tag

    let pn_offset = out.len();
    out.put_slice(&0u32.to_be_bytes()); // packet number = 0

    let mut sealed = BytesMut::from(payload);
    sealed.reserve(16);
    let nonce = build_initial_nonce(&keys.aead_iv, 0);
    Aes128Gcm::new(GenericArray::from_slice(&keys.aead_key))
        .encrypt_in_place(
            GenericArray::from_slice(&nonce),
            &out[..pn_offset + PN_LEN],
            &mut sealed,
        )
        .expect("fixed-size in-place AES-128-GCM seal cannot fail");
    out.put_slice(&sealed);

    apply_initial_hp(&mut out, pn_offset, PN_LEN, &keys.hp_key);
    out.freeze()
}

/// Декоративный ответ сервера на клиентский Initial (bug #12): пара пакетов —
/// server Initial (ACK по pn=0 + `ServerHello`) и Handshake. Так пассивный
/// stateful-DPI видит ДВУСТОРОННИЙ QUIC-хендшейк, а не «клиент шлёт Initial и
/// сразу 1-RTT в тишину».
///
/// - **Initial** — настоящей формы: расшифровывается публичными
///   server-initial-ключами (выведенными из `client_dcid`) и содержит валидный
///   `ServerHello`.
/// - **Handshake** — заголовок валиден, тело непрозрачно (случайные байты):
///   его ключи вывелись бы из настоящего TLS-хендшейка, которого у нас нет, но
///   и наблюдатель без приватного ключа клиента их не выведет, поэтому
///   случайные байты под HP неотличимы от настоящего шифртекста.
///
/// Это НЕ спасает от активного зондирования (для того нужен настоящий QUIC,
/// `QuicMode::Real`) — только закрывает пассивный признак «сервер не отвечал».
///
/// `client_dcid` — DCID клиентского Initial; `client_scid` — SCID клиента (в
/// ответе он становится нашим DCID, RFC 9000 §7.3).
pub(crate) fn build_server_initial_flight(
    profile: &super::QuicProfile,
    client_dcid: &[u8],
    client_scid: &[u8],
) -> Vec<Bytes> {
    let server_scid: [u8; 8] = rand::random();

    // ── Server Initial: ACK(pn=0) + CRYPTO(ServerHello) ──
    let server_hello = crate::quiceng::client_hello::build_quic_server_hello();
    let mut payload = BytesMut::new();
    // ACK frame (RFC 9000 §19.3): type 0x02, Largest Ack=0, Delay=0, Range Cnt=0, First Range=0.
    payload.put_slice(&[0x02, 0x00, 0x00, 0x00, 0x00]);
    payload.put_u8(0x06); // CRYPTO frame
    put_varint(&mut payload, 0);
    put_varint(&mut payload, server_hello.len() as u64);
    payload.put_slice(&server_hello);

    let keys = derive_initial_keys(client_dcid, false);
    // DCID сервера = SCID клиента (RFC 9000 §7.3); ключи выведены из ИСХОДНОГО
    // клиентского DCID.
    let initial = seal_initial_packet(profile.version, client_scid, &server_scid, &payload, &keys);

    // ── Handshake: непрозрачная нагрузка правдоподобного размера ──
    let mut hs = BytesMut::new();
    let pn_len = 4usize;
    let pn_len_bits = ((pn_len - 1) & 0x03) as u8;
    hs.put_u8(0xE0 | pn_len_bits); // long | fixed | type=Handshake(10)
    hs.put_u32(profile.version);
    hs.put_u8(client_scid.len() as u8);
    hs.put_slice(client_scid);
    hs.put_u8(server_scid.len() as u8);
    hs.put_slice(&server_scid);
    let body_len = 900usize; // ~ размер реального flight; калибровать по захвату (§4.3)
    put_varint(&mut hs, (pn_len + body_len) as u64);
    let pn_offset = hs.len();
    hs.put_slice(&0u32.to_be_bytes()); // pn = 0 (до HP)
    let start = hs.len();
    hs.resize(start + body_len, 0);
    rand::rng().fill_bytes(&mut hs[start..]);
    // HP случайным ключом — настоящего Handshake-hp у нас нет, а отличить
    // случайную маску от настоящей наблюдатель без ключей не может.
    let hp_random: [u8; 16] = rand::random();
    apply_initial_hp(&mut hs, pn_offset, pn_len, &hp_random);

    vec![initial, hs.freeze()]
}

/// Nonce AEAD = `IV XOR big_endian(packet_number)` по младшим 8 байтам
/// (RFC 9001 §5.3).
fn build_initial_nonce(iv: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut n = *iv;
    let counter_bytes = counter.to_be_bytes();
    for i in 0..8 {
        n[i + 4] ^= counter_bytes[i];
    }
    n
}

/// Кодирует QUIC varint (RFC 9000 §16) в наименьшей форме, которой хватает
/// значению — этого достаточно для длин, с которыми мы здесь работаем
/// (ClientHello и Initial-пакет умещаются далеко внутри 2-байтового диапазона).
fn put_varint(buf: &mut BytesMut, value: u64) {
    if value < 0x40 {
        buf.put_u8(value as u8);
    } else if value < 0x4000 {
        buf.put_u16(0x4000 | value as u16);
    } else if value < 0x4000_0000 {
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        buf.put_u64(0xC000_0000_0000_0000 | value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DCID: &[u8] = b"12345678";
    const SCID: &[u8] = b"87654321";

    #[test]
    fn client_initial_meets_the_amplification_floor() {
        let pkt = build_client_initial(
            &super::super::QuicProfile::CHROME,
            "example.com",
            DCID,
            SCID,
        );
        assert!(
            pkt.len() >= MIN_INITIAL_DATAGRAM_LEN,
            "client Initial datagram must be >= {MIN_INITIAL_DATAGRAM_LEN} bytes, got {}",
            pkt.len()
        );
    }

    #[test]
    fn client_initial_starts_with_a_long_header_initial_first_byte() {
        let pkt = build_client_initial(
            &super::super::QuicProfile::CHROME,
            "example.com",
            DCID,
            SCID,
        );
        // Header protection масками только 4 младших бита long header —
        // верхние 4 бита (form=1, fixed=1, type=00) видны как есть на проводе.
        assert_eq!(
            pkt[0] & 0xF0,
            0xC0,
            "top 4 bits must mark a long-header Initial packet"
        );
    }

    #[test]
    fn derive_initial_keys_is_deterministic_for_the_same_dcid() {
        let a = derive_initial_keys(b"same-dcid", true);
        let b = derive_initial_keys(b"same-dcid", true);
        assert_eq!(a.aead_key, b.aead_key);
        assert_eq!(a.hp_key, b.hp_key);
        // Размеры суита AES-128-GCM, а не ChaCha (bug #9).
        assert_eq!(a.aead_key.len(), 16);
        assert_eq!(a.hp_key.len(), 16);
        assert_eq!(a.aead_iv.len(), 12);
    }

    #[test]
    fn client_and_server_initial_secrets_differ() {
        let client = derive_initial_keys(b"same-dcid", true);
        let server = derive_initial_keys(b"same-dcid", false);
        assert_ne!(
            client.aead_key, server.aead_key,
            "\"client in\" and \"server in\" must diverge"
        );
    }

    /// Главная проверка bug #9/#10: наш Initial — НАСТОЯЩИЙ QUIC Initial. Любой
    /// сторонний QUIC-стек (в т.ч. DPI) выводит те же публичные Initial-ключи по
    /// открытому DCID, снимает AES header protection, расшифровывает AES-128-GCM
    /// и получает валидный `ClientHello`. Здесь мы делаем ровно это своими же
    /// примитивами, НО как независимый «получатель» — не переиспользуя код
    /// сборки, а разбирая байты на проводе с нуля.
    #[test]
    fn our_initial_decrypts_and_parses_as_a_real_quic_client_hello() {
        let pkt = build_client_initial(
            &super::super::QuicProfile::CHROME,
            "sni.example",
            DCID,
            SCID,
        );
        let mut wire = pkt.to_vec();

        // Разбор long header: first(1) | version(4) | dcid_len(1) | dcid |
        // scid_len(1) | scid | token_len varint(=0) | length varint | pn | payload.
        let mut off = 1;
        off += 4; // version
        let dcid_len = wire[off] as usize;
        off += 1;
        let dcid = wire[off..off + dcid_len].to_vec();
        off += dcid_len;
        let scid_len = wire[off] as usize;
        off += 1;
        let scid = wire[off..off + scid_len].to_vec();
        off += scid_len;
        assert_eq!(dcid, DCID);
        assert_eq!(scid, SCID);
        // token length varint — у нас всегда 0 (один байт 0x00).
        assert_eq!(wire[off], 0x00);
        off += 1;
        // length varint: у нас 2-байтовая форма (Initial > 63 байт).
        assert_eq!(wire[off] & 0xC0, 0x40, "length varint must be 2-byte form");
        off += 2;
        let pn_offset = off;

        let keys = derive_initial_keys(&dcid, true);

        // Снимаем header protection тем же AES-ECB, что настоящий получатель.
        let sample_start = pn_offset + 4;
        let sample: [u8; 16] = wire[sample_start..sample_start + 16].try_into().unwrap();
        let mask = aes_hp_mask(&keys.hp_key, &sample);
        wire[0] ^= mask[0] & LONG_HEADER_MASK;
        let pn_len = ((wire[0] & 0x03) + 1) as usize;
        assert_eq!(pn_len, 4, "мы всегда шлём 4-байтный packet number");
        for i in 0..pn_len {
            wire[pn_offset + i] ^= mask[1 + i];
        }
        let mut pn_bytes = [0u8; 8];
        pn_bytes[8 - pn_len..].copy_from_slice(&wire[pn_offset..pn_offset + pn_len]);
        let packet_number = u64::from_be_bytes(pn_bytes);
        assert_eq!(packet_number, 0);

        // Расшифровываем AES-128-GCM: aad = заголовок до конца PN, nonce из IV.
        let aad = wire[..pn_offset + pn_len].to_vec();
        let ct = wire[pn_offset + pn_len..].to_vec();
        let nonce = build_initial_nonce(&keys.aead_iv, packet_number);
        let mut buf = BytesMut::from(&ct[..]);
        Aes128Gcm::new(GenericArray::from_slice(&keys.aead_key))
            .decrypt_in_place(GenericArray::from_slice(&nonce), &aad, &mut buf)
            .expect("our Initial must decrypt with the standard public Initial keys (bug #9)");

        // В расшифрованном payload — CRYPTO-фрейм (0x06) с ClientHello, плюс
        // PADDING (0x00). Находим CRYPTO, читаем ClientHello.
        assert_eq!(buf[0], 0x06, "first frame must be CRYPTO");
        // offset varint (0) + length varint.
        let mut p = 1;
        assert_eq!(buf[p], 0x00); // offset 0
        p += 1;
        // length varint: ClientHello наш < 16384 → 2-байтовая форма.
        let ch_len = (((buf[p] & 0x3f) as usize) << 8) | buf[p + 1] as usize;
        p += 2;
        let ch = &buf[p..p + ch_len];

        // Валидный QUIC ClientHello: тип 0x01, пустой session_id, ALPN h3,
        // quic_transport_parameters (bug #10).
        assert_eq!(ch[0], 0x01, "CRYPTO must carry a ClientHello");
        assert_eq!(
            ch[4 + 2 + 32],
            0x00,
            "legacy_session_id must be empty (QUIC)"
        );
        assert!(
            ch.windows(2).any(|w| w == [b'h', b'3']),
            "ALPN must advertise h3, not h2"
        );
        assert!(
            ch.windows(2).any(|w| w == [0x00, 0x39]),
            "quic_transport_parameters must be present"
        );
    }

    /// bug #12: серверный flight — это настоящий QUIC Initial (расшифровывается
    /// публичными server-initial-ключами, выведенными из ИСХОДНОГО клиентского
    /// DCID) с ACK и `ServerHello`, плюс Handshake-пакет правдоподобной формы.
    #[test]
    fn server_initial_flight_decrypts_to_ack_and_server_hello() {
        let flight = build_server_initial_flight(&super::super::QuicProfile::CHROME, DCID, SCID);
        assert_eq!(flight.len(), 2, "Initial + Handshake");

        // Пакет 1 — long-header Handshake (тип 10 в битах 4..5 → 0xE0 сверху).
        assert_eq!(
            flight[1][0] & 0xF0,
            0xE0,
            "second packet must be a Handshake long header"
        );

        // Пакет 0 — Initial: разбираем и расшифровываем как независимый получатель.
        let mut wire = flight[0].to_vec();
        assert_eq!(
            wire[0] & 0xF0,
            0xC0,
            "first packet must be an Initial long header"
        );
        let mut off = 1 + 4; // first + version
        let dcid_len = wire[off] as usize;
        off += 1;
        // DCID сервера = SCID клиента (RFC 9000 §7.3).
        assert_eq!(&wire[off..off + dcid_len], SCID);
        off += dcid_len;
        let scid_len = wire[off] as usize;
        off += 1 + scid_len; // пропускаем server SCID
        assert_eq!(wire[off], 0x00, "token length must be 0");
        off += 1;
        assert_eq!(wire[off] & 0xC0, 0x40, "length varint 2-byte form");
        off += 2;
        let pn_offset = off;

        // Ключи выводятся из ИСХОДНОГО клиентского DCID, серверная сторона.
        let keys = derive_initial_keys(DCID, false);
        let sample_start = pn_offset + 4;
        let sample: [u8; 16] = wire[sample_start..sample_start + 16].try_into().unwrap();
        let mask = aes_hp_mask(&keys.hp_key, &sample);
        wire[0] ^= mask[0] & LONG_HEADER_MASK;
        let pn_len = ((wire[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            wire[pn_offset + i] ^= mask[1 + i];
        }
        let aad = wire[..pn_offset + pn_len].to_vec();
        let ct = wire[pn_offset + pn_len..].to_vec();
        let nonce = build_initial_nonce(&keys.aead_iv, 0);
        let mut buf = BytesMut::from(&ct[..]);
        Aes128Gcm::new(GenericArray::from_slice(&keys.aead_key))
            .decrypt_in_place(GenericArray::from_slice(&nonce), &aad, &mut buf)
            .expect("server Initial must decrypt with public server-initial keys");

        // payload: ACK (0x02) затем CRYPTO (0x06) с ServerHello (0x02).
        assert_eq!(buf[0], 0x02, "first frame must be ACK");
        // ACK: type + 4 varint-нуля = 5 байт.
        assert_eq!(buf[5], 0x06, "second frame must be CRYPTO");
        let mut p = 6;
        assert_eq!(buf[p], 0x00); // offset 0
        p += 1;
        let sh_len = (((buf[p] & 0x3f) as usize) << 8) | buf[p + 1] as usize;
        p += 2;
        let sh = &buf[p..p + sh_len];
        assert_eq!(sh[0], 0x02, "CRYPTO must carry a ServerHello");
    }
}
