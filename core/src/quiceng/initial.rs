//! QUIC Initial-пакет (RFC 9000 §17.2.2): единственный пакет UDP-ноги,
//! который несёт наш поддельный `ClientHello` вместо потока
//! [`crate::nrxp::datagram`]-трафика — ровно то, чем `ClientHello`+CCS
//! являются для TCP-ноги (см. `edge::EdgeHandshake`), только в QUIC-форме.
//!
//! ## Что здесь по-настоящему совпадает с RFC 9001 §5.2, а что — нет
//!
//! `INITIAL_SALT` и вывод `{client,server}_initial_secret` — байт-в-байт по
//! спецификации: это чистая функция версии протокола и **публичного**
//! Destination Connection ID, без единого нашего секрета внутри, так что
//! повторить её было буквально бесплатно и не открывает никакого нашего
//! ключевого материала.
//!
//! Дальше — есть отличие, и оно намеренное: настоящий QUIC на этом шаге
//! получает ключи `AEAD_AES_128_GCM` (RFC 9001 §5). Во всём остальном нашем
//! стеке — ChaCha20-Poly1305 (см. [`crate::crypto`],
//! [`crate::nrxp::datagram`]), и заводить вторую реализацию AEAD ради ОДНОГО
//! пакета на всю сессию — это реальные зависимость и код ради выигрыша,
//! который снимается только ручным разбором в Wireshark, причём тем же
//! самым разбором, который через кадр-другой всё равно упрётся в то, что
//! "TLS"-хендшейк внутри ненастоящий (нет реального Certificate/Finished —
//! та же граница, что и у мимикрии `tlseng` поверх TCP). Поэтому лейблы
//! `"quic key"`/`"quic hp"` из `HKDF-Expand-Label` здесь идут в
//! ChaCha20-Poly1305-размерные ключи (32/32 байта) вместо
//! AES-128-GCM-размерных (16/16). Первый реальный шаг к устранению этого
//! разрыва, если он когда-нибудь понадобится, — настоящий AES-128-GCM
//! (см. `docs/UDP_LEG_RESEARCH.md`).

use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key as ChachaKey, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::SessionKeys;
use crate::nrxp::TlsBridge;
use crate::quiceng::header::apply_mask;
use crate::tlseng::BrowserProfile;

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
    aead_key: [u8; 32],
    aead_iv: [u8; 12],
    hp_key: [u8; 32],
}

/// RFC 9001 §5.2, шаг за шагом, до общего `{client,server}_initial_secret`; с
/// этого секрета мы сворачиваем на свой AEAD — см. докстринг модуля.
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
        aead_key: hkdf_expand_label::<32>(&secret_hkdf, b"quic key"),
        aead_iv: hkdf_expand_label::<12>(&secret_hkdf, b"quic iv"),
        hp_key: hkdf_expand_label::<32>(&secret_hkdf, b"quic hp"),
    }
}

/// RFC 9000 §14.1: UDP-датаграммы, несущие Initial-пакет клиента, обязаны
/// быть не короче 1200 байт (амплификационная защита) — настоящие браузеры
/// набивают PADDING-фреймами до этого порога, и его отсутствие само по себе
/// узнаваемо.
const MIN_INITIAL_DATAGRAM_LEN: usize = 1200;

/// Собирает клиентский QUIC Initial-пакет, несущий наш `ClientHello`
/// (см. докстринг модуля — это НЕ настоящий TLS-в-QUIC, а мимикрия поверх
/// собственного протокола) в CRYPTO-фрейме (RFC 9000 §19.6), защищённый по
/// форме RFC 9001, но нашим AEAD.
pub(crate) fn build_client_initial(
    profile: &super::QuicProfile,
    decoy_sni: &str,
    session_keys: &SessionKeys,
    dcid: &[u8],
    scid: &[u8],
) -> Bytes {
    let client_hello =
        TlsBridge::wrap_client_hello(&BrowserProfile::CHROME_140, decoy_sni, session_keys);

    // CRYPTO frame (RFC 9000 §19.6): Type(1)=0x06, Offset varint=0, Length
    // varint, Crypto Data. Смещение и длина ClientHello у нас всегда влезают
    // в однобайтовый varint (< 64) не всегда — считаем честно.
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
        + 2 // length varint (2-byte form, see put_varint_len below)
        + 4 // packet number (мы всегда используем 4 байта для Initial)
        + payload.len()
        + 16; // AEAD tag
    if unpadded_len_estimate < MIN_INITIAL_DATAGRAM_LEN {
        payload.resize(
            payload.len() + (MIN_INITIAL_DATAGRAM_LEN - unpadded_len_estimate),
            0,
        );
    }

    let keys = derive_initial_keys(dcid, true);
    let packet_number: u32 = 0; // первый (и единственный в этой правке) Initial клиента.
    let pn_len: usize = 4;

    let mut out = BytesMut::new();
    let pn_len_bits = ((pn_len - 1) & 0x03) as u8;
    // bit7=1 (long header) | bit6=1 (fixed bit) | type=00 (Initial) | reserved=00 | pn_len
    out.put_u8(0xC0 | pn_len_bits);
    out.put_u32(profile.version);
    out.put_u8(dcid.len() as u8);
    out.put_slice(dcid);
    out.put_u8(scid.len() as u8);
    out.put_slice(scid);
    put_varint(&mut out, 0); // Token Length = 0 (мы никогда не несём retry token)

    let length_field_value = pn_len + payload.len() + 16; // PN + payload + AEAD tag
    put_varint(&mut out, length_field_value as u64);

    let pn_offset = out.len();
    out.put_slice(&packet_number.to_be_bytes()[4 - pn_len..]);

    let mut sealed = BytesMut::from(&payload[..]);
    sealed.reserve(16);
    let nonce = build_initial_nonce(&keys.aead_iv, packet_number as u64);
    ChaCha20Poly1305::new(ChachaKey::from_slice(&keys.aead_key))
        .encrypt_in_place(&nonce, &out[..pn_offset + pn_len], &mut sealed)
        .expect("fixed-size in-place AEAD seal cannot fail");
    out.put_slice(&sealed);

    apply_mask(&mut out, pn_offset, pn_len, LONG_HEADER_MASK, &keys.hp_key);
    out.freeze()
}

fn build_initial_nonce(iv: &[u8; 12], counter: u64) -> chacha20poly1305::Nonce {
    let mut n = *iv;
    let counter_bytes = counter.to_be_bytes();
    for i in 0..8 {
        n[i + 4] ^= counter_bytes[i];
    }
    *chacha20poly1305::aead::generic_array::GenericArray::from_slice(&n)
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

    fn test_session_keys() -> SessionKeys {
        // Initial-пакет несёт только `ClientHello` — сам хендшейк NRXP
        // (`update_keys`) для этого не нужен, `wrap_client_hello` требует
        // лишь свежесозданный `SessionKeys` для своих полей (соль, X25519
        // pubkey, auth-тег).
        SessionKeys::new(true)
    }

    #[test]
    fn client_initial_meets_the_amplification_floor() {
        let keys = test_session_keys();
        let pkt = build_client_initial(
            &super::super::QuicProfile::CHROME,
            "example.com",
            &keys,
            b"12345678",
            b"87654321",
        );
        assert!(
            pkt.len() >= MIN_INITIAL_DATAGRAM_LEN,
            "client Initial datagram must be >= {MIN_INITIAL_DATAGRAM_LEN} bytes, got {}",
            pkt.len()
        );
    }

    #[test]
    fn client_initial_starts_with_a_long_header_initial_first_byte() {
        let keys = test_session_keys();
        let pkt = build_client_initial(
            &super::super::QuicProfile::CHROME,
            "example.com",
            &keys,
            b"12345678",
            b"87654321",
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
}
