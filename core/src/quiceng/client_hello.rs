//! Построение TLS 1.3 `ClientHello` в QUIC-варианте — **handshake-сообщение**
//! (RFC 8446 §4.1.2), а НЕ TLS-запись: в QUIC `ClientHello` едет прямо в
//! CRYPTO-фрейме Initial-пакета, без обёртки `record` (`16 03 01 …`). Это
//! ключевое отличие от TCP-ноги, где [`crate::nrxp::TlsBridge::wrap_client_hello`]
//! отдаёт как раз запись.
//!
//! Что здесь QUIC-специфично и обязательно (иначе любой QUIC-стек, включая DPI,
//! отвергнет пакет как невалидный QUIC — bug #10):
//! - **`legacy_session_id` пуст** (RFC 9001 §8.4 запрещает непустой в QUIC).
//! - Есть расширение **`application_layer_protocol_negotiation`** со значением
//!   `h3` (а не `h2`/`http/1.1`, как у TCP-профиля).
//! - Есть расширение **`quic_transport_parameters`** (0x0039) — обязательно по
//!   RFC 9001 §8.2; внутри `initial_source_connection_id` совпадает с SCID
//!   пакета (RFC 9000 §7.3), чем закрывается внутренняя рассогласованность CID
//!   (часть bug #11).
//!
//! Материал здесь **декоративный**: наш сервер этот `ClientHello` не
//! обрабатывает и ключей из него не выводит (настоящие ключи ноги идут из
//! `datagram_root` TCP-ноги — см. `quiceng::initial` module docs). Поэтому
//! `key_share` — просто 32 случайных байта: настоящий X25519-pubkey структурно
//! неотличим от случайных 32 байт, отдельная генерация ключа ничего не даёт.

/// QUIC varint (RFC 9000 §16) в наименьшей форме.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&(0x4000u16 | value as u16).to_be_bytes());
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&(0x8000_0000u32 | value as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xC000_0000_0000_0000u64 | value).to_be_bytes());
    }
}

fn varint_bytes(value: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    put_varint(&mut v, value);
    v
}

/// Одно TLS-расширение: `type(2) || len(2) || body`.
fn push_ext(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Транспортный параметр QUIC с целочисленным (varint) значением.
fn push_tp_int(out: &mut Vec<u8>, id: u64, value: u64) {
    let val = varint_bytes(value);
    put_varint(out, id);
    put_varint(out, val.len() as u64);
    out.extend_from_slice(&val);
}

/// Транспортный параметр QUIC с байтовым значением.
fn push_tp_bytes(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    put_varint(out, id);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn server_name_ext(host: &str) -> Vec<u8> {
    // ServerNameList: list_len(2) || [ name_type(1)=0 || name_len(2) || name ]
    let mut body = Vec::new();
    let entry_len = 1 + 2 + host.len();
    body.extend_from_slice(&(entry_len as u16).to_be_bytes());
    body.push(0x00); // host_name
    body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    body.extend_from_slice(host.as_bytes());
    body
}

fn transport_params(scid: &[u8]) -> Vec<u8> {
    let mut tp = Vec::new();
    // initial_source_connection_id (0x0f) = SCID пакета (RFC 9000 §7.3).
    push_tp_bytes(&mut tp, 0x0f, scid);
    // Набор целочисленных параметров — правдоподобные значения браузерного
    // масштаба (не сняты с захвата; это отправная точка, см.
    // docs/UDP_LEG_RESEARCH.md §4.3).
    push_tp_int(&mut tp, 0x01, 30_000); // max_idle_timeout (мс)
    push_tp_int(&mut tp, 0x03, 1_472); // max_udp_payload_size
    push_tp_int(&mut tp, 0x04, 0x00C0_0000); // initial_max_data
    push_tp_int(&mut tp, 0x05, 0x0010_0000); // initial_max_stream_data_bidi_local
    push_tp_int(&mut tp, 0x06, 0x0010_0000); // initial_max_stream_data_bidi_remote
    push_tp_int(&mut tp, 0x07, 0x0010_0000); // initial_max_stream_data_uni
    push_tp_int(&mut tp, 0x08, 100); // initial_max_streams_bidi
    push_tp_int(&mut tp, 0x09, 100); // initial_max_streams_uni
    tp
}

/// Собирает handshake-сообщение `ClientHello` для QUIC Initial. `scid` — Source
/// Connection ID пакета (может быть пустым, как у Chrome); он же уходит в
/// `initial_source_connection_id`.
pub(crate) fn build_quic_client_hello(decoy_sni: &str, scid: &[u8]) -> Vec<u8> {
    let random: [u8; 32] = rand::random();
    let key_share_pub: [u8; 32] = rand::random();

    let mut exts = Vec::new();
    push_ext(&mut exts, 0x0000, &server_name_ext(decoy_sni)); // server_name
    push_ext(&mut exts, 0x000a, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]); // supported_groups: x25519,secp256r1
    push_ext(
        &mut exts,
        0x000d,
        &[0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x08, 0x05, 0x04, 0x01], // signature_algorithms
    );
    push_ext(&mut exts, 0x002b, &[0x02, 0x03, 0x04]); // supported_versions: TLS 1.3
    {
        // key_share: client_shares_len(2) || group(2)=x25519 || key_len(2)=32 || key
        let mut ks = Vec::with_capacity(2 + 4 + 32);
        ks.extend_from_slice(&(36u16).to_be_bytes());
        ks.extend_from_slice(&[0x00, 0x1d]);
        ks.extend_from_slice(&(32u16).to_be_bytes());
        ks.extend_from_slice(&key_share_pub);
        push_ext(&mut exts, 0x0033, &ks);
    }
    push_ext(&mut exts, 0x0010, &[0x00, 0x03, 0x02, b'h', b'3']); // ALPN: h3
    push_ext(&mut exts, 0x0039, &transport_params(scid)); // quic_transport_parameters

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2 (RFC 8446)
    body.extend_from_slice(&random);
    body.push(0x00); // legacy_session_id: ПУСТ (QUIC, RFC 9001 §8.4)
    body.extend_from_slice(&(6u16).to_be_bytes()); // cipher_suites length
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]); // AES128-GCM, AES256-GCM, CHACHA20
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods: [null]
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(0x01); // Handshake type: ClientHello
    let len = body.len();
    msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    msg.extend_from_slice(&body);
    msg
}

/// Собирает TLS 1.3 `ServerHello` handshake-сообщение (RFC 8446 §4.1.3) для
/// декоративного ответа сервера в QUIC Initial (bug #12). `session_id_echo` —
/// эхо `legacy_session_id` клиента (в QUIC он пуст, значит и здесь пуст).
/// Материал декоративный (см. module docs): `key_share` — случайные 32 байта.
pub(crate) fn build_quic_server_hello() -> Vec<u8> {
    let random: [u8; 32] = rand::random();
    let key_share_pub: [u8; 32] = rand::random();

    let mut exts = Vec::new();
    push_ext(&mut exts, 0x002b, &[0x03, 0x04]); // supported_versions: selected = TLS 1.3
    {
        // key_share: group(2)=x25519 || key_len(2)=32 || key
        let mut ks = Vec::with_capacity(4 + 32);
        ks.extend_from_slice(&[0x00, 0x1d]);
        ks.extend_from_slice(&(32u16).to_be_bytes());
        ks.extend_from_slice(&key_share_pub);
        push_ext(&mut exts, 0x0033, &ks);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&random);
    body.push(0x00); // legacy_session_id_echo: пуст (эхо пустого клиентского)
    body.extend_from_slice(&[0x13, 0x01]); // cipher_suite: TLS_AES_128_GCM_SHA256
    body.push(0x00); // legacy_compression_method
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(0x02); // Handshake type: ServerHello
    let len = body.len();
    msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_min_form() {
        assert_eq!(varint_bytes(0), vec![0x00]);
        assert_eq!(varint_bytes(0x3f), vec![0x3f]); // max 1-byte
        assert_eq!(varint_bytes(0x40), vec![0x40, 0x40]); // min 2-byte
        assert_eq!(varint_bytes(0x3fff), vec![0x7f, 0xff]); // max 2-byte
        assert_eq!(varint_bytes(0x4000), vec![0x80, 0x00, 0x40, 0x00]); // min 4-byte
        assert_eq!(varint_bytes(30_000), vec![0x80, 0x00, 0x75, 0x30]); // 4-byte
    }

    #[test]
    fn client_hello_is_a_clienthello_handshake_message_with_empty_session_id() {
        let ch = build_quic_client_hello("example.com", &[]);
        assert_eq!(ch[0], 0x01, "handshake type must be ClientHello");
        let len = ((ch[1] as usize) << 16) | ((ch[2] as usize) << 8) | ch[3] as usize;
        assert_eq!(len, ch.len() - 4, "3-byte length must cover the body");
        // legacy_version(2) + random(32) → session_id length byte at offset 4+34.
        assert_eq!(ch[4], 0x03);
        assert_eq!(ch[5], 0x03);
        assert_eq!(
            ch[4 + 2 + 32],
            0x00,
            "legacy_session_id must be empty in QUIC"
        );
    }

    #[test]
    fn client_hello_advertises_h3_and_transport_params() {
        let scid = [0xAAu8; 8];
        let ch = build_quic_client_hello("example.com", &scid);
        // Грубая, но достаточная проверка присутствия ключевых байтов:
        // ALPN "h3" и id расширения quic_transport_parameters (0x00 0x39).
        assert!(
            ch.windows(2).any(|w| w == [b'h', b'3']),
            "ALPN h3 must be present"
        );
        assert!(
            ch.windows(2).any(|w| w == [0x00, 0x39]),
            "quic_transport_parameters extension must be present"
        );
        // initial_source_connection_id должен содержать байты SCID.
        assert!(
            ch.windows(scid.len()).any(|w| w == scid),
            "initial_source_connection_id must carry the SCID"
        );
    }
}
