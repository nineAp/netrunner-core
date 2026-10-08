//! Сквозные тесты: синтетический захват (кадры собираются из настоящих
//! `ClientHello` нашего же сборщика) → разбор → профиль → пересборка.

use super::net::build::{ethernet, tcp_v4};
use super::net::{TCP_ACK, TCP_SYN};
use super::*;
use crate::crypto::SessionKeys;
use crate::tlseng::{BrowserProfile, ClientHello};

const C: [u8; 4] = [192, 168, 1, 10];
const S: [u8; 4] = [203, 0, 113, 7];

fn pcap_file(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0xa1b23c4du32.to_le_bytes()); // наносекунды
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&4u16.to_le_bytes());
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&65535u32.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    for (ts, d) in frames {
        f.extend_from_slice(&((ts / 1_000_000_000) as u32).to_le_bytes());
        f.extend_from_slice(&((ts % 1_000_000_000) as u32).to_le_bytes());
        f.extend_from_slice(&(d.len() as u32).to_le_bytes());
        f.extend_from_slice(&(d.len() as u32).to_le_bytes());
        f.extend_from_slice(d);
    }
    f
}

fn server_hello_record(suite: u16) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[5u8; 32]);
    body.push(32);
    body.extend_from_slice(&[9u8; 32]);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    ext.extend_from_slice(&[7u8; 32]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![2, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 3];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn record(ct: u8, len: usize) -> Vec<u8> {
    let mut r = vec![ct, 3, 3];
    r.extend_from_slice(&(len as u16).to_be_bytes());
    r.extend(std::iter::repeat(0xab).take(len));
    r
}

/// Кадры одного TLS-соединения: SYN-рукопожатие, ClientHello в двух сегментах
/// (второй приходит раньше первого), ответ сервера и первая запись клиента.
fn connection(
    sport: u16,
    client_hello: &[u8],
    cover: &[usize],
    t0: u64,
) -> Vec<(u64, Vec<u8>)> {
    let isn_c = 1000u32 + sport as u32;
    let isn_s = 5000u32;
    let split = client_hello.len().min(1448);
    let (a, b) = client_hello.split_at(split);
    let mut out = vec![
        (t0, ethernet(&tcp_v4(C, S, sport, 443, isn_c, TCP_SYN, b""))),
        (
            t0 + 1_000,
            ethernet(&tcp_v4(S, C, 443, sport, isn_s, TCP_SYN | TCP_ACK, b"")),
        ),
    ];
    let mut t = t0 + 2_000_000;
    if !b.is_empty() {
        out.push((
            t,
            ethernet(&tcp_v4(C, S, sport, 443, isn_c + 1 + a.len() as u32, TCP_ACK, b)),
        ));
        t += 1_000;
    }
    out.push((t, ethernet(&tcp_v4(C, S, sport, 443, isn_c + 1, TCP_ACK, a))));

    // Ответ сервера: ServerHello + CCS + flight ApplicationData.
    let mut s_bytes = server_hello_record(0x1301);
    s_bytes.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
    for len in cover {
        s_bytes.extend_from_slice(&record(0x17, *len));
    }
    let mut seq = isn_s + 1;
    t += 20_000_000;
    for chunk in s_bytes.chunks(1400) {
        out.push((t, ethernet(&tcp_v4(S, C, 443, sport, seq, TCP_ACK, chunk))));
        seq += chunk.len() as u32;
        t += 10_000;
    }
    // Запись клиента (Finished) позже flight'а + пост-handshake тикет сервера.
    t += 5_000_000;
    out.push((
        t,
        ethernet(&tcp_v4(
            C,
            S,
            sport,
            443,
            isn_c + 1 + client_hello.len() as u32,
            TCP_ACK,
            &record(0x17, 74),
        )),
    ));
    t += 3_000_000;
    out.push((t, ethernet(&tcp_v4(S, C, 443, sport, seq, TCP_ACK, &record(0x17, 250)))));
    out
}

fn chrome_hello(host: &str) -> Vec<u8> {
    let keys = SessionKeys::new(true);
    ClientHello::make_client_hello(&BrowserProfile::CHROME_140, host, &keys).to_vec()
}

#[test]
fn chrome140_capture_round_trip() {
    let cover = [41usize, 2385, 97, 53];
    let ch = chrome_hello("www.debian.org");
    let frames = connection(40001, &ch, &cover, 1_700_000_000_000_000_000);
    let file = pcap_file(&frames);

    let a = analyze(&file).unwrap();
    assert_eq!(a.tcp_flows, 1);
    assert_eq!(a.client_hellos.len(), 1);
    let h = &a.client_hellos[0];
    assert_eq!(h.sni.as_deref(), Some("www.debian.org"));
    assert_eq!(h.record_payload_len, ch.len() - 5);
    assert!(!h.fragmented);

    // первый flight сервера, без пост-handshake тикета (он позже Finished клиента)
    let f = a.flight_for(h).unwrap();
    assert_eq!(f.cover_records, cover);
    assert!(f.ccs_seen);
    assert_eq!(f.server_hello.cipher_suite, 0x1301);
    assert_eq!(f.server_hello.selected_version, Some(0x0304));
    assert_eq!(f.server_hello.key_share_group, Some(0x001d));
    assert_eq!(f.cover_flight().records, cover);

    let p = a
        .build_profile(&ProfileOptions {
            name: Some("CHROME_TEST".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(p.groups, vec![0x11ec, 0x001d, 0x0017, 0x0018]);
    assert_eq!(p.signatures.len(), 11);
    assert_eq!(p.signatures[0], 0x0904);
    assert_eq!(p.versions, vec![0x0304, 0x0303]);
    assert_eq!(p.alpn, vec!["h2", "http/1.1"]);
    assert_eq!(p.alps_protocols, vec!["h2"]);
    assert_eq!(p.record_layer_version, 0x0301);
    assert_eq!(p.target_padding_len, 0);
    assert!(p.has_grease);
    assert_eq!(p.cipher_suites.len(), 15);
    assert_eq!(p.extension_order.first(), Some(&0x0a0a));
    assert_eq!(p.extension_order.last(), Some(&0x2a2a));
    assert_eq!(p.extension_order.len(), 18);
    assert!(p.ja4.starts_with("t13d1516h2_"), "{}", p.ja4);
    // собственный сборщик ничего не «недовоспроизводит»
    assert!(p.notes.is_empty(), "notes: {:#?}", p.notes);

    // тот же набор расширений, что в эталонном профиле крейта
    let mut got = p.extension_order.clone();
    let mut want = BrowserProfile::CHROME_140.extension_order.0.to_vec();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want);

    // пересборка из снятого профиля даёт тот же JA4
    let rebuilt = p.to_browser_profile().unwrap();
    let keys = SessionKeys::new(true);
    let wire = ClientHello::make_client_hello(rebuilt, "www.debian.org", &keys);
    let file2 = pcap_file(&connection(40002, &wire, &cover, 1_700_000_100_000_000_000));
    let p2 = analyze(&file2).unwrap().build_profile(&ProfileOptions::default()).unwrap();
    assert_eq!(p2.ja4, p.ja4);
    assert_eq!(p2.groups, p.groups);

    let src = p.to_rust_source();
    assert!(src.contains("pub const CHROME_TEST: Self = Self {"));
    assert!(src.contains("TlsGroups(&[0x11ec, 0x001d, 0x0017, 0x0018])"));
    assert!(src.contains("TlsExtensions::GREASE_SLOT_FIRST"));
    assert!(src.contains("record_layer_version: ProtocolVersion::Tls10"));
    assert!(p.to_json().contains("\"ja4\""));
}

#[test]
fn shuffle_is_detected_from_several_connections() {
    let cover = [41usize, 2385, 97, 53];
    let mut frames = Vec::new();
    for i in 0..4u16 {
        frames.extend(connection(
            41000 + i,
            &chrome_hello("www.debian.org"),
            &cover,
            1_700_000_000_000_000_000 + i as u64 * 1_000_000_000,
        ));
    }
    frames.sort_by_key(|f| f.0);
    let a = analyze(&pcap_file(&frames)).unwrap();
    assert_eq!(a.client_hellos.len(), 4);
    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    assert!(p.shuffle_extensions, "{}", p.shuffle_evidence);
    assert_eq!(p.hellos_used, 4);

    // Фиксированный порядок (Firefox-профиль не перемешивает) → shuffle=false
    let mut ff = Vec::new();
    for i in 0..3u16 {
        let keys = SessionKeys::new(true);
        let h = ClientHello::make_client_hello(&BrowserProfile::FIREFOX_130, "example.org", &keys);
        ff.extend(connection(42000 + i, &h, &cover, 1_800_000_000_000_000_000 + i as u64 * 1_000_000_000));
    }
    ff.sort_by_key(|f| f.0);
    let p = analyze(&pcap_file(&ff)).unwrap().build_profile(&ProfileOptions::default()).unwrap();
    assert!(!p.shuffle_extensions, "{}", p.shuffle_evidence);
    assert!(!p.has_grease);
}

#[test]
fn groups_and_filters_choose_the_client() {
    let cover = [41usize, 100];
    let mut frames = Vec::new();
    for i in 0..3u16 {
        frames.extend(connection(
            43000 + i,
            &chrome_hello("chrome.example"),
            &cover,
            1_700_000_000_000_000_000 + i as u64 * 1_000_000_000,
        ));
    }
    let keys = SessionKeys::new(true);
    let ff = ClientHello::make_client_hello(&BrowserProfile::FIREFOX_130, "firefox.example", &keys);
    frames.extend(connection(43100, &ff, &cover, 1_700_000_050_000_000_000));
    frames.sort_by_key(|f| f.0);
    let a = analyze(&pcap_file(&frames)).unwrap();

    // по умолчанию — самая многочисленная группа (Chrome)
    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    assert!(p.has_grease);
    assert_eq!(p.other_groups.len(), 1);
    assert!(p.notes.iter().any(|n| n.contains("групп")));

    // фильтр по SNI выбирает Firefox
    let p = a
        .build_profile(&ProfileOptions {
            sni_contains: Some("firefox".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(!p.has_grease);
    assert_eq!(p.sni.as_deref(), Some("firefox.example"));

    // фильтр, которому ничего не соответствует
    let e = a
        .build_profile(&ProfileOptions {
            sni_contains: Some("nothing".into()),
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(e, PcapError::NoClientHello));
}

#[test]
fn padding_target_is_recovered_from_a_padded_hello() {
    // Профиль Chrome 131 паддит ClientHello до 512 байт payload записи.
    let keys = SessionKeys::new(true);
    let h = ClientHello::make_client_hello(&BrowserProfile::CHROME_131, "a.example", &keys);
    let a = analyze(&pcap_file(&connection(44000, &h, &[41], 1_700_000_000_000_000_000))).unwrap();
    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    assert_eq!(p.target_padding_len, 512);
    assert_eq!(p.versions, vec![0x0304]);
}

#[test]
fn garbage_and_empty_captures_fail_cleanly() {
    assert!(analyze(b"not a capture at all").is_err());
    let empty = pcap_file(&[]);
    let a = analyze(&empty).unwrap();
    assert!(a.client_hellos.is_empty());
    assert!(matches!(
        a.build_profile(&ProfileOptions::default()),
        Err(PcapError::NoClientHello)
    ));
    // Захват без TLS: просто TCP-данные
    let junk = pcap_file(&[(1, ethernet(&tcp_v4(C, S, 1, 80, 1, TCP_ACK, b"GET / HTTP/1.1\r\n\r\n")))]);
    assert!(analyze(&junk).unwrap().client_hellos.is_empty());
}

#[test]
fn truncated_capture_still_yields_what_was_complete() {
    let ch = chrome_hello("www.debian.org");
    let mut file = pcap_file(&connection(45000, &ch, &[41, 2385], 1_700_000_000_000_000_000));
    file.truncate(file.len() - 10);
    let a = analyze(&file).unwrap();
    assert_eq!(a.client_hellos.len(), 1);
}

#[test]
fn ja4_and_ja3_are_order_and_grease_insensitive_where_specified() {
    let a = analyze(&pcap_file(&{
        let mut f = Vec::new();
        for i in 0..3u16 {
            f.extend(connection(46000 + i, &chrome_hello("x.example"), &[41], 1_700_000_000_000_000_000 + i as u64 * 1_000_000));
        }
        f.sort_by_key(|x| x.0);
        f
    }))
    .unwrap();
    let ja4s: std::collections::HashSet<_> = a.client_hellos.iter().map(ja4).collect();
    assert_eq!(ja4s.len(), 1, "JA4 не должен зависеть от перемешивания и GREASE");
    let ja3s: std::collections::HashSet<_> = a.client_hellos.iter().map(ja3_hash).collect();
    // JA3 зависит от порядка расширений: при перемешивании различается.
    assert!(ja3s.len() > 1);
}

/// Настоящий захват Google Chrome 148 (headless, loopback → `openssl s_server`,
/// TLS 1.3): 6 соединений, три длины SNI. Снимок не синтетический — это
/// регрессия на реальные байты, а не на то, что мы сами умеем собрать.
const REAL_CHROME_148: &[u8] = include_bytes!("testdata/chrome148_loopback.pcap");

#[test]
fn real_chrome_148_capture() {
    let a = analyze(REAL_CHROME_148).unwrap();
    assert_eq!((a.tcp_flows, a.tls_flows, a.client_hellos.len()), (6, 6, 6));

    // JA4_b = хеш отсортированных шифров настоящего Chrome (`8daaf6152771`),
    // и он един для всех соединений независимо от GREASE и перемешивания.
    let ja4s: std::collections::HashSet<_> = a.client_hellos.iter().map(ja4).collect();
    assert_eq!(ja4s.len(), 1, "{ja4s:?}");
    let j = ja4s.into_iter().next().unwrap();
    assert!(j.starts_with("t13d1516h2_8daaf6152771_"), "{j}");

    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    assert_eq!(p.hellos_used, 6);
    assert_eq!(p.groups, vec![0x11ec, 0x001d, 0x0017, 0x0018]);
    assert_eq!(p.versions, vec![0x0304, 0x0303]);
    assert_eq!(p.alpn, vec!["h2", "http/1.1"]);
    assert_eq!(p.alps_protocols, vec!["h2"]);
    assert_eq!(p.record_layer_version, 0x0301);
    assert_eq!(p.cipher_suites.len(), 15);
    assert!(p.has_grease);
    assert!(p.shuffle_extensions, "{}", p.shuffle_evidence);
    assert_eq!(p.extension_order.len(), 18);
    assert_eq!(p.target_padding_len, 0);
    // Chrome 148 не шлёт ML-DSA в signature_algorithms: 8 значений.
    assert_eq!(
        p.signatures,
        vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    );
    // Длина payload GREASE-ECH у браузера случайна, а не константа.
    assert!(p.ech_payload_lengths.len() > 1, "{:?}", p.ech_payload_lengths);
    assert!(p.notes.iter().any(|n| n.contains("ECH")), "{:#?}", p.notes);

    // Первый flight сервера (openssl s_server, RSA-2048): EE, Certificate,
    // CertificateVerify, Finished — Finished = 4 + 32 + 17 = 53.
    let h = &a.client_hellos[0];
    let f = a.flight_for(h).unwrap();
    assert_eq!(f.cover_records, vec![23, 832, 281, 53]);
    assert_eq!(f.server_hello.selected_version, Some(0x0304));

    // Профиль, снятый с браузера, воссоздаётся нашим сборщиком с тем же JA4.
    let rebuilt = p.to_browser_profile().unwrap();
    let keys = SessionKeys::new(true);
    let wire = ClientHello::make_client_hello(rebuilt, "a.test", &keys);
    let again = analyze(&pcap_file(&connection(47000, &wire, &[23, 832], 1_700_000_000_000_000_000)))
        .unwrap();
    assert_eq!(ja4(&again.client_hellos[0]), j);
}
