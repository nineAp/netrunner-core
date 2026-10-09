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
    assert!(p.notes.iter().all(|n| n.contains("форма трафика")), "notes: {:#?}", p.notes);

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
    // Раньше ECH-payload был зашитой константой и попадал в notes; теперь
    // профиль хранит наблюдавшиеся длины и сборщик берёт случайную из них.
    // единственные замечания — о малом числе наблюдений формы трафика (фикстура короткая)
    assert!(p.notes.iter().all(|n| n.contains("форма трафика")), "{:#?}", p.notes);
    assert_eq!(p.compress_cert_algs, vec![2]);
    assert_eq!(p.psk_modes, vec![1]);
    assert_eq!(p.ec_point_formats, vec![0]);

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

/// JSON — единственный канал между снятием профиля и движком: профиль,
/// записанный в JSON и прочитанный обратно, ведёт себя как оригинал, а длина
/// ECH-payload у него случайна из наблюдавшегося набора.
#[test]
fn captured_profile_survives_json_and_drives_the_builder() {
    use crate::browser_profile::{self, ProfileSpec};
    let _guard = crate::nrxp::shape::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let a = analyze(REAL_CHROME_148).unwrap();
    let p = a.build_profile(&ProfileOptions {
        name: Some("chrome_148".into()),
        ..Default::default()
    })
    .unwrap();
    let json = p.to_json();
    assert!(json.contains("\"server_name\"") && json.contains("\"0x11ec\""), "{json}");

    // Валидация и разбор обратно.
    let spec = ProfileSpec::from_json(&json).unwrap();
    assert!(spec.validate().unwrap().iter().all(|w| w.contains("shape")));
    let built = spec.into_profile().unwrap();
    assert_eq!(built.ech_payload_lengths, p.ech_payload_lengths.as_slice());

    // Собранные hello дают тот же JA4 и разные длины ECH.
    let mut lens = std::collections::HashSet::new();
    for i in 0..40u16 {
        let keys = SessionKeys::new(true);
        let wire = ClientHello::make_client_hello(built, "a.test", &keys);
        let an = analyze(&pcap_file(&connection(48000 + i, &wire, &[41], 1_700_000_000_000_000_000)))
            .unwrap();
        assert_eq!(ja4(&an.client_hellos[0]), p.ja4);
        lens.insert(an.client_hellos[0].ech.unwrap().1);
    }
    assert!(lens.len() > 1, "ECH payload length must vary: {lens:?}");
    assert!(lens.iter().all(|l| p.ech_payload_lengths.contains(l)), "{lens:?}");

    // Подмена встроенного пула: сессии берут профиль из JSON.
    let report = browser_profile::load_json(&json).unwrap();
    assert_eq!(report.names, vec!["chrome_148"]);
    assert_eq!(browser_profile::active_count(), 1);
    let chosen = BrowserProfile::for_session("any-session");
    assert_eq!(chosen.ech_payload_lengths, p.ech_payload_lengths.as_slice());
    browser_profile::clear();
    assert_eq!(browser_profile::active_count(), 0);
    assert!(BrowserProfile::for_session("any-session").ech_payload_lengths == [144]);

    // Некорректный профиль отклоняется и не меняет состояние.
    let bad = json.replace("\"0x001d\"", "\"0x0017\"");
    assert!(browser_profile::load_json(&bad).is_err());
    assert_eq!(browser_profile::active_count(), 0);
}

/// Снятый с настоящего Chrome профиль воспроизводится движком: JA4 тот же,
/// перемешивание и разброс ECH на месте. Подмена отпечатка в профиле ловится.
#[test]
fn verify_confirms_real_profile_and_catches_a_mismatch() {
    let a = analyze(REAL_CHROME_148).unwrap();
    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    let rep = a.verify_profile(&p, DEFAULT_SAMPLES).unwrap();
    assert!(rep.ok(), "{:#?}", rep.problems);
    assert!(rep.ja4_match && rep.extension_set_match && rep.ech_match);
    assert!(rep.order_variants >= 2, "shuffle must be reproduced: {}", rep.order_variants);
    assert!(rep.ech_lengths_seen.len() >= 2);

    // Профиль без перемешивания вместо перемешивающего — расхождение видно.
    let mut bad = p.clone();
    bad.shuffle_extensions = false;
    let rep = a.verify_profile(&bad, DEFAULT_SAMPLES).unwrap();
    assert!(rep.ok(), "no-shuffle build is self-consistent: {:#?}", rep.problems);
    // а вот несовпадающий эталонный JA4 — нет
    let mut bad = p.clone();
    bad.ja4 = "t13d0000h2_000000000000_000000000000".into();
    let rep = bad.verify(a.reference_hello(&p).unwrap(), 4);
    assert!(!rep.ok() && !rep.ja4_match);
}

/// В файле профиля нет имён сайтов из захвата: профиль выкладывают и пересылают.
#[test]
fn profile_json_does_not_leak_visited_hosts() {
    let a = analyze(REAL_CHROME_148).unwrap();
    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    assert!(p.sni.is_some(), "в памяти SNI остаётся — для сводки в терминале");
    let json = p.to_json();
    assert!(!json.contains("a.test"), "{json}");
    let src = p.to_rust_source();
    assert!(!src.contains("a.test"), "{src}");

    // other_groups тоже без SNI
    let cover = [41usize, 100];
    let mut frames = Vec::new();
    for i in 0..3u16 {
        frames.extend(connection(
            44000 + i,
            &chrome_hello("secret-bank.example"),
            &cover,
            1_700_000_000_000_000_000 + i as u64 * 1_000_000_000,
        ));
    }
    let keys = SessionKeys::new(true);
    let ff = ClientHello::make_client_hello(&BrowserProfile::FIREFOX_130, "private-forum.example", &keys);
    frames.extend(connection(44100, &ff, &cover, 1_700_000_050_000_000_000));
    frames.sort_by_key(|f| f.0);
    let p = analyze(&pcap_file(&frames)).unwrap().build_profile(&ProfileOptions::default()).unwrap();
    let json = p.to_json();
    assert!(!json.contains("secret-bank") && !json.contains("private-forum"), "{json}");
}

#[test]
fn build_profiles_makes_one_profile_per_fingerprint() {
    let cover = [41usize, 100];
    let mut frames = Vec::new();
    for i in 0..3u16 {
        frames.extend(connection(
            45000 + i,
            &chrome_hello("c.example"),
            &cover,
            1_700_000_000_000_000_000 + i as u64 * 1_000_000_000,
        ));
    }
    for i in 0..2u16 {
        let keys = SessionKeys::new(true);
        let ff = ClientHello::make_client_hello(&BrowserProfile::FIREFOX_130, "f.example", &keys);
        frames.extend(connection(45100 + i, &ff, &cover, 1_700_000_050_000_000_000 + i as u64 * 1_000_000_000));
    }
    // одиночный чужак (например curl) отсекается порогом
    let keys = SessionKeys::new(true);
    let sf = ClientHello::make_client_hello(&BrowserProfile::SAFARI_17, "s.example", &keys);
    frames.extend(connection(45200, &sf, &cover, 1_700_000_090_000_000_000));
    frames.sort_by_key(|f| f.0);
    let a = analyze(&pcap_file(&frames)).unwrap();

    let all = a
        .build_profiles(&ProfileOptions { name: Some("web".into()), ..Default::default() }, 2)
        .unwrap();
    assert_eq!(all.len(), 2, "{:?}", all.iter().map(|p| &p.name).collect::<Vec<_>>());
    assert_eq!(all[0].name, "web");
    assert_eq!(all[1].name, "web_2");
    assert!(all[0].has_grease && !all[1].has_grease);
    assert!(all.iter().all(|p| p.other_groups.is_empty() && p.notes.iter().all(|n| !n.contains("ещё"))));

    let with_single = a.build_profiles(&ProfileOptions::default(), 1).unwrap();
    assert_eq!(with_single.len(), 3);
    assert!(a.build_profiles(&ProfileOptions::default(), 9).is_err());
}

#[test]
fn measured_flight_picks_the_common_full_handshake_for_the_sni() {
    let mut frames = Vec::new();
    // три одинаковых полных рукопожатия с decoy-доменом, одно с другой цепочкой
    for i in 0..3u16 {
        frames.extend(connection(46000 + i, &chrome_hello("decoy.example"), &[27, 4342, 537, 69],
            1_700_000_000_000_000_000 + i as u64 * 1_000_000_000));
    }
    frames.extend(connection(46100, &chrome_hello("decoy.example"), &[27, 3000, 537, 69], 1_700_000_050_000_000_000));
    // посторонний сайт не должен влиять
    frames.extend(connection(46200, &chrome_hello("other.example"), &[30, 999, 100, 53], 1_700_000_060_000_000_000));
    frames.sort_by_key(|f| f.0);
    let a = analyze(&pcap_file(&frames)).unwrap();

    let m = a.measured_flight("decoy.example").unwrap();
    assert_eq!(m.records, vec![27, 4342, 537, 69]);
    assert_eq!((m.seen, m.total, m.distinct), (3, 4, 2));
    // и это ровно то, что принимает узел
    let (f, warn) = crate::decoy::CoverFlight::from_records(m.records).unwrap();
    assert_eq!(f.records.len(), 4);
    assert_eq!(warn.len(), 1); // 27 Б < 41

    assert!(matches!(a.measured_flight("nothing"), Err(PcapError::NoServerFlight)));
}

/// Форма трафика снимается с настоящего Chrome (после рукопожатия, без первого
/// flight'а сервера и `Finished`), попадает в JSON и в движок.
#[test]
fn traffic_shape_is_extracted_serialised_and_installed() {
    use crate::browser_profile;
    use crate::nrxp::shape;
    let _guard = shape::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let a = analyze(REAL_CHROME_148).unwrap();
    assert_eq!(a.flow_shapes.len(), 6);
    let p = a.build_profile(&ProfileOptions::default()).unwrap();
    assert!(!p.shape_up.is_empty() && !p.shape_down.is_empty());
    // первый flight сервера (832/281 и т.д.) в форму не попадает
    assert!(!p.shape_down.contains(&832) && !p.shape_down.contains(&281), "{:?}", p.shape_down);
    assert!(p.shape_up.iter().chain(&p.shape_down).all(|l| (41..=16401).contains(l)));
    // мало наблюдений → понятное замечание, а не молчаливая подмена
    assert!(p.notes.iter().any(|n| n.contains("форма трафика")), "{:#?}", p.notes);

    // Имитируем длинный сёрфинг: форма с достаточным числом значений.
    let mut spec = p.to_spec();
    spec.shape = Some(crate::tlseng::spec::ShapeSpec {
        up: (0..40).map(|i| 90 + i * 11).collect(),
        down: (0..40).map(|i| 300 + i * 40).collect(),
    });
    let json = spec.to_json();
    let report = browser_profile::load_json(&json).unwrap();
    assert_eq!(report.shape_samples, (40, 40));
    shape::set_server_role(false);
    assert_eq!(shape::outbound_samples().map(|v| v.len()), Some(40));
    browser_profile::clear();
    assert!(shape::shape().is_none());

    // Только форма (узел): профиль не подменяется.
    assert_eq!(browser_profile::load_shape_json(&json).unwrap(), (40, 40));
    assert_eq!(browser_profile::active_count(), 0);
    browser_profile::clear();

    // Некорректная форма отвергается.
    let mut bad = spec.clone();
    bad.shape = Some(crate::tlseng::spec::ShapeSpec { up: vec![60000], down: vec![] });
    assert!(browser_profile::load_json(&bad.to_json()).is_err());
    assert!(shape::shape().is_none());
}

// ───────────────────────────────── QUIC ─────────────────────────────────────

use super::net::build::udp_v4;
use crate::browser_profile::{self, Hex64, PacketSpec, QuicSpec, TpKind, TpSpec};
use crate::tlseng::spec::{ExtId, Hex16, ProfileSpec};

fn udp_frames(datagrams: &[bytes::Bytes], sport: u16, t0: u64) -> Vec<(u64, Vec<u8>)> {
    datagrams
        .iter()
        .enumerate()
        .map(|(i, d)| (t0 + i as u64 * 200_000, ethernet(&udp_v4(C, S, sport, 443, d))))
        .collect()
}

/// QUIC-профиль, собранный по реальному Chrome 148 (TCP-часть) с QUIC-особенностями.
fn chrome_quic_spec() -> QuicSpec {
    let a = analyze(REAL_CHROME_148).unwrap();
    let p = a.build_profile(&ProfileOptions { name: Some("chrome_quic".into()), ..Default::default() }).unwrap();
    let mut h = p.to_spec();
    h.alpn = vec!["h3".into()];
    h.alps_protocols = vec!["h3".into()];
    h.record_layer_version = Hex16(0x0303);
    h.raw_extensions.clear();
    h.shape = None;
    let n = h.extension_order.len();
    h.extension_order.insert(n - 1, ExtId(0x0039));
    let tp = |id: u64, v: &str, kind| TpSpec { id: Hex64(id), value: v.into(), kind };
    QuicSpec {
        hello: h,
        scid_len: 0,
        pn_len: 4,
        first_pn: 0,
        scramble_frames: false,
        shuffle_transport_params: false,
        initial_packets: vec![
            PacketSpec { crypto: 1200, datagram: 1252, pn_len: None },
            PacketSpec { crypto: 400, datagram: 1252, pn_len: None },
        ],
        transport_params: vec![
            tp(0x01, "80007530", TpKind::Fixed),
            tp(0x03, "45c0", TpKind::Fixed),
            tp(0x04, "80f00000", TpKind::Fixed),
            tp(0x0f, "", TpKind::Scid),
            tp(27 + 31 * 256, "aabbcc", TpKind::Grease),
            tp(0x11, "00000001000000011a2a3a4a", TpKind::VersionInformation),
            tp(0x3128, "5143414c", TpKind::Fixed),
        ],
    }
}

#[test]
fn builtin_quic_initial_is_parsed_back_with_public_keys() {
    use crate::pcap::quic::{QuicCollector, EXT_QUIC_TP};
    let dcid = [0x42u8; 8];
    let pkt = crate::quiceng::build_client_initial(&crate::quiceng::QuicProfile::CHROME, "www.example.org", &dcid, &[0xaa; 4]);
    let ep = |port| Endpoint { ip: std::net::IpAddr::from([10, 0, 0, 1]), port };
    let mut qc = QuicCollector::default();
    qc.push(1, ep(5000), ep(443), &pkt);
    let (flows, skipped, bad) = qc.finish();
    assert!(skipped.is_empty() && bad == 0);
    let f = &flows[0];
    let h = f.hello.as_ref().expect("ClientHello собран");
    assert_eq!(h.sni.as_deref(), Some("www.example.org"));
    assert_eq!(h.alpn, vec!["h3"]);
    assert_eq!(h.session_id_len, 0);
    assert!(h.quic && crate::pcap::ja4(h).starts_with("q13d"), "{}", crate::pcap::ja4(h));
    assert!(h.has_ext(EXT_QUIC_TP));
    assert_eq!(f.packets[0].dcid, dcid);
    assert_eq!(f.packets[0].scid, vec![0xaa; 4]);
    assert_eq!(f.packets[0].pn, 0);
    assert_eq!(f.packets[0].datagram_len, pkt.len());
    // initial_source_connection_id (0x0f) совпадает с SCID пакета
    assert!(f.transport_params.iter().any(|(id, v)| *id == 0x0f && v == &vec![0xaa; 4]), "{:?}", f.transport_params);
}

#[test]
fn quic_block_validates_and_rejects_nonsense() {
    let ok = chrome_quic_spec();
    assert!(ok.validate().is_ok(), "{:?}", ok.validate());

    let mut bad = ok.clone();
    bad.initial_packets[0].datagram = 900; // меньше 1200 запрещено RFC 9000
    assert!(bad.validate().is_err());
    let mut bad = ok.clone();
    bad.initial_packets.clear();
    assert!(bad.validate().is_err());
    let mut bad = ok.clone();
    bad.pn_len = 9;
    assert!(bad.validate().is_err());
    let mut bad = ok.clone();
    bad.hello.extension_order.retain(|e| e.0 != 0x0039);
    assert!(bad.validate().is_err(), "без quic_transport_parameters QUIC-hello невалиден");
    let mut bad = ok.clone();
    bad.transport_params[0].value = "zz".into();
    assert!(bad.validate().is_err());
    let mut bad = ok.clone();
    bad.hello.quic = Some(Box::new(ok.clone()));
    assert!(bad.validate().is_err(), "вложенный quic запрещён");
}

#[test]
fn quic_profile_is_built_by_the_engine_captured_and_verified() {
    use crate::pcap::quic::{QuicCollector, EXT_QUIC_TP};
    let spec = chrome_quic_spec();
    let runtime = spec.build_runtime().unwrap();

    // 1. Движок собирает два Initial'а нужного размера и номеров.
    let flight = crate::quiceng::build_client_initial_flight(runtime, 1, "www.example.org", &[7u8; 8]);
    assert_eq!(flight.len(), 2, "ClientHello с ML-KEM не умещается в один пакет");
    assert!(flight.iter().all(|d| d.len() == 1252), "{:?}", flight.iter().map(|d| d.len()).collect::<Vec<_>>());

    // 2. Тем же парсером, что и захват, из них собирается ClientHello.
    let ep = |port| Endpoint { ip: std::net::IpAddr::from([10, 0, 0, 1]), port };
    let mut qc = QuicCollector::default();
    for d in &flight {
        qc.push(1, ep(5000), ep(443), d);
    }
    let (flows, _, bad) = qc.finish();
    assert_eq!(bad, 0);
    let f = &flows[0];
    assert_eq!(f.packets.iter().map(|p| p.pn).collect::<Vec<_>>(), vec![0, 1]);
    let h = f.hello.as_ref().expect("собрался ClientHello из двух пакетов");
    assert_eq!(h.sni.as_deref(), Some("www.example.org"));
    assert_eq!(h.session_id_len, 0);
    assert!(h.has_ext(EXT_QUIC_TP) && h.alpn == vec!["h3"]);
    let ids: Vec<u64> = f.transport_params.iter().map(|(i, _)| *i).collect();
    assert_eq!(ids[..4], [0x01, 0x03, 0x04, 0x0f]);
    assert_eq!(ids[5], 0x11);
    assert_eq!(ids[6], 0x3128);
    assert!(crate::pcap::quic::is_grease_param(ids[4]), "{ids:?}");
    let grease = f.transport_params[4].1.len();
    assert_eq!(grease, 3);
    // GREASE-версия в version_information свежая и вида 0x?a?a?a?a
    let vi = &f.transport_params[5].1;
    assert_eq!(&vi[..8], &[0, 0, 0, 1, 0, 0, 0, 1]);

    // 3. Параметры, которые «на соединение», действительно меняются.
    let mut grease_ids = std::collections::HashSet::new();
    let mut vers = std::collections::HashSet::new();
    for _ in 0..30 {
        let fl = crate::quiceng::build_client_initial_flight(runtime, 1, "a.example", &[1u8; 8]);
        let mut qc = QuicCollector::default();
        for d in &fl {
            qc.push(1, ep(5000), ep(443), d);
        }
        let (flows, _, _) = qc.finish();
        grease_ids.insert(flows[0].transport_params[4].0);
        vers.insert(flows[0].transport_params[5].1.clone());
    }
    assert!(grease_ids.len() > 5 && vers.len() > 5, "{} {}", grease_ids.len(), vers.len());

    // 4. Захват → профиль → проверка движком.
    let mut frames = Vec::new();
    for i in 0..4u16 {
        let fl = crate::quiceng::build_client_initial_flight(runtime, 1, "a.example", &[i as u8; 8]);
        frames.extend(udp_frames(&fl, 50000 + i, 1_700_000_000_000_000_000 + i as u64 * 1_000_000_000));
    }
    let an = analyze(&pcap_file(&frames)).unwrap();
    assert_eq!(an.quic_flows.len(), 4);
    assert_eq!(an.quic_initials, 8);
    let q = an.build_quic(&ProfileOptions { name: Some("web".into()), ..Default::default() }).unwrap();
    assert_eq!(q.flows_used, 4);
    assert!(q.ja4.starts_with("q13d"), "{}", q.ja4);
    assert_eq!(q.spec.initial_packets.len(), 2);
    assert!(q.spec.initial_packets.iter().all(|p| p.datagram == 1252));
    assert_eq!((q.spec.scid_len, q.spec.pn_len), (0, 4));
    let kinds: Vec<TpKind> = q.spec.transport_params.iter().map(|t| t.kind).collect();
    assert_eq!(
        kinds,
        vec![TpKind::Fixed, TpKind::Fixed, TpKind::Fixed, TpKind::Scid, TpKind::Grease, TpKind::VersionInformation, TpKind::Fixed]
    );
    assert!(q.spec.hello.extension_order.iter().any(|e| e.0 == 0x0039));
    assert!(q.spec.hello.raw_extensions.is_empty(), "тело 0x0039 в профиль не пишется");
    assert!(q.spec.validate().is_ok(), "{:?}", q.spec.validate());
    let rep = an.verify_quic(&q, DEFAULT_SAMPLES).unwrap();
    assert!(rep.ok(), "{:#?}", rep.problems);
    assert!(rep.order_variants >= 2, "перемешивание расширений воспроизводится: {}", rep.order_variants);
}

#[test]
fn quic_block_travels_through_json_into_the_engine() {
    use crate::nrxp::shape;
    let _guard = shape::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let a = analyze(REAL_CHROME_148).unwrap();
    let p = a.build_profile(&ProfileOptions { name: Some("chrome".into()), ..Default::default() }).unwrap();
    let mut spec = p.to_spec();
    spec.quic = Some(Box::new(chrome_quic_spec()));
    let json = spec.to_json();
    assert!(json.contains("\"quic\"") && json.contains("\"initial_packets\""));

    assert_eq!(browser_profile::active_quic_count(), 0);
    let report = browser_profile::load_json(&json).unwrap();
    assert_eq!(report.quic_profiles, 1);
    assert_eq!(browser_profile::active_quic_count(), 1);
    assert!(crate::quiceng::pick_custom(&[1, 2, 3]).is_some());
    browser_profile::clear();
    assert_eq!(browser_profile::active_quic_count(), 0);
    assert!(crate::quiceng::pick_custom(&[1, 2, 3]).is_none());

    // Некорректный QUIC-блок отвергает загрузку целиком.
    let mut bad = spec.clone();
    bad.quic.as_mut().unwrap().initial_packets[0].datagram = 100;
    assert!(browser_profile::load_json(&bad.to_json()).is_err());
    assert_eq!(browser_profile::active_quic_count(), 0);
}

/// Настоящий Chrome 148 (headless, `--origin-to-force-quic-on`), записанный
/// встроенным рекордером: 9 QUIC-соединений по 2 Initial-датаграммы.
const REAL_CHROME_148_QUIC: &[u8] = include_bytes!("testdata/chrome148_quic.pcap");

#[test]
fn real_chrome_148_quic_capture() {
    use crate::pcap::quic::FrameKind;
    let a = analyze(REAL_CHROME_148_QUIC).unwrap();
    assert_eq!(a.quic_flows.len(), 3);
    assert!(a.warnings.is_empty(), "{:?}", a.warnings);
    let want_ja4 = "q13d0311h3_55b375c5d22e_653d80c3fe9d";
    for f in &a.quic_flows {
        let h = f.hello.as_ref().expect("ClientHello собрался из пакетов настоящего Chrome");
        assert_eq!(crate::pcap::ja4(h), want_ja4);
        assert_eq!(h.alpn, vec!["h3"]);
        assert_eq!(h.session_id_len, 0);
        assert!(h.sni.is_some() && h.ech.is_some() && h.alps.is_some());
        assert!(h.extensions.iter().all(|e| !crate::pcap::is_grease_ext(e.id)), "у QUIC-hello Chrome нет GREASE-расширений");
        // первый полёт: пакеты №1 и №2, датаграммы по 1250, «взбитые» кадры
        let mut pk: Vec<_> = f.packets.iter().collect();
        pk.sort_by_key(|p| p.pn);
        assert_eq!((pk[0].pn, pk[1].pn), (1, 2));
        assert!(pk.iter().all(|p| p.datagram_len == 1250 && p.dcid.len() == 8 && p.scid.is_empty()));
        assert!(pk[0].frames.iter().any(|x| matches!(x, FrameKind::Ping)));
        assert!(pk[0].frames.iter().filter(|x| matches!(x, FrameKind::Crypto { .. })).count() > 4);
        // транспортные параметры: GREASE с 8-байтным идентификатором и пустой SCID
        assert!(f.transport_params.iter().any(|(id, _)| *id == 0x0f));
        assert!(f.transport_params.iter().any(|(id, _)| crate::pcap::quic::is_grease_param(*id) && *id > 0x3fff_ffff));
        assert!(f.transport_params.iter().any(|(id, v)| *id == 0x11 && v.len() == 12));
    }

    let q = a.build_quic(&ProfileOptions { name: Some("chrome_148".into()), ..Default::default() }).unwrap();
    assert_eq!(q.ja4, want_ja4);
    assert_eq!(q.flows_used, 3);
    assert_eq!((q.spec.first_pn, q.spec.scid_len), (1, 0));
    assert!(q.spec.scramble_frames && q.spec.shuffle_transport_params);
    assert!(q.spec.hello.shuffle_extensions, "{}", q.hello.shuffle_evidence);
    assert_eq!(q.spec.initial_packets.len(), 2, "повторные отправки в раскладку не входят: {:?}", q.spec.initial_packets);
    assert!(q.spec.initial_packets.iter().all(|p| p.datagram == 1250));
    assert!(q.spec.hello.extension_order.iter().any(|e| e.0 == 0x0039));
    assert!(q.spec.validate().is_ok(), "{:?}", q.spec.validate());

    // Движок воспроизводит то, что снято с браузера.
    let rep = a.verify_quic(&q, DEFAULT_SAMPLES).unwrap();
    assert!(rep.ok(), "{:#?}", rep.problems);
    assert!(rep.order_variants >= 2);
}

/// «Взбитая» раскладка устойчива: сотни сборок подряд всегда дают Initial'ы,
/// из которых целиком собирается ClientHello, в пределах датаграммы.
#[test]
fn scrambled_initial_layout_is_always_decodable() {
    use crate::pcap::quic::QuicCollector;
    let a = analyze(REAL_CHROME_148_QUIC).unwrap();
    let q = a.build_quic(&ProfileOptions::default()).unwrap();
    let runtime = q.spec.build_runtime().unwrap();
    let ep = |port| Endpoint { ip: std::net::IpAddr::from([10, 0, 0, 1]), port };
    let mut npackets = std::collections::HashSet::new();
    for i in 0..300u32 {
        let flight = crate::quiceng::build_client_initial_flight(runtime, 1, "fuzz.example", &[i as u8; 8]);
        assert!(!flight.is_empty() && flight.len() <= 4, "{}", flight.len());
        assert!(flight.iter().all(|d| d.len() >= 1200 && d.len() <= 1500), "{:?}", flight.iter().map(|d| d.len()).collect::<Vec<_>>());
        npackets.insert(flight.len());
        let mut qc = QuicCollector::default();
        for d in &flight {
            qc.push(1, ep(5000), ep(443), d);
        }
        let (flows, _, bad) = qc.finish();
        assert_eq!(bad, 0);
        let h = flows[0].hello.as_ref().unwrap_or_else(|| panic!("ClientHello не собрался на итерации {i}"));
        assert_eq!(h.sni.as_deref(), Some("fuzz.example"));
        let mut pns: Vec<u64> = flows[0].packets.iter().map(|p| p.pn).collect();
        pns.sort_unstable();
        assert_eq!(pns[0], 1);
    }
    assert!(npackets.contains(&2));
}

/// Поставляемый `profiles/chrome_148.json` несёт рабочий QUIC-блок: движок собирает
/// по нему Initial'ы, которые разбираются обратно в тот же `ClientHello`.
#[test]
fn shipped_chrome_profile_has_a_working_quic_block() {
    use crate::pcap::quic::QuicCollector;
    let spec = ProfileSpec::from_json(include_str!("../../../profiles/chrome_148.json")).unwrap();
    let q = spec.quic.as_ref().expect("в профиле есть блок quic");
    assert!(q.scramble_frames && q.shuffle_transport_params && q.first_pn == 1);
    let runtime = q.build_runtime().unwrap();
    let ep = |port| Endpoint { ip: std::net::IpAddr::from([10, 0, 0, 1]), port };
    for _ in 0..20 {
        let flight = crate::quiceng::build_client_initial_flight(runtime, 1, "www.debian.org", &[9u8; 8]);
        let mut qc = QuicCollector::default();
        for d in &flight {
            qc.push(1, ep(5000), ep(443), d);
        }
        let (flows, _, bad) = qc.finish();
        assert_eq!(bad, 0);
        let h = flows[0].hello.as_ref().expect("ClientHello собран");
        assert_eq!(crate::pcap::ja4(h), "q13d0311h3_55b375c5d22e_653d80c3fe9d");
    }
}
