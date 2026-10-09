//! Сборка браузерного профиля из захваченных `ClientHello`.
//!
//! Профиль ([`BrowserProfile`](crate::tlseng::BrowserProfile)) — «рецепт»,
//! по которому наш сборщик строит `ClientHello`. Раньше его значения
//! переносили из дампов руками; здесь они вычисляются из самого захвата, а всё,
//! что сборщик воспроизвести **не умеет**, перечисляется в [`CapturedProfile::notes`],
//! чтобы расхождение с браузером было видно, а не скрыто.

use serde::Serialize;

use super::fingerprint::{ja3_hash, ja3_string, ja4};
use super::tls::{ext, is_grease, ClientHelloInfo};

/// `TlsExtensions::GREASE_SLOT_FIRST` / `GREASE_SLOT_LAST`: маркеры позиции
/// крайних GREASE-расширений в `ExtensionOrder`.
const GREASE_SLOT_FIRST: u16 = 0x0a0a;
const GREASE_SLOT_LAST: u16 = 0x2a2a;

/// Расширения, для которых у сборщика есть собственный код.
const KNOWN_EXTENSIONS: &[u16] = &[
    0x0000, // server_name
    0x0005, // status_request
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x000d, // signature_algorithms
    0x0010, // ALPN
    0x0012, // SCT
    0x0015, // padding
    0x0017, // extended_master_secret
    0x001b, // compress_certificate
    0x0022, // delegated_credential
    0x0023, // session_ticket
    0x002b, // supported_versions
    0x002d, // psk_key_exchange_modes
    0x0033, // key_share
    0x44cd, // ALPS
    0xfe0d, // ECH
    0xff01, // renegotiation_info
];

/// Параметры выбора клиента в захвате и оформления результата.
#[derive(Debug, Clone, Default)]
pub struct ProfileOptions {
    /// Имя константы в сгенерированном Rust-коде (`CHROME_141`).
    pub name: Option<String>,
    /// Брать только `ClientHello` с SNI, содержащим эту подстроку.
    pub sni_contains: Option<String>,
    /// Брать только `ClientHello` от этого клиента.
    pub client_ip: Option<std::net::IpAddr>,
    /// Брать группу с этим JA4 (по умолчанию — самую многочисленную).
    pub ja4: Option<String>,
    /// То же для QUIC-отпечатка (JA4 с `q`).
    pub quic_ja4: Option<String>,
}

/// Группа однотипных `ClientHello` (одинаковый JA4).
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintGroup {
    pub ja4: String,
    pub hellos: usize,
    pub sni_sample: Option<String>,
}

/// Браузерный профиль, снятый с захвата.
#[derive(Debug, Clone, Serialize)]
pub struct CapturedProfile {
    pub name: String,
    pub groups: Vec<u16>,
    pub signatures: Vec<u16>,
    pub delegated_signatures: Vec<u16>,
    pub versions: Vec<u16>,
    pub alpn: Vec<String>,
    /// Порядок расширений; крайние GREASE заменены маркерами позиции.
    pub extension_order: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub record_layer_version: u16,
    pub target_padding_len: u16,
    pub alps_protocols: Vec<String>,
    pub has_grease: bool,
    pub shuffle_extensions: bool,
    /// Чем обосновано значение `shuffle_extensions`.
    pub shuffle_evidence: String,

    /// Наблюдавшиеся длины payload GREASE-ECH во всех `ClientHello` группы
    /// (по возрастанию). У Chrome длина **случайна** среди нескольких значений.
    pub ech_payload_lengths: Vec<u16>,
    pub compress_cert_algs: Vec<u16>,
    pub psk_modes: Vec<u8>,
    pub ec_point_formats: Vec<u8>,
    /// Кодпоинт ALPS из захвата (`0x44cd` либо `0x4469`).
    pub alps_codepoint: Option<u16>,
    /// Расширения без собственной сборки: тело из эталонного hello (id → hex).
    pub raw_extensions: std::collections::BTreeMap<String, String>,

    /// QUIC-блок (если в захвате был клиентский Initial); ставится сборкой профиля.
    pub quic: Option<crate::quiceng::QuicSpec>,
    /// Форма трафика: квантили длин TLS-записей после рукопожатия (клиент →
    /// сервер и обратно) по всем соединениям группы. Пусто — не наблюдалось.
    pub shape_up: Vec<u16>,
    pub shape_down: Vec<u16>,
    /// Сколько записей легло в `shape_*` до сжатия (up, down).
    pub shape_records: (usize, usize),

    /// Отпечатки эталонного `ClientHello`.
    pub ja3: String,
    pub ja3_hash: String,
    pub ja4: String,
    pub sni: Option<String>,
    /// Сколько `ClientHello` использовано для профиля.
    pub hellos_used: usize,
    /// Прочие группы отпечатков, найденные в захвате (в профиль не вошли).
    pub other_groups: Vec<FingerprintGroup>,
    /// Что сборщик не воспроизводит точно / допущения.
    pub notes: Vec<String>,
}

fn strip_grease(v: &[u16]) -> Vec<u16> {
    v.iter().copied().filter(|x| !is_grease(*x)).collect()
}

/// Порядок расширений с маркерами GREASE-слотов.
fn order_with_slots(ch: &ClientHelloInfo) -> Vec<u16> {
    let n = ch.extensions.len();
    ch.extensions
        .iter()
        .enumerate()
        .map(|(i, e)| {
            if is_grease(e.id) {
                if i == 0 {
                    GREASE_SLOT_FIRST
                } else if i + 1 == n {
                    GREASE_SLOT_LAST
                } else {
                    e.id
                }
            } else {
                e.id
            }
        })
        .collect()
}

/// «Середина» порядка (без крайних GREASE) — то, что Chromium перемешивает.
fn middle(order: &[u16]) -> &[u16] {
    let mut s = 0;
    let mut e = order.len();
    if order.first().is_some_and(|x| *x == GREASE_SLOT_FIRST) {
        s = 1;
    }
    if e > s && order.last().is_some_and(|x| *x == GREASE_SLOT_LAST) {
        e -= 1;
    }
    &order[s..e]
}

/// Выбирает `ClientHello` по фильтрам и группирует их по JA4.
pub fn select_hellos<'a>(
    all: &'a [ClientHelloInfo],
    opt: &ProfileOptions,
) -> (Vec<&'a ClientHelloInfo>, Vec<FingerprintGroup>) {
    let filtered: Vec<&ClientHelloInfo> = all
        .iter()
        .filter(|h| {
            opt.client_ip.is_none_or(|ip| h.client.ip == ip)
                && opt.sni_contains.as_ref().is_none_or(|s| {
                    h.sni.as_ref().is_some_and(|x| x.contains(s.as_str()))
                })
        })
        .collect();

    // Ротационные (resumption) hello содержат pre_shared_key (0x0029) и дают
    // иной отпечаток; предпочитаем полные рукопожатия.
    let fresh: Vec<&ClientHelloInfo> = filtered
        .iter()
        .copied()
        .filter(|h| !h.has_ext(0x0029))
        .collect();
    let pool = if fresh.is_empty() { filtered } else { fresh };

    let mut groups: Vec<(String, Vec<&ClientHelloInfo>)> = Vec::new();
    for h in pool {
        let key = ja4(h);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(h),
            None => groups.push((key, vec![h])),
        }
    }
    let summary: Vec<FingerprintGroup> = groups
        .iter()
        .map(|(k, v)| FingerprintGroup {
            ja4: k.clone(),
            hellos: v.len(),
            sni_sample: v.iter().find_map(|h| h.sni.clone()),
        })
        .collect();

    let chosen = match &opt.ja4 {
        Some(want) => groups.into_iter().find(|(k, _)| k == want),
        None => {
            // Самая многочисленная; при равенстве — появившаяся раньше.
            let mut best: Option<usize> = None;
            for (i, (_, v)) in groups.iter().enumerate() {
                if best.is_none_or(|b| v.len() > groups[b].1.len()) {
                    best = Some(i);
                }
            }
            best.map(|i| groups.swap_remove(i))
        }
    };
    (chosen.map(|(_, v)| v).unwrap_or_default(), summary)
}

impl CapturedProfile {
    /// Строит профиль из группы `ClientHello` одного отпечатка.
    /// Эталоном служит первый; остальные нужны, чтобы определить
    /// перемешивание расширений.
    pub fn from_hellos(hellos: &[&ClientHelloInfo], opt: &ProfileOptions) -> Option<Self> {
        let r = *hellos.first()?;
        let mut notes: Vec<String> = Vec::new();

        let groups = strip_grease(&r.supported_groups);
        let versions = {
            let v = strip_grease(&r.supported_versions);
            if v.is_empty() {
                notes.push(
                    "нет расширения supported_versions: версии взяты из legacy_version".into(),
                );
                vec![r.legacy_version]
            } else {
                v
            }
        };
        let order = order_with_slots(r);
        let has_grease = r.cipher_suites.iter().any(|c| is_grease(*c))
            || r.extensions.iter().any(|e| is_grease(e.id));

        // ── перемешивание расширений ──
        let (shuffle, evidence) = if hellos.len() >= 2 {
            let mids: Vec<Vec<u16>> = hellos
                .iter()
                .map(|h| middle(&order_with_slots(h)).to_vec())
                .collect();
            let distinct = mids.iter().any(|m| *m != mids[0]);
            if distinct {
                (
                    true,
                    format!("порядок расширений различается между {} ClientHello", hellos.len()),
                )
            } else {
                (
                    false,
                    format!(
                        "порядок одинаков во всех {} ClientHello (при перемешивании это \
                         практически невозможно)",
                        hellos.len()
                    ),
                )
            }
        } else {
            let guess = has_grease && (r.alps.is_some() || r.ech.is_some());
            (
                guess,
                "один ClientHello: перемешивание не наблюдаемо, эвристика \
                 «GREASE + ALPS/ECH ⇒ Chromium ⇒ перемешивает»; снимите ≥ 2 соединений"
                    .to_string(),
            )
        };

        // ── паддинг ──
        let target_padding_len = match r.padding_ext_len {
            Some(_) if !r.fragmented => r.record_payload_len.min(u16::MAX as usize) as u16,
            Some(_) => {
                notes.push("ClientHello с padding разбит на несколько записей: цель паддинга не определена".into());
                0
            }
            None => 0,
        };

        // ── что сборщик не воспроизводит ──
        if r.fragmented {
            notes.push("ClientHello разбит на несколько TLS-записей (наш сборщик шлёт одной)".into());
        }
        if r.legacy_version != 0x0303 {
            notes.push(format!("legacy_version = {:#06x}, сборщик пишет 0x0303", r.legacy_version));
        }
        if r.quic {
            if r.session_id_len != 0 {
                notes.push(format!(
                    "session_id в QUIC длиной {} Б, должен быть пуст (RFC 9001 §8.4)",
                    r.session_id_len
                ));
            }
        } else if r.session_id_len != 32 {
            notes.push(format!(
                "session_id длиной {} Б, сборщик всегда использует 32 Б (в нём несёт служебные поля)",
                r.session_id_len
            ));
        }
        if r.compression != [0] {
            notes.push(format!("compression_methods = {:?}, сборщик пишет [0]", r.compression));
        }
        // Расширения без собственной сборки сохраняются «сырыми»: тело берётся из
        // эталонного hello. Если оно меняется между соединениями (cookie, ticket),
        // повтор одного значения сам станет признаком — предупреждаем.
        let mut raw_extensions = std::collections::BTreeMap::new();
        for e in &r.extensions {
            if is_grease(e.id) || KNOWN_EXTENSIONS.contains(&e.id) || e.id == ext::ALPS_OLD {
                continue;
            }
            // Транспортные параметры QUIC движок заполняет сам на каждое соединение.
            if r.quic && e.id == super::quic::EXT_QUIC_TP {
                continue;
            }
            let varies = hellos.iter().any(|h| {
                h.extensions.iter().find(|x| x.id == e.id).map(|x| &x.data) != Some(&e.data)
            });
            raw_extensions.insert(
                format!("{:#06x}", e.id),
                e.data.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            );
            if e.id == 0x0029 {
                notes.push("pre_shared_key (0x0029): resumption-hello, профиль из него не годится".into());
            } else if varies {
                notes.push(format!(
                    "расширение {:#06x} без сборки: тело меняется между соединениями, но в профиль \
                     записано одно значение (raw_extensions)",
                    e.id
                ));
            }
        }
        if let Some(sr) = r.extensions.iter().find(|e| e.id == ext::STATUS_REQUEST) {
            if sr.data != [1, 0, 0, 0, 0] {
                notes.push("status_request отличается от OCSP с пустыми списками".into());
            }
        }
        for (id, name, want) in [
            (0x0012u16, "signed_certificate_timestamp", &[][..]),
            (0x0017, "extended_master_secret", &[][..]),
            (0x0023, "session_ticket", &[][..]),
            (0xff01, "renegotiation_info", &[0u8][..]),
        ] {
            if let Some(e) = r.extensions.iter().find(|e| e.id == id) {
                if e.data != want {
                    notes.push(format!("{name}: содержимое отличается от того, что пишет сборщик"));
                }
            }
        }
        let mut ech_lens: Vec<u16> = hellos.iter().filter_map(|h| h.ech.map(|e| e.1)).collect();
        ech_lens.sort_unstable();
        ech_lens.dedup();
        if let Some((enc, _)) = r.ech {
            if enc != 32 {
                notes.push(format!("ECH: enc = {enc} Б, сборщик пишет 32 Б"));
            }
        } else if r.has_ext(ext::ECH) {
            notes.push("ECH не вида outer: сборщик пишет GREASE-ECH outer".into());
        }
        // key_share: сборщик строит [GREASE 1Б] [ML-KEM 1216Б] x25519 32Б
        {
            let mut expect: Vec<(bool, u16, u16)> = Vec::new(); // (grease, group, len)
            if has_grease {
                expect.push((true, 0, 1));
            }
            if groups.contains(&0x11ec) {
                expect.push((false, 0x11ec, 1216));
            }
            expect.push((false, 0x001d, 32));
            let got: Vec<(bool, u16, u16)> = r
                .key_shares
                .iter()
                .map(|k| {
                    if is_grease(k.group) {
                        (true, 0, k.len)
                    } else {
                        (false, k.group, k.len)
                    }
                })
                .collect();
            if r.has_ext(ext::KEY_SHARE) && got != expect {
                notes.push(format!(
                    "key_share отличается от собираемого (наблюдается {:?}): \
                     сборщик строит GREASE/ML-KEM/x25519 по списку групп",
                    r.key_shares
                        .iter()
                        .map(|k| format!("{:#06x}:{}", k.group, k.len))
                        .collect::<Vec<_>>()
                ));
            }
        }
        if !r.has_ext(ext::SUPPORTED_GROUPS) || !groups.contains(&0x001d) {
            notes.push("x25519 нет среди supported_groups: обмен ключами идёт по X25519, клиент сломан для нашего протокола".into());
        }
        let ciphers = strip_grease(&r.cipher_suites);
        if !ciphers.iter().any(|c| matches!(c, 0x1301..=0x1303)) {
            notes.push("нет TLS 1.3-наборов 1301/1302/1303: сервер не сможет выбрать AEAD".into());
        }
        if hellos.len() > 1 {
            // Все ли hello группы имеют одинаковые наборы.
            let same = hellos.iter().all(|h| {
                strip_grease(&h.cipher_suites) == ciphers
                    && strip_grease(&h.supported_groups) == groups
                    && h.signature_algorithms == r.signature_algorithms
            });
            if !same {
                notes.push("в группе есть ClientHello с различающимися списками шифров/групп/подписей".into());
            }
        }

        let name = opt.name.clone().unwrap_or_else(|| "CAPTURED".to_string());
        Some(Self {
            name,
            groups,
            signatures: r.signature_algorithms.clone(),
            delegated_signatures: r.delegated_credential.clone().unwrap_or_default(),
            versions,
            alpn: r.alpn.clone(),
            extension_order: order,
            cipher_suites: ciphers,
            record_layer_version: r.record_version,
            target_padding_len,
            alps_protocols: r.alps.as_ref().map(|(_, p)| p.clone()).unwrap_or_default(),
            has_grease,
            shuffle_extensions: shuffle,
            ech_payload_lengths: ech_lens,
            compress_cert_algs: r.compress_certificate.clone(),
            psk_modes: r.psk_modes.clone(),
            ec_point_formats: r.ec_point_formats.clone(),
            alps_codepoint: r.alps.as_ref().map(|(c, _)| *c),
            raw_extensions,
            quic: None,
            shape_up: Vec::new(),
            shape_down: Vec::new(),
            shape_records: (0, 0),
            shuffle_evidence: evidence,
            ja3: ja3_string(r),
            ja3_hash: ja3_hash(r),
            ja4: ja4(r),
            sni: r.sni.clone(),
            hellos_used: hellos.len(),
            other_groups: Vec::new(),
            notes,
        })
    }

    /// Профиль как JSON-описание [`ProfileSpec`](crate::browser_profile::ProfileSpec):
    /// его читает движок (`browser_profile::load_file`), его можно править руками.
    pub fn to_spec(&self) -> crate::browser_profile::ProfileSpec {
        use crate::browser_profile::{ExtId, Hex16, ProfileSpec, SCHEMA_VERSION};
        let h = |v: &[u16]| v.iter().map(|x| Hex16(*x)).collect::<Vec<_>>();
        let order = self
            .extension_order
            .iter()
            .map(|id| ExtId(if *id == ext::ALPS_OLD { ext::ALPS } else { *id }))
            .collect();
        ProfileSpec {
            schema: SCHEMA_VERSION,
            name: self.name.clone(),
            record_layer_version: Hex16(self.record_layer_version),
            cipher_suites: h(&self.cipher_suites),
            groups: h(&self.groups),
            signatures: h(&self.signatures),
            delegated_signatures: h(&self.delegated_signatures),
            versions: h(&self.versions),
            alpn: self.alpn.clone(),
            alps_protocols: self.alps_protocols.clone(),
            alps_codepoint: self.alps_codepoint.filter(|c| *c != ext::ALPS).map(Hex16),
            extension_order: order,
            has_grease: Some(self.has_grease),
            shuffle_extensions: self.shuffle_extensions,
            target_padding_len: self.target_padding_len,
            ech_payload_lengths: self.ech_payload_lengths.clone(),
            compress_cert_algs: h(&self.compress_cert_algs),
            psk_modes: self.psk_modes.clone(),
            ec_point_formats: self.ec_point_formats.clone(),
            raw_extensions: self.raw_extensions.clone(),
            quic: self.quic.clone().map(Box::new),
            shape: (!self.shape_up.is_empty() || !self.shape_down.is_empty()).then(|| {
                crate::tlseng::spec::ShapeSpec { up: self.shape_up.clone(), down: self.shape_down.clone() }
            }),
            meta: Some(serde_json::json!({
                "source": "netrunner pcap profile builder",
                "ja4": self.ja4,
                "ja3_hash": self.ja3_hash,
                "hellos_used": self.hellos_used,
                "shuffle_evidence": self.shuffle_evidence,
                "notes": self.notes,
                // Только отпечаток и счётчик: имена сайтов из захвата в файл не попадают —
                // профиль выкладывают и пересылают, а SNI — это история посещений.
                "other_groups": self.other_groups
                    .iter()
                    .map(|g| serde_json::json!({ "ja4": g.ja4, "hellos": g.hellos }))
                    .collect::<Vec<_>>(),
            })),
        }
    }

    /// JSON-описание профиля (см. [`to_spec`](Self::to_spec)).
    pub fn to_json(&self) -> String {
        self.to_spec().to_json()
    }

    /// Готовый к вставке в `core/src/tlseng/profile.rs` ассоциированный
    /// `const` типа `BrowserProfile`.
    pub fn to_rust_source(&self) -> String {
        use std::fmt::Write as _;
        let hex = |v: &[u16]| {
            v.iter()
                .map(|x| format!("{x:#06x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let strs = |v: &[String]| {
            v.iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let rec_ver = match self.record_layer_version {
            0x0301 => "ProtocolVersion::Tls10",
            0x0303 => "ProtocolVersion::Tls12",
            0x0304 => "ProtocolVersion::Tls13",
            _ => "ProtocolVersion::Tls12 /* NOTE: unsupported record version */",
        };
        let mut s = String::new();
        let _ = writeln!(s, "// Сгенерировано pcap-сборщиком профиля netrunner-core.");
        let _ = writeln!(s, "// JA4:  {}", self.ja4);
        let _ = writeln!(s, "// JA3:  {}", self.ja3_hash);
        let _ = writeln!(
            s,
            "// ClientHello в профиле: {}; перемешивание расширений: {} ({})",
            self.hellos_used, self.shuffle_extensions, self.shuffle_evidence
        );
        for n in &self.notes {
            let _ = writeln!(s, "// ВНИМАНИЕ: {n}");
        }
        let _ = writeln!(s, "pub const {}: Self = Self {{", self.name);
        let _ = writeln!(s, "    groups: TlsGroups(&[{}]),", hex(&self.groups));
        let _ = writeln!(s, "    signatures: TlsSignatures(&[{}]),", hex(&self.signatures));
        let _ = writeln!(
            s,
            "    delegated_signatures: TlsSignatures(&[{}]),",
            hex(&self.delegated_signatures)
        );
        let _ = writeln!(s, "    versions: TlsVersions(&[{}]),", hex(&self.versions));
        let _ = writeln!(s, "    record_layer_version: {rec_ver},");
        let _ = writeln!(s, "    cipher_suites: &[{}],", hex(&self.cipher_suites));
        let _ = writeln!(s, "    alpn: &[{}],", strs(&self.alpn));
        let _ = writeln!(s, "    extension_order: ExtensionOrder(&[");
        for id in &self.extension_order {
            let _ = writeln!(s, "        {},", ext_const(*id));
        }
        let _ = writeln!(s, "    ]),");
        let _ = writeln!(s, "    has_grease: {},", self.has_grease);
        let _ = writeln!(s, "    shuffle_extensions: {},", self.shuffle_extensions);
        let _ = writeln!(s, "    alps_protocols: &[{}],", strs(&self.alps_protocols));
        let _ = writeln!(s, "    target_padding_len: {},", self.target_padding_len);
        let _ = writeln!(s, "    ech_payload_lengths: &[{}],", self.ech_payload_lengths.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
        let _ = writeln!(s, "    compress_cert_algs: &[{}],", hex(&self.compress_cert_algs));
        let _ = writeln!(s, "    psk_modes: &{:?},", self.psk_modes);
        let _ = writeln!(s, "    ec_point_formats: &{:?},", self.ec_point_formats);
        let _ = writeln!(s, "    alps_codepoint: {:#06x},", self.alps_codepoint.unwrap_or(ext::ALPS));
        let _ = writeln!(s, "    raw_extensions: &[], // тела расширений — в JSON-варианте (raw_extensions)");
        let _ = writeln!(s, "}};");
        s
    }

    /// Профиль как значение, которым пользуется сборщик `ClientHello`.
    pub(crate) fn to_browser_profile(&self) -> Option<&'static crate::tlseng::BrowserProfile> {
        self.to_spec().into_profile().ok()
    }
}

fn ext_const(id: u16) -> String {
    let name = match id {
        0x0a0a => return "TlsExtensions::GREASE_SLOT_FIRST".into(),
        0x2a2a => return "TlsExtensions::GREASE_SLOT_LAST".into(),
        0x0000 => "SNI",
        0x0005 => "STATUS_REQUEST",
        0x000a => "SUPPORTED_GROUPS",
        0x000b => "EC_POINT_FORMATS",
        0x000d => "SIGNATURE_ALGORITHMS",
        0x0010 => "ALPN",
        0x0012 => "SCT",
        0x0015 => "PADDING",
        0x0017 => "EMS",
        0x001b => "COMPRESS_CERT",
        0x0022 => "DELEGATED_CREDENTIAL",
        0x0023 => "SESSION_TICKET",
        0x002b => "SUPPORTED_VERSIONS",
        0x002d => "PSK_MODES",
        0x0033 => "KEY_SHARE",
        0x44cd => "ALPS",
        0xfe0d => "ECH",
        0xff01 => "RENEGOTIATION_INFO",
        other => return format!("{other:#06x}"),
    };
    format!("TlsExtensions::{name}")
}
