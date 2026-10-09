//! QUIC-профиль как **данные**: блок `quic` в JSON-профиле браузера.
//!
//! Описывает то, чем клиентский Initial отличает один QUIC-стек от другого:
//! `ClientHello` (шифры, группы, порядок расширений — тем же форматом, что и
//! TCP-профиль), транспортные параметры, длину SCID, длину номера пакета и
//! **раскладку Initial-пакетов по датаграммам** (Chrome с постквантовым
//! `key_share` режет `ClientHello` на два пакета в двух датаграммах).
//!
//! Что остаётся зашитым — и почему: длина DCID (8 байт) и версия QUIC (1). Это
//! параметры протокола между нашим клиентом и узлом (по DCID узел находит
//! сессию), а не отпечаток. Содержимое Initial узел не разбирает.

use rand::{Rng, RngExt};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::tlseng::spec::{ProfileError, ProfileSpec};
use crate::tlseng::BrowserProfile;

/// u64, записываемое как `"0x3128"` (читается и числом, и строкой).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hex64(pub u64);

impl Serialize for Hex64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:#06x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Hex64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(Hex64(n)),
            Raw::Str(s) => {
                let t = s.trim();
                let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => u64::from_str_radix(h, 16).ok(),
                    None => t.parse().ok(),
                };
                v.map(Hex64).ok_or_else(|| serde::de::Error::custom(format!("bad number {s:?}")))
            }
        }
    }
}

/// Как значение транспортного параметра получается на каждом соединении.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TpKind {
    /// Значение из профиля как есть.
    #[default]
    Fixed,
    /// `initial_source_connection_id`: подставляется SCID пакета.
    Scid,
    /// Зарезервированный параметр (`31·N + 27`): идентификатор того же класса
    /// длины и случайное значение той же длины — на каждом соединении новые.
    Grease,
    /// `version_information` (0x11): GREASE-версии в списке заменяются свежими.
    VersionInformation,
}

/// Один транспортный параметр (порядок в списке = порядок на проводе).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpSpec {
    pub id: Hex64,
    /// Значение в hex (для `scid` игнорируется).
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub kind: TpKind,
}

/// Один клиентский Initial-пакет: сколько байт CRYPTO несёт и какого размера
/// UDP-датаграмма его везёт (добивается PADDING).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketSpec {
    /// Сколько байт `ClientHello` несёт пакет (в сумме по его CRYPTO-кадрам).
    pub crypto: u16,
    /// Размер UDP-датаграммы пакета (добивается PADDING).
    pub datagram: u16,
    /// Длина номера этого пакета; не задана — берётся `pn_len` профиля.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pn_len: Option<u8>,
}

fn default_pn_len() -> u8 {
    4
}

/// Блок `quic` профиля.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicSpec {
    /// `ClientHello` QUIC. Расширение `quic_transport_parameters` (`"0x0039"`)
    /// стоит в `extension_order` как обычное; тело подставляется движком.
    pub hello: ProfileSpec,
    /// Длина Source Connection ID клиента (Chrome — 0).
    #[serde(default)]
    pub scid_len: u8,
    /// Длина кодируемого номера пакета по умолчанию, 1..=4.
    #[serde(default = "default_pn_len")]
    pub pn_len: u8,
    /// Номер первого пакета (у Chrome — 1, у многих стеков — 0).
    #[serde(default)]
    pub first_pn: u32,
    /// Chrome «взбивает» Initial: `ClientHello` режется на много CRYPTO-кадров
    /// случайной длины, кадры идут вперемешку с PING и PADDING и разложены по
    /// пакетам непоследовательно. Включено — движок делает то же.
    #[serde(default)]
    pub scramble_frames: bool,
    /// Порядок транспортных параметров случаен на каждое соединение.
    #[serde(default)]
    pub shuffle_transport_params: bool,
    /// Раскладка Initial-пакетов (минимум один).
    pub initial_packets: Vec<PacketSpec>,
    #[serde(default)]
    pub transport_params: Vec<TpSpec>,
}

const MIN_DATAGRAM: u16 = 1200;
const MAX_DATAGRAM: u16 = 1500;
const MAX_PACKETS: usize = 8;

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

impl QuicSpec {
    /// Проверка применимости. `Ok` — предупреждения.
    pub fn validate(&self) -> Result<Vec<String>, ProfileError> {
        let mut err = Vec::new();
        let mut warn = Vec::new();
        if self.hello.quic.is_some() {
            err.push("quic.hello must not contain its own quic block".into());
        }
        if self.hello.shape.is_some() {
            warn.push("quic.hello.shape is ignored (the traffic shape is read from the profile itself)".into());
        }
        match self.hello.validate_with_dynamic(&[crate::tlseng::EXT_QUIC_TP]) {
            Ok(w) => warn.extend(w.into_iter().map(|x| format!("quic.hello: {x}"))),
            Err(ProfileError::Invalid(v)) => err.extend(v.into_iter().map(|x| format!("quic.hello: {x}"))),
            Err(e) => err.push(e.to_string()),
        }
        if !self.hello.extension_order.iter().any(|e| e.0 == crate::tlseng::EXT_QUIC_TP) {
            err.push("quic.hello.extension_order must contain \"0x0039\" (quic_transport_parameters)".into());
        }
        if self.hello.alpn.first().map(String::as_str) != Some("h3") {
            warn.push("quic.hello.alpn does not start with \"h3\"".into());
        }
        if self.scid_len > 20 {
            err.push("scid_len must be 0..=20".into());
        }
        if !(1..=4).contains(&self.pn_len) {
            err.push("pn_len must be 1..=4".into());
        }
        for (i, p) in self.initial_packets.iter().enumerate() {
            let pl = p.pn_len.unwrap_or(self.pn_len);
            if !(1..=4).contains(&pl) {
                err.push(format!("initial_packets[{i}].pn_len must be 1..=4"));
            } else if pl < 4 && (self.first_pn as u64 + i as u64) >= 1u64 << (8 * pl as u32) {
                err.push(format!("initial_packets[{i}]: packet number does not fit in {pl} byte(s)"));
            }
        }
        if self.initial_packets.is_empty() || self.initial_packets.len() > MAX_PACKETS {
            err.push(format!("initial_packets: 1..={MAX_PACKETS} entries expected"));
        }
        for (i, p) in self.initial_packets.iter().enumerate() {
            if p.crypto == 0 {
                err.push(format!("initial_packets[{i}].crypto must be > 0"));
            }
            if !(MIN_DATAGRAM..=MAX_DATAGRAM).contains(&p.datagram) {
                err.push(format!(
                    "initial_packets[{i}].datagram {} outside {MIN_DATAGRAM}..={MAX_DATAGRAM} \
                     (RFC 9000 §14.1: a client Initial datagram is at least 1200 bytes)",
                    p.datagram
                ));
            }
        }
        if self.transport_params.len() > 64 {
            err.push("transport_params: more than 64 entries".into());
        }
        for (i, t) in self.transport_params.iter().enumerate() {
            if t.id.0 >= 1 << 62 {
                err.push(format!("transport_params[{i}].id does not fit a QUIC varint"));
            }
            match unhex(&t.value) {
                None => err.push(format!("transport_params[{i}].value is not even-length hex")),
                Some(v) if v.len() > 512 => err.push(format!("transport_params[{i}].value is longer than 512 bytes")),
                Some(_) => {}
            }
            if t.kind == TpKind::Grease && !is_grease_param(t.id.0) {
                warn.push(format!(
                    "transport_params[{i}]: id {:#x} is not of the form 31*N+27 but is marked grease",
                    t.id.0
                ));
            }
        }
        if !self.transport_params.iter().any(|t| t.kind == TpKind::Scid) && self.scid_len > 0 {
            warn.push("scid_len > 0 but no parameter of kind \"scid\" (initial_source_connection_id)".into());
        }
        if err.is_empty() {
            Ok(warn)
        } else {
            Err(ProfileError::Invalid(err))
        }
    }

    /// Строит рабочий профиль (память не освобождается: живёт весь процесс).
    pub(crate) fn build_runtime(&self) -> Result<&'static QuicHelloProfile, ProfileError> {
        self.validate()?;
        let hello = self.hello.into_profile_with_dynamic(&[crate::tlseng::EXT_QUIC_TP])?;
        let tps = self
            .transport_params
            .iter()
            .map(|t| TpTemplate { id: t.id.0, value: unhex(&t.value).unwrap_or_default(), kind: t.kind })
            .collect();
        Ok(Box::leak(Box::new(QuicHelloProfile {
            name: self.hello.name.clone(),
            hello,
            scid_len: self.scid_len as usize,
            pn_len: self.pn_len as usize,
            packets: self
                .initial_packets
                .iter()
                .map(|p| (p.crypto as usize, p.datagram as usize, p.pn_len.unwrap_or(self.pn_len) as usize))
                .collect(),
            first_pn: self.first_pn,
            scramble: self.scramble_frames,
            shuffle_tps: self.shuffle_transport_params,
            tps,
        })))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TpTemplate {
    pub id: u64,
    pub value: Vec<u8>,
    pub kind: TpKind,
}

/// Рабочий QUIC-профиль, собранный из [`QuicSpec`].
pub(crate) struct QuicHelloProfile {
    #[allow(dead_code)]
    pub name: String,
    pub hello: &'static BrowserProfile,
    pub scid_len: usize,
    pub pn_len: usize,
    /// `(байт CRYPTO, размер датаграммы, длина номера пакета)` на пакет.
    pub packets: Vec<(usize, usize, usize)>,
    pub first_pn: u32,
    pub scramble: bool,
    pub shuffle_tps: bool,
    pub tps: Vec<TpTemplate>,
}

fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.extend_from_slice(&(0x4000u16 | v as u16).to_be_bytes());
    } else if v < 0x4000_0000 {
        out.extend_from_slice(&(0x8000_0000u32 | v as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xC000_0000_0000_0000u64 | v).to_be_bytes());
    }
}

/// Зарезервированные идентификаторы параметров: `31·N + 27` (RFC 9000 §18.1).
fn is_grease_param(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

fn varint_len(v: u64) -> usize {
    match v {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

/// GREASE-версия QUIC: `0x?a?a?a?a` (RFC 9000 §15).
fn grease_version(rng: &mut impl Rng) -> u32 {
    (rng.random::<u32>() & 0xf0f0_f0f0) | 0x0a0a_0a0a
}

/// Свежий идентификатор зарезервированного параметра того же класса длины.
fn grease_id(template: u64, rng: &mut impl Rng) -> u64 {
    // Класс длины варинта: 1 байт < 64, 2 < 2^14, 4 < 2^30, 8 — до 2^62 − 1.
    let max_n: u64 = match varint_len(template) {
        1 => 1, // 27, 58
        2 => (0x3fff - 27) / 31,
        4 => (0x3fff_ffff - 27) / 31,
        _ => ((1u64 << 62) - 1 - 27) / 31,
    };
    let min_n: u64 = match varint_len(template) {
        2 => 2,
        4 => (0x4000 - 27) / 31 + 1,
        8 => (0x4000_0000 - 27) / 31 + 1,
        _ => 0,
    };
    27 + 31 * rng.random_range(min_n..=max_n.max(min_n))
}

impl QuicHelloProfile {
    /// Тело `quic_transport_parameters` для нового соединения.
    pub(crate) fn transport_params(&self, scid: &[u8]) -> Vec<u8> {
        let mut rng = rand::rng();
        let mut out = Vec::with_capacity(128);
        let mut order: Vec<&TpTemplate> = self.tps.iter().collect();
        if self.shuffle_tps {
            // Fisher–Yates
            for i in (1..order.len()).rev() {
                order.swap(i, rng.random_range(0..=i));
            }
        }
        for t in order {
            let (id, value): (u64, Vec<u8>) = match t.kind {
                TpKind::Fixed => (t.id, t.value.clone()),
                TpKind::Scid => (t.id, scid.to_vec()),
                TpKind::Grease => {
                    let mut v = vec![0u8; t.value.len()];
                    rng.fill(&mut v[..]);
                    (grease_id(t.id, &mut rng), v)
                }
                TpKind::VersionInformation => {
                    let mut v = t.value.clone();
                    for c in v.chunks_exact_mut(4) {
                        let ver = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                        if ver & 0x0f0f_0f0f == 0x0a0a_0a0a {
                            c.copy_from_slice(&grease_version(&mut rng).to_be_bytes());
                        }
                    }
                    (t.id, v)
                }
            };
            put_varint(&mut out, id);
            put_varint(&mut out, value.len() as u64);
            out.extend_from_slice(&value);
        }
        out
    }
}

// ───────────────────────────── реестр ───────────────────────────────────────

static CUSTOM: std::sync::RwLock<Vec<&'static QuicHelloProfile>> = std::sync::RwLock::new(Vec::new());

pub(crate) fn set_custom(list: Vec<&'static QuicHelloProfile>) {
    if let Ok(mut g) = CUSTOM.write() {
        *g = list;
    }
}

pub(crate) fn custom_count() -> usize {
    CUSTOM.read().map(|g| g.len()).unwrap_or(0)
}

/// Профиль для сессии: стабильный по `key` (например `leg_token`), `None` —
/// пользовательских нет, работает встроенный Initial.
pub(crate) fn pick_custom(key: &[u8]) -> Option<&'static QuicHelloProfile> {
    let g = CUSTOM.read().ok()?;
    if g.is_empty() {
        return None;
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h);
    Some(g[(h.finish() as usize) % g.len()])
}

