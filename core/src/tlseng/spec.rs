//! Профиль браузера как **данные**: JSON-описание ([`ProfileSpec`]), его
//! проверка и превращение в [`BrowserProfile`].
//!
//! Раньше профиль был `const` в коде: чтобы добавить свой, нужно было править
//! Rust и пересобирать. Теперь любой профиль — JSON-файл: его можно снять с
//! браузера (`pcap`-сборщик), отредактировать руками либо написать с нуля, а
//! движок подхватывает его при запуске (`browser_profile::load_file`).
//!
//! Формат версии 1, все числа — числом или строкой `"0x1301"`, расширения —
//! ещё и по имени (`"server_name"`, `"ech"`, `"grease_first"`…):
//!
//! ```json
//! {
//!   "schema": 1,
//!   "name": "my_chrome",
//!   "record_layer_version": "0x0301",
//!   "cipher_suites": ["0x1301", "0x1302", "0x1303", "0xc02b"],
//!   "groups": ["0x11ec", "0x001d", "0x0017", "0x0018"],
//!   "signatures": ["0x0403", "0x0804", "0x0401"],
//!   "versions": ["0x0304", "0x0303"],
//!   "alpn": ["h2", "http/1.1"],
//!   "alps_protocols": ["h2"],
//!   "extension_order": ["grease_first", "alpn", "supported_versions", "alps", "server_name",
//!                       "supported_groups", "key_share", "ech", "signature_algorithms",
//!                       "grease_last"],
//!   "shuffle_extensions": true,
//!   "ech_payload_lengths": [144, 176, 208, 240]
//! }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::profile::BrowserProfile;
use super::types::{ExtensionOrder, ProtocolVersion, TlsExtensions, TlsGroups, TlsSignatures, TlsVersions};

/// Версия формата описания.
pub const SCHEMA_VERSION: u32 = 1;

/// Ошибки загрузки профиля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// Не JSON либо не та структура/неизвестное поле.
    Json(String),
    /// Профиль не годится для работы с нашим протоколом (список причин).
    Invalid(Vec<String>),
    /// Ошибка чтения файла.
    Io(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid profile JSON: {e}"),
            Self::Invalid(v) => write!(f, "profile rejected: {}", v.join("; ")),
            Self::Io(e) => write!(f, "cannot read profile: {e}"),
        }
    }
}

impl std::error::Error for ProfileError {}

// ───────────────────────────── числа и имена ────────────────────────────────

/// u16, записываемое как `"0x1301"` (читается и числом, и строкой).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hex16(pub u16);

impl Serialize for Hex16 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:#06x}", self.0))
    }
}

fn parse_u16(v: &str) -> Option<u16> {
    let v = v.trim();
    if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u16::from_str_radix(h, 16).ok()
    } else {
        v.parse().ok()
    }
}

impl<'de> Deserialize<'de> for Hex16 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => u16::try_from(n)
                .map(Hex16)
                .map_err(|_| serde::de::Error::custom(format!("{n} does not fit in 16 bits"))),
            Raw::Str(s) => parse_u16(&s)
                .map(Hex16)
                .ok_or_else(|| serde::de::Error::custom(format!("bad number {s:?}"))),
        }
    }
}

/// Имена расширений для читаемого JSON.
const EXT_NAMES: &[(&str, u16)] = &[
    ("grease_first", TlsExtensions::GREASE_SLOT_FIRST),
    ("grease_last", TlsExtensions::GREASE_SLOT_LAST),
    ("server_name", TlsExtensions::SNI),
    ("status_request", TlsExtensions::STATUS_REQUEST),
    ("supported_groups", TlsExtensions::SUPPORTED_GROUPS),
    ("ec_point_formats", TlsExtensions::EC_POINT_FORMATS),
    ("signature_algorithms", TlsExtensions::SIGNATURE_ALGORITHMS),
    ("alpn", TlsExtensions::ALPN),
    ("sct", TlsExtensions::SCT),
    ("padding", TlsExtensions::PADDING),
    ("extended_master_secret", TlsExtensions::EMS),
    ("compress_certificate", TlsExtensions::COMPRESS_CERT),
    ("delegated_credential", TlsExtensions::DELEGATED_CREDENTIAL),
    ("session_ticket", TlsExtensions::SESSION_TICKET),
    ("supported_versions", TlsExtensions::SUPPORTED_VERSIONS),
    ("psk_key_exchange_modes", TlsExtensions::PSK_MODES),
    ("key_share", TlsExtensions::KEY_SHARE),
    ("alps", TlsExtensions::ALPS),
    ("ech", TlsExtensions::ECH),
    ("renegotiation_info", TlsExtensions::RENEGOTIATION_INFO),
];

/// Идентификатор расширения: число, `"0x…"` либо имя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtId(pub u16);

impl Serialize for ExtId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match EXT_NAMES.iter().find(|(_, id)| *id == self.0) {
            Some((n, _)) => s.serialize_str(n),
            None => s.serialize_str(&format!("{:#06x}", self.0)),
        }
    }
}

impl<'de> Deserialize<'de> for ExtId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => u16::try_from(n)
                .map(ExtId)
                .map_err(|_| serde::de::Error::custom(format!("{n} does not fit in 16 bits"))),
            Raw::Str(s) => {
                let key = s.trim().to_ascii_lowercase();
                if let Some((_, id)) = EXT_NAMES.iter().find(|(n, _)| *n == key) {
                    return Ok(ExtId(*id));
                }
                parse_u16(&s).map(ExtId).ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "unknown extension {s:?} (use a number, \"0x…\" or one of: {})",
                        EXT_NAMES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                    ))
                })
            }
        }
    }
}

// ─────────────────────────────── описание ───────────────────────────────────

/// JSON-описание браузерного профиля (формат версии 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpec {
    #[serde(default = "default_schema")]
    pub schema: u32,
    pub name: String,
    /// Версия в заголовке TLS-записи с `ClientHello` (`0x0301`/`0x0303`/`0x0304`).
    pub record_layer_version: Hex16,
    /// Шифронаборы без GREASE (он добавляется автоматически при `has_grease`).
    pub cipher_suites: Vec<Hex16>,
    /// `supported_groups` без GREASE. Обязателен `0x001d` (x25519).
    pub groups: Vec<Hex16>,
    pub signatures: Vec<Hex16>,
    #[serde(default)]
    pub delegated_signatures: Vec<Hex16>,
    /// `supported_versions` без GREASE. Обязателен `0x0304`.
    pub versions: Vec<Hex16>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub alps_protocols: Vec<String>,
    /// `0x44cd` (по умолчанию) либо `0x4469`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alps_codepoint: Option<Hex16>,
    /// Порядок расширений. `grease_first`/`grease_last` — позиции GREASE.
    pub extension_order: Vec<ExtId>,
    /// По умолчанию: есть ли GREASE-слоты в `extension_order`.
    #[serde(default)]
    pub has_grease: Option<bool>,
    /// Перемешивать ли середину порядка на каждое соединение (Chromium).
    #[serde(default)]
    pub shuffle_extensions: bool,
    /// Цель паддинга `ClientHello` в байтах payload записи (0 — без).
    #[serde(default)]
    pub target_padding_len: u16,
    /// Длины payload GREASE-ECH; случайная на соединение. Пусто — 144.
    #[serde(default)]
    pub ech_payload_lengths: Vec<u16>,
    /// Алгоритмы `compress_certificate`. Пусто — brotli.
    #[serde(default)]
    pub compress_cert_algs: Vec<Hex16>,
    /// `psk_key_exchange_modes`. Пусто — `[1]`.
    #[serde(default)]
    pub psk_modes: Vec<u8>,
    /// `ec_point_formats`. Пусто — `[0]`.
    #[serde(default)]
    pub ec_point_formats: Vec<u8>,
    /// Тела расширений без собственной сборки: `"0x0029": "hex…"`.
    #[serde(default)]
    pub raw_extensions: BTreeMap<String, String>,
    /// QUIC-часть профиля: `ClientHello`, транспортные параметры и раскладка
    /// Initial-пакетов UDP-ноги. У пула профилей QUIC-блоки собираются отдельно
    /// (сессия берёт любой из них), не обязательно из того же профиля, что и TCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<Box<crate::quiceng::QuicSpec>>,
    /// Форма трафика: длины записей, снятые с браузера (см. `nrxp::shape`).
    /// Если у нескольких профилей файла есть `shape`, значения объединяются.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<ShapeSpec>,
    /// Произвольные сведения (источник, JA3/JA4, замечания) — движком не читаются.
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

/// Распределение длин TLS-записей `ApplicationData` после рукопожатия.
/// Значения — квантили наблюдений (сортированные), до 256 на направление.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShapeSpec {
    /// Клиент → сервер.
    #[serde(default)]
    pub up: Vec<u16>,
    /// Сервер → клиент.
    #[serde(default)]
    pub down: Vec<u16>,
}

impl ShapeSpec {
    pub fn lengths(&self) -> crate::nrxp::shape::ShapeLengths {
        crate::nrxp::shape::ShapeLengths { up: self.up.clone(), down: self.down.clone() }
    }
}

fn default_schema() -> u32 {
    SCHEMA_VERSION
}

/// Расширения, для которых у сборщика есть собственный код.
const NATIVE: &[u16] = &[
    TlsExtensions::SNI,
    TlsExtensions::STATUS_REQUEST,
    TlsExtensions::SUPPORTED_GROUPS,
    TlsExtensions::EC_POINT_FORMATS,
    TlsExtensions::SIGNATURE_ALGORITHMS,
    TlsExtensions::ALPN,
    TlsExtensions::SCT,
    TlsExtensions::PADDING,
    TlsExtensions::EMS,
    TlsExtensions::COMPRESS_CERT,
    TlsExtensions::DELEGATED_CREDENTIAL,
    TlsExtensions::SESSION_TICKET,
    TlsExtensions::SUPPORTED_VERSIONS,
    TlsExtensions::PSK_MODES,
    TlsExtensions::KEY_SHARE,
    TlsExtensions::ALPS,
    TlsExtensions::ECH,
    TlsExtensions::RENEGOTIATION_INFO,
];

const ALPS_ALT: u16 = 0x4469;

fn is_slot(id: u16) -> bool {
    id == TlsExtensions::GREASE_SLOT_FIRST || id == TlsExtensions::GREASE_SLOT_LAST
}

impl ProfileSpec {
    /// Разбирает одно описание из JSON (без проверки применимости).
    pub fn from_json(json: &str) -> Result<Self, ProfileError> {
        serde_json::from_str(json).map_err(|e| ProfileError::Json(e.to_string()))
    }

    /// JSON с отступами — удобно править руками.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// Пул профилей одним файлом (массив): сессии выбирают из него по хешу.
    pub fn pool_to_json(specs: &[ProfileSpec]) -> String {
        let mut s = serde_json::to_string_pretty(specs).unwrap_or_else(|_| "[]".into());
        s.push('\n');
        s
    }

    /// Нормализованный порядок расширений: оба кодпоинта ALPS → `ALPS`.
    fn normalized_order(&self) -> Vec<u16> {
        self.extension_order
            .iter()
            .map(|e| if e.0 == ALPS_ALT { TlsExtensions::ALPS } else { e.0 })
            .collect()
    }

    fn alps_codepoint_effective(&self) -> u16 {
        if let Some(c) = self.alps_codepoint {
            return c.0;
        }
        if self.extension_order.iter().any(|e| e.0 == ALPS_ALT) {
            ALPS_ALT
        } else {
            TlsExtensions::ALPS
        }
    }

    fn raw_parsed(&self) -> Result<Vec<(u16, Vec<u8>)>, String> {
        let mut out = Vec::new();
        for (k, v) in &self.raw_extensions {
            let id = parse_u16(k).ok_or_else(|| format!("raw_extensions: bad id {k:?}"))?;
            let v = v.trim();
            if v.len() % 2 != 0 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("raw_extensions[{k}]: expected an even-length hex string"));
            }
            let bytes: Vec<u8> = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap_or(0))
                .collect();
            if bytes.len() > 4096 {
                return Err(format!("raw_extensions[{k}]: body longer than 4096 bytes"));
            }
            out.push((id, bytes));
        }
        Ok(out)
    }

    /// Проверяет, что профиль работает с нашим протоколом. `Err` — причины
    /// отказа; `Ok` — список предупреждений (профиль применим, но не идеален).
    pub fn validate(&self) -> Result<Vec<String>, ProfileError> {
        self.validate_with_dynamic(&[])
    }

    /// То же, но расширения из `dynamic` считаются заполняемыми движком на
    /// соединение (как `quic_transport_parameters`), а не «без сборщика».
    pub(crate) fn validate_with_dynamic(&self, dynamic: &[u16]) -> Result<Vec<String>, ProfileError> {
        let mut err: Vec<String> = Vec::new();
        let mut warn: Vec<String> = Vec::new();
        let order = self.normalized_order();
        let has = |id: u16| order.contains(&id);
        let ids = |v: &[Hex16]| v.iter().map(|h| h.0).collect::<Vec<u16>>();
        let grease = |v: u16| (v & 0x0f0f) == 0x0a0a && (v & 0xff) == (v >> 8);

        if let Some(q) = &self.quic {
            match q.validate() {
                Ok(w) => warn.extend(w),
                Err(ProfileError::Invalid(v)) => err.extend(v),
                Err(e) => err.push(e.to_string()),
            }
        }
        if let Some(sh) = &self.shape {
            match crate::nrxp::shape::validate(&sh.lengths()) {
                Ok(w) => warn.extend(w),
                Err(e) => err.push(e),
            }
        }
        if self.schema != SCHEMA_VERSION {
            err.push(format!("schema {} is not supported (expected {SCHEMA_VERSION})", self.schema));
        }
        if self.name.is_empty() || self.name.len() > 64 {
            err.push("name must be 1..=64 characters".into());
        }
        if ProtocolVersion::try_from(self.record_layer_version.0).is_err() {
            err.push(format!(
                "record_layer_version {:#06x} must be 0x0301, 0x0303 or 0x0304",
                self.record_layer_version.0
            ));
        }
        for (what, len) in [
            ("cipher_suites", self.cipher_suites.len()),
            ("groups", self.groups.len()),
            ("signatures", self.signatures.len()),
            ("delegated_signatures", self.delegated_signatures.len()),
            ("versions", self.versions.len()),
            ("extension_order", self.extension_order.len()),
        ] {
            if len > 64 {
                err.push(format!("{what}: more than 64 entries"));
            }
        }
        let suites = ids(&self.cipher_suites);
        if !suites.iter().any(|c| *c == 0x1301 || *c == 0x1302) {
            err.push(
                "cipher_suites must contain 0x1301 or 0x1302 (the node picks an AES-GCM suite by default)"
                    .into(),
            );
        }
        if !suites.contains(&0x1303) {
            warn.push("no 0x1303: an explicit ChaCha20-Poly1305 preference will not work".into());
        }
        if suites.iter().any(|c| grease(*c)) {
            err.push("cipher_suites must not contain GREASE values (has_grease adds one)".into());
        }
        let groups = ids(&self.groups);
        if !groups.contains(&0x001d) {
            err.push("groups must contain 0x001d (x25519): the key exchange uses it".into());
        }
        if groups.iter().any(|g| grease(*g)) {
            err.push("groups must not contain GREASE values".into());
        }
        let versions = ids(&self.versions);
        if !versions.contains(&0x0304) {
            err.push("versions must contain 0x0304 (TLS 1.3)".into());
        }
        if versions.iter().any(|v| grease(*v)) {
            err.push("versions must not contain GREASE values".into());
        }
        for required in [
            ("key_share", TlsExtensions::KEY_SHARE),
            ("supported_groups", TlsExtensions::SUPPORTED_GROUPS),
            ("supported_versions", TlsExtensions::SUPPORTED_VERSIONS),
        ] {
            if !has(required.1) {
                err.push(format!("extension_order must contain {}", required.0));
            }
        }
        if !has(TlsExtensions::SNI) {
            warn.push("no server_name: ClientHello will carry no SNI".into());
        }
        if has(TlsExtensions::SIGNATURE_ALGORITHMS) && self.signatures.is_empty() {
            err.push("signature_algorithms is in extension_order but signatures is empty".into());
        }
        if has(TlsExtensions::ALPN) && self.alpn.is_empty() {
            err.push("alpn is in extension_order but the alpn list is empty".into());
        }
        if self.alpn.iter().chain(&self.alps_protocols).any(|p| p.is_empty() || p.len() > 255) {
            err.push("alpn/alps protocol names must be 1..=255 bytes".into());
        }
        if has(TlsExtensions::ALPS) && self.alps_protocols.is_empty() {
            warn.push("alps is in extension_order but alps_protocols is empty: it will be skipped".into());
        }
        let mut seen = std::collections::HashSet::new();
        for id in &order {
            if is_slot(*id) {
                continue;
            }
            if !seen.insert(*id) {
                err.push(format!("extension {id:#06x} appears twice in extension_order"));
            }
        }
        let slots = order.iter().filter(|i| is_slot(**i)).count();
        let grease_flag = self.has_grease.unwrap_or(slots > 0);
        if slots > 0 && !grease_flag {
            warn.push("grease slots in extension_order but has_grease=false: they will be skipped".into());
        }
        if grease_flag && slots == 0 {
            warn.push("has_grease=true without grease slots: GREASE only in ciphers/groups/versions".into());
        }
        if self.shuffle_extensions && order.len() < 4 {
            warn.push("shuffle_extensions needs at least 4 extensions".into());
        }
        if has(TlsExtensions::PADDING) && self.target_padding_len == 0 {
            warn.push("padding is in extension_order but target_padding_len is 0".into());
        }
        if self.target_padding_len > 16000 {
            err.push("target_padding_len is too large".into());
        }
        if self.ech_payload_lengths.iter().any(|l| !(16..=1024).contains(l)) {
            err.push("ech_payload_lengths entries must be 16..=1024".into());
        }
        if self.ech_payload_lengths.len() > 16 {
            err.push("ech_payload_lengths: more than 16 entries".into());
        }
        if self.psk_modes.len() > 8 || self.ec_point_formats.len() > 8 || self.compress_cert_algs.len() > 8 {
            err.push("psk_modes/ec_point_formats/compress_cert_algs: more than 8 entries".into());
        }
        match self.raw_parsed() {
            Err(e) => err.push(e),
            Ok(raw) => {
                for (id, _) in &raw {
                    if NATIVE.contains(id) {
                        warn.push(format!(
                            "raw_extensions[{id:#06x}] is ignored: the extension is built natively"
                        ));
                    } else if !order.contains(id) {
                        warn.push(format!("raw_extensions[{id:#06x}] is not in extension_order: unused"));
                    }
                }
                for id in &order {
                    if !is_slot(*id) && !NATIVE.contains(id) && !dynamic.contains(id) && !raw.iter().any(|(r, _)| r == id) {
                        warn.push(format!(
                            "extension {id:#06x} has no builder and no raw body: it will be omitted \
                             (JA3/JA4 will differ)"
                        ));
                    }
                }
            }
        }
        if err.is_empty() {
            Ok(warn)
        } else {
            Err(ProfileError::Invalid(err))
        }
    }

    /// Проверяет и строит рабочий профиль. Память намеренно не освобождается:
    /// профиль живёт весь процесс (как и встроенные `const`).
    pub(crate) fn into_profile(&self) -> Result<&'static BrowserProfile, ProfileError> {
        self.into_profile_with_dynamic(&[])
    }

    pub(crate) fn into_profile_with_dynamic(&self, dynamic: &[u16]) -> Result<&'static BrowserProfile, ProfileError> {
        self.validate_with_dynamic(dynamic)?;
        let leak_u16 = |v: Vec<u16>| -> &'static [u16] { Box::leak(v.into_boxed_slice()) };
        let leak_u8 = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
        let leak_strs = |v: &[String]| -> &'static [&'static str] {
            let items: Vec<&'static str> = v
                .iter()
                .map(|s| &*Box::leak(s.clone().into_boxed_str()))
                .collect();
            Box::leak(items.into_boxed_slice())
        };
        let ids = |v: &[Hex16]| v.iter().map(|h| h.0).collect::<Vec<u16>>();
        let order = self.normalized_order();
        let slots = order.iter().any(|i| is_slot(*i));
        let raw: Vec<(u16, &'static [u8])> = self
            .raw_parsed()
            .map_err(|e| ProfileError::Invalid(vec![e]))?
            .into_iter()
            .map(|(id, b)| (id, leak_u8(b)))
            .collect();
        let p = BrowserProfile {
            groups: TlsGroups(leak_u16(ids(&self.groups))),
            signatures: TlsSignatures(leak_u16(ids(&self.signatures))),
            delegated_signatures: TlsSignatures(leak_u16(ids(&self.delegated_signatures))),
            versions: TlsVersions(leak_u16(ids(&self.versions))),
            alpn: leak_strs(&self.alpn),
            extension_order: ExtensionOrder(leak_u16(order)),
            cipher_suites: leak_u16(ids(&self.cipher_suites)),
            record_layer_version: ProtocolVersion::try_from(self.record_layer_version.0)
                .map_err(|e| ProfileError::Invalid(vec![e.to_string()]))?,
            target_padding_len: self.target_padding_len,
            alps_protocols: leak_strs(&self.alps_protocols),
            has_grease: self.has_grease.unwrap_or(slots),
            shuffle_extensions: self.shuffle_extensions,
            ech_payload_lengths: leak_u16(self.ech_payload_lengths.clone()),
            compress_cert_algs: if self.compress_cert_algs.is_empty() {
                &[super::consts::CERT_COMPRESSION_BROTLI]
            } else {
                leak_u16(ids(&self.compress_cert_algs))
            },
            psk_modes: if self.psk_modes.is_empty() {
                &[super::consts::PSK_DHE_KE_MODE]
            } else {
                leak_u8(self.psk_modes.clone())
            },
            ec_point_formats: if self.ec_point_formats.is_empty() {
                &[0]
            } else {
                leak_u8(self.ec_point_formats.clone())
            },
            alps_codepoint: self.alps_codepoint_effective(),
            raw_extensions: Box::leak(raw.into_boxed_slice()),
        };
        Ok(Box::leak(Box::new(p)))
    }
}

/// Разбирает JSON с одним профилем либо массивом профилей.
pub fn parse_specs(json: &str) -> Result<Vec<ProfileSpec>, ProfileError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| ProfileError::Json(e.to_string()))?;
    match v {
        serde_json::Value::Array(items) => items
            .into_iter()
            .enumerate()
            .map(|(i, it)| {
                serde_json::from_value::<ProfileSpec>(it)
                    .map_err(|e| ProfileError::Json(format!("profile #{i}: {e}")))
            })
            .collect(),
        other => serde_json::from_value::<ProfileSpec>(other)
            .map(|p| vec![p])
            .map_err(|e| ProfileError::Json(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> &'static str {
        r#"{
          "name": "t",
          "record_layer_version": "0x0301",
          "cipher_suites": ["0x1301", 4866, "0x1303"],
          "groups": ["0x001d", "0x0017"],
          "signatures": ["0x0403"],
          "versions": ["0x0304"],
          "alpn": ["h2"],
          "extension_order": ["server_name", "supported_groups", "key_share",
                              "supported_versions", "signature_algorithms", "alpn"]
        }"#
    }

    #[test]
    fn minimal_profile_loads_with_defaults() {
        let s = ProfileSpec::from_json(minimal()).unwrap();
        let w = s.validate().unwrap();
        assert!(w.is_empty(), "{w:?}");
        let p = s.into_profile().unwrap();
        assert_eq!(p.cipher_suites, &[0x1301, 0x1302, 0x1303]);
        assert!(!p.has_grease);
        assert_eq!(p.compress_cert_algs, &[0x0002]);
        assert_eq!(p.psk_modes, &[1]);
        assert_eq!(p.alps_codepoint, 0x44cd);
        assert_eq!(p.ech_payload_lengths, &[] as &[u16]);
    }

    #[test]
    fn numbers_accept_decimal_hex_and_names() {
        let s = ProfileSpec::from_json(minimal()).unwrap();
        assert_eq!(s.cipher_suites[1], Hex16(0x1302));
        assert_eq!(s.extension_order[0], ExtId(TlsExtensions::SNI));
        let back = ProfileSpec::from_json(&s.to_json()).unwrap();
        assert_eq!(back.extension_order, s.extension_order);
        assert!(s.to_json().contains("\"server_name\""));
    }

    #[test]
    fn rejects_profiles_that_break_the_protocol() {
        let bad = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value = serde_json::from_str(minimal()).unwrap();
            edit(&mut v);
            let s: ProfileSpec = serde_json::from_value(v).unwrap();
            match s.validate() {
                Err(ProfileError::Invalid(e)) => e.join(" | "),
                other => panic!("expected rejection, got {other:?}"),
            }
        };
        assert!(bad(&|v| v["groups"] = serde_json::json!(["0x0017"])).contains("x25519"));
        assert!(bad(&|v| v["versions"] = serde_json::json!(["0x0303"])).contains("TLS 1.3"));
        assert!(bad(&|v| v["cipher_suites"] = serde_json::json!(["0x1303"])).contains("0x1301"));
        assert!(bad(&|v| v["extension_order"] = serde_json::json!(["server_name"])).contains("key_share"));
        assert!(bad(&|v| v["record_layer_version"] = serde_json::json!("0x0200")).contains("record_layer_version"));
        assert!(bad(&|v| v["schema"] = serde_json::json!(2)).contains("schema"));
        assert!(bad(&|v| {
            v["extension_order"] = serde_json::json!(["key_share", "key_share", "supported_groups", "supported_versions"])
        })
        .contains("twice"));
        assert!(bad(&|v| v["ech_payload_lengths"] = serde_json::json!([5])).contains("ech_payload_lengths"));
        assert!(bad(&|v| v["raw_extensions"] = serde_json::json!({"0x1234": "zz"})).contains("hex"));
    }

    #[test]
    fn unknown_fields_and_names_are_reported() {
        let e = ProfileSpec::from_json(&minimal().replace("\"name\"", "\"nmae\"")).unwrap_err();
        assert!(matches!(e, ProfileError::Json(_)));
        let e = ProfileSpec::from_json(&minimal().replace("server_name", "nonsense")).unwrap_err();
        assert!(e.to_string().contains("nonsense"));
    }

    #[test]
    fn alps_alt_codepoint_is_normalized() {
        let j = minimal().replace(
            "\"alpn\"]",
            "\"alpn\", \"0x4469\"], \"alps_protocols\": [\"h2\"]",
        );
        let p = ProfileSpec::from_json(&j).unwrap().into_profile().unwrap();
        assert_eq!(p.alps_codepoint, 0x4469);
        assert!(p.extension_order.0.contains(&TlsExtensions::ALPS));
    }

    #[test]
    fn raw_extension_bodies_and_arrays() {
        let j = minimal().replace(
            "\"alpn\"]",
            "\"alpn\", \"0x1234\"], \"raw_extensions\": {\"0x1234\": \"abcd01\"}",
        );
        let w = ProfileSpec::from_json(&j).unwrap().validate().unwrap();
        assert!(w.is_empty(), "{w:?}");
        let p = ProfileSpec::from_json(&j).unwrap().into_profile().unwrap();
        assert_eq!(p.raw_extensions, &[(0x1234u16, &[0xab, 0xcd, 0x01][..])]);
        // массив профилей
        let arr = format!("[{0},{0}]", minimal());
        assert_eq!(parse_specs(&arr).unwrap().len(), 2);
    }

    /// Поставляемые в `profiles/` примеры обязаны оставаться рабочими: проходят
    /// проверку, а собранный по ним `ClientHello` принимает настоящий серверный
    /// разбор (тег, ключи, выбор шифра).
    #[test]
    fn shipped_example_profiles_are_accepted_by_the_server_side() {
        use crate::crypto::SessionKeys;
        use crate::nrxp::TlsBridge;
        use crate::tlseng::{ClientHello, ServerProfile};
        for (name, json) in [
            ("chrome_148", include_str!("../../../profiles/chrome_148.json")),
            ("minimal_example", include_str!("../../../profiles/minimal_example.json")),
        ] {
            let spec = ProfileSpec::from_json(json).unwrap();
            assert_eq!(spec.name, name);
            assert!(spec.validate().unwrap().is_empty(), "{name}");
            let profile = spec.into_profile().unwrap();
            for _ in 0..8 {
                let client = SessionKeys::new(true);
                let wire = ClientHello::make_client_hello(profile, "www.debian.org", &client);
                let mut buf = bytes::BytesMut::from(&wire[..]);
                let msg = TlsBridge::unpack_handshake(&mut buf).unwrap().unwrap();
                let mut server = SessionKeys::new(false);
                TlsBridge::wrap_server_hello(&msg, &mut server, &ServerProfile::MODERN)
                    .unwrap_or_else(|e| panic!("{name}: server rejected hello: {:?}", e.stage));
            }
        }
    }
}
