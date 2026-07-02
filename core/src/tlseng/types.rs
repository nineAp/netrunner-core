//! Wire-константы и типы TLS, нужные для маскировки.
//!
//! Все числовые значения здесь — части формата TLS «на проводе» (RFC 8446 и
//! реестр IANA tls-extensiontype-values). Менять их нельзя: от точного совпадения
//! зависит JA3/JA4-отпечаток. Группировка по смыслу:
//! - базовый каркас записи/хендшейка: [`ContentType`], [`ProtocolVersion`], [`HelloType`];
//! - наборы для отпечатка: [`TlsGroups`], [`TlsSignatures`], [`TlsVersions`],
//!   [`TlsExtensions`], [`ExtensionOrder`].

/// Тип TLS-записи (первый байт на проводе). Мы используем три из них:
/// `Handshake` для hello-сообщений, `ApplicationData` для кадров NRXP,
/// `Alert` распознаём для совместимости.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentType {
    Handshake = 0x16,

    ApplicationData = 0x17,

    Alert = 0x15,
}

impl TryFrom<u8> for ContentType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x16 => Ok(ContentType::Handshake),
            0x17 => Ok(ContentType::ApplicationData),
            0x15 => Ok(ContentType::Alert),
            _ => Err("This is not ContentType"),
        }
    }
}

/// Версия TLS на проводе. Заметьте «маскировочный» нюанс: реальный TLS 1.3
/// притворяется 1.2 в поле версии записи (`0x0303`), а настоящая версия едет в
/// расширении `supported_versions` — ровно как делают браузеры.
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
pub(crate) enum ProtocolVersion {
    Tls10 = 0x0301,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0301 => Ok(ProtocolVersion::Tls10),

            0x0303 => Ok(ProtocolVersion::Tls12),

            0x0304 => Ok(ProtocolVersion::Tls13),
            _ => Err("This is not Protocol Version"),
        }
    }
}

/// Тип handshake-сообщения: `ClientHello` (`0x01`) или `ServerHello` (`0x02`) —
/// первый байт тела `Handshake`-записи.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum HelloType {
    Client = 0x01,

    Server = 0x02,
}

impl TryFrom<u8> for HelloType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(HelloType::Client),
            0x02 => Ok(HelloType::Server),
            _ => Err("This is not Hello header"),
        }
    }
}

/// Поддерживаемые ECDH-группы (расширение `supported_groups`). Обёртка над
/// статическим срезом, чтобы профили могли ссылаться на готовые наборы
/// ([`CHROMIUM`](TlsGroups::CHROMIUM)/[`MODERN`](TlsGroups::MODERN)) без аллокаций.
/// На практике обмен идёт по `X25519` — остальные перечислены для правдоподобия.
#[derive(Clone, Copy)]
pub(crate) struct TlsGroups(pub &'static [u16]);

impl TlsGroups {
    pub const X25519: u16 = 0x001d;
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    pub const SECP521R1: u16 = 0x0019;

    pub const CHROMIUM: Self = Self(&[Self::X25519, Self::SECP256R1, Self::SECP384R1]);

    pub const MODERN: Self = Self(&[Self::X25519, Self::SECP256R1]);

    /// Firefox рекламирует более широкий список групп, включая `secp521r1`.
    pub const FIREFOX: Self = Self(&[
        Self::X25519,
        Self::SECP256R1,
        Self::SECP384R1,
        Self::SECP521R1,
    ]);

    /// Safari — тот же набор, что и Chromium.
    pub const SAFARI: Self = Self(&[Self::X25519, Self::SECP256R1, Self::SECP384R1]);
}

/// Алгоритмы подписи (`signature_algorithms`). Для нас это «декорация» отпечатка:
/// сертификаты мы не проверяем, но список и его порядок должны совпадать с
/// браузером ([`BROWSER_STANDARD`](TlsSignatures::BROWSER_STANDARD)).
#[derive(Clone, Copy)]
pub(crate) struct TlsSignatures(pub &'static [u16]);

impl TlsSignatures {
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;

    pub const BROWSER_STANDARD: Self = Self(&[
        Self::ECDSA_SECP256R1_SHA256,
        Self::RSA_PSS_RSAE_SHA256,
        Self::RSA_PKCS1_SHA256,
        Self::ECDSA_SECP384R1_SHA384,
        Self::RSA_PSS_RSAE_SHA384,
        Self::RSA_PKCS1_SHA384,
        Self::RSA_PSS_RSAE_SHA512,
    ]);
}

/// Версии для расширения `supported_versions`. Профиль решает, рекламировать
/// только 1.3 ([`TLS_13_ONLY`](TlsVersions::TLS_13_ONLY), как Chrome) или 1.3+1.2
/// ([`MODERN`](TlsVersions::MODERN), как Firefox).
#[derive(Clone, Copy)]
pub struct TlsVersions(pub &'static [u16]);

impl TlsVersions {
    pub const TLS_1_3: u16 = 0x0304;
    pub const TLS_1_2: u16 = 0x0303;

    pub const TLS_13_ONLY: Self = Self(&[Self::TLS_1_3]);
    pub const MODERN: Self = Self(&[Self::TLS_1_3, Self::TLS_1_2]);

    /// Наибольшая версия из набора — кладётся в основное поле версии хендшейка.
    pub fn max(&self) -> ProtocolVersion {
        if self.0.contains(&Self::TLS_1_3) {
            ProtocolVersion::Tls13
        } else if self.0.contains(&Self::TLS_1_2) {
            ProtocolVersion::Tls12
        } else {
            ProtocolVersion::Tls10
        }
    }
}

/// Идентификаторы TLS-расширений (реестр IANA) + детектор GREASE.
///
/// Используются как ключи при сборке/поиске расширений в [`extension`](super::extension).
pub struct TlsExtensions;

impl TlsExtensions {
    pub const SNI: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SCT: u16 = 0x0012;
    pub const PADDING: u16 = 0x0015;
    pub const EMS: u16 = 0x0017;
    pub const COMPRESS_CERT: u16 = 0x001b;
    pub const DELEGATED_CREDENTIAL: u16 = 0x0022;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const PSK_MODES: u16 = 0x002d;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const ALPS: u16 = 0x44cd;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;

    /// Является ли id GREASE-значением (RFC 8701).
    ///
    /// GREASE-значения имеют вид `0x?a?a`, где оба байта равны (например `0x0a0a`,
    /// `0x1a1a`). Браузеры на базе Chromium вставляют их, чтобы серверы не «костенели»
    /// на конкретных значениях; для нас они — обязательная часть Chromium-отпечатка.
    pub fn is_grease(id: u16) -> bool {
        if (id & 0x0f0f) != 0x0a0a {
            return false;
        }

        (id & 0xff) == (id >> 8)
    }
}

/// Точный порядок расширений в `ClientHello` — определяющий фактор JA3/JA4.
///
/// Хранится как статический срез id и перебирается [`ExtensionBuilder`] при
/// сборке. Константы ниже скопированы из реальных захватов соответствующих
/// браузеров; первые/последние элементы — GREASE-значения.
#[derive(Clone, Copy)]
pub struct ExtensionOrder(pub &'static [u16]);

impl<'a> IntoIterator for &'a ExtensionOrder {
    type Item = &'a u16;
    type IntoIter = std::slice::Iter<'a, u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl ExtensionOrder {
    /// `PADDING` — обязательно последним: у реального Chrome паддинг всегда
    /// замыкает список расширений (раньше он был пропущен в этом списке, из-за
    /// чего `BrowserProfile::CHROME_131.target_padding_len` никогда не
    /// применялся — `ExtensionBuilder::apply_profile` вызывает
    /// [`padding`](super::extension::ExtensionBuilder::padding) только для id,
    /// присутствующего в порядке, а его тут не было).
    pub const CHROMIUM_131: Self = Self(&[
        0xaaaa,
        TlsExtensions::SNI,
        TlsExtensions::EMS,
        TlsExtensions::SESSION_TICKET,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::EC_POINT_FORMATS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::ALPN,
        TlsExtensions::ALPS,
        TlsExtensions::STATUS_REQUEST,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::PSK_MODES,
        TlsExtensions::COMPRESS_CERT,
        TlsExtensions::SCT,
        TlsExtensions::DELEGATED_CREDENTIAL,
        TlsExtensions::PADDING,
    ]);

    /// Edge — тот же Chromium-движок, порядок идентичен Chrome с поправкой на
    /// собственные GREASE-значения (`0x1a1a`/`0x3a3a` вместо `0xaaaa`).
    pub const EDGE_130: Self = Self(&[
        0x1a1a,
        TlsExtensions::SNI,
        TlsExtensions::EMS,
        TlsExtensions::SESSION_TICKET,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::EC_POINT_FORMATS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::ALPN,
        TlsExtensions::ALPS,
        TlsExtensions::STATUS_REQUEST,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::PSK_MODES,
        TlsExtensions::COMPRESS_CERT,
        TlsExtensions::SCT,
        TlsExtensions::DELEGATED_CREDENTIAL,
        TlsExtensions::PADDING,
        0x3a3a,
    ]);

    /// Firefox: своя собственная последовательность (не Chromium-семейство) —
    /// без GREASE, без ALPS/`compress_certificate`, `renegotiation_info` рано в
    /// списке. Раньше эта роль по ошибке была отдана `EDGE_130` (Chromium-порядок
    /// с ALPS/compress_certificate, которых у Firefox не существует в принципе).
    pub const FIREFOX_133: Self = Self(&[
        TlsExtensions::SNI,
        TlsExtensions::EMS,
        TlsExtensions::RENEGOTIATION_INFO,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::EC_POINT_FORMATS,
        TlsExtensions::SESSION_TICKET,
        TlsExtensions::ALPN,
        TlsExtensions::STATUS_REQUEST,
        TlsExtensions::DELEGATED_CREDENTIAL,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::PSK_MODES,
    ]);

    /// Safari: не Chromium-семейство — без GREASE и без ALPS.
    pub const SAFARI_17: Self = Self(&[
        TlsExtensions::SNI,
        TlsExtensions::EMS,
        TlsExtensions::RENEGOTIATION_INFO,
        TlsExtensions::SUPPORTED_GROUPS,
        TlsExtensions::EC_POINT_FORMATS,
        TlsExtensions::ALPN,
        TlsExtensions::STATUS_REQUEST,
        TlsExtensions::SIGNATURE_ALGORITHMS,
        TlsExtensions::SCT,
        TlsExtensions::KEY_SHARE,
        TlsExtensions::PSK_MODES,
        TlsExtensions::SUPPORTED_VERSIONS,
        TlsExtensions::COMPRESS_CERT,
    ]);
}
