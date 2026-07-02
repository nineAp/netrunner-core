//! Профили отпечатков: «рецепты» того, как должен выглядеть наш TLS.
//!
//! [`BrowserProfile`] описывает клиентский отпечаток (что и в каком порядке класть
//! в `ClientHello`, чтобы JA3/JA4 совпал с реальным браузером), а [`ServerProfile`] —
//! как отвечать на стороне сервера. Профили — это `const`-значения без аллокаций;
//! все списки ссылаются на статические срезы из [`types`](super::types).
//!
//! Менять поля профиля = менять отпечаток. Значения скопированы из реальных
//! захватов трафика соответствующих браузеров.

use crate::tlseng::types::{
    ExtensionOrder, ProtocolVersion, TlsGroups, TlsSignatures, TlsVersions,
};

/// Клиентский отпечаток конкретного браузера.
pub(crate) struct BrowserProfile {
    /// ECDH-группы (`supported_groups`).
    pub groups: TlsGroups,
    /// Алгоритмы подписи (`signature_algorithms`).
    pub signatures: TlsSignatures,
    /// Подписи для `delegated_credentials`.
    pub delegated_signatures: TlsSignatures,
    /// Рекламируемые версии TLS (`supported_versions`).
    pub versions: TlsVersions,
    /// Протоколы ALPN (например `h2`, `http/1.1`).
    pub alpn: &'static [&'static str],
    /// Точный порядок расширений — определяющий фактор JA3/JA4.
    pub extension_order: ExtensionOrder,
    /// Список cipher-suites (значения и порядок — часть отпечатка).
    pub cipher_suites: &'static [u16],
    /// Версия в заголовке TLS-записи (у Chrome — TLS 1.0, как в реальности).
    pub record_layer_version: ProtocolVersion,
    /// До какого размера добивать `ClientHello` паддингом (0 = без паддинга).
    pub target_padding_len: u16,
    /// Протоколы ALPS (`application_settings`) — поведение только Chromium.
    pub alps_protocols: &'static [&'static str],
    /// Вставлять ли GREASE-значения (обязательно для Chromium).
    pub has_grease: bool,
}

impl BrowserProfile {
    /// Отпечаток Chrome 131: GREASE + ALPS, паддинг до 512, только TLS 1.3,
    /// версия записи маскируется под TLS 1.0 — как у настоящего Chrome.
    pub const CHROME_131: Self = Self {
        groups: TlsGroups::CHROMIUM,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::TLS_13_ONLY,

        record_layer_version: ProtocolVersion::Tls10,

        cipher_suites: &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::CHROMIUM_131,

        has_grease: true,

        alps_protocols: &["h2"],

        target_padding_len: 512,
    };

    /// Отпечаток Firefox 133: без GREASE и ALPS (их у Firefox не бывает), без
    /// паддинга, TLS 1.3+1.2. Раньше по ошибке ссылался на `ExtensionOrder::EDGE_130`
    /// (Chromium-порядок с ALPS/compress_certificate) — теперь у него свой порядок
    /// ([`FIREFOX_133`](ExtensionOrder::FIREFOX_133)) и своя группа `secp521r1`.
    pub const FIREFOX_130: Self = Self {
        groups: TlsGroups::FIREFOX,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::FIREFOX_133,

        has_grease: false,
        alps_protocols: &[],
        target_padding_len: 0,
    };

    /// Отпечаток Edge 130: тот же Chromium-движок, что и Chrome (GREASE + ALPS +
    /// паддинг до 512), отличается только собственными GREASE-значениями
    /// (`0x1a1a`/`0x3a3a`), как у настоящего Edge.
    pub const EDGE_130: Self = Self {
        groups: TlsGroups::CHROMIUM,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::TLS_13_ONLY,

        record_layer_version: ProtocolVersion::Tls10,

        cipher_suites: &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::EDGE_130,

        has_grease: true,

        alps_protocols: &["h2"],

        target_padding_len: 512,
    };

    /// Отпечаток Safari 17: не Chromium — без GREASE, без ALPS, TLS 1.3+1.2,
    /// без паддинга.
    pub const SAFARI_17: Self = Self {
        groups: TlsGroups::SAFARI,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[
            0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8,
        ],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::SAFARI_17,

        has_grease: false,
        alps_protocols: &[],
        target_padding_len: 0,
    };

    /// Пул профилей для fallback-ротации: если нога не смогла установиться
    /// ([`ClientHandler::establish_leg`](crate::net::connection::ClientHandler::establish_leg)
    /// повторяет попытки), очередной реконнект берёт следующий профиль отсюда
    /// вместо того, чтобы вечно долбить DPI одним и тем же Chrome-отпечатком.
    pub const ALL: &'static [&'static Self] = &[
        &Self::CHROME_131,
        &Self::EDGE_130,
        &Self::FIREFOX_130,
        &Self::SAFARI_17,
    ];

    /// Выбирает профиль по номеру попытки переподключения (`0` = первый профиль
    /// из [`ALL`](Self::ALL), и так по кругу). Чистая функция без состояния —
    /// вызывающий сам хранит счётчик попыток на ногу.
    pub fn for_attempt(attempt: u32) -> &'static Self {
        Self::ALL[attempt as usize % Self::ALL.len()]
    }
}

/// Серверный профиль ответа. Поля с префиксом `_` зарезервированы под будущее
/// расширение `ServerHello` и сейчас в сборке не участвуют.
pub(crate) struct ServerProfile {
    /// Версии для `supported_versions` в ответе.
    pub versions: TlsVersions,
    /// Версия заголовка TLS-записи ответа.
    pub record_layer_version: ProtocolVersion,
    /// Cipher-suites, среди которых выбирается один итоговый.
    pub cipher_suites: &'static [u16],
    pub _groups: TlsGroups,
    pub _signatures: TlsSignatures,
    pub _alpn: &'static [&'static str],
    pub _session_tickets: bool,
    /// `true` — приоритет у порядка сервера при выборе cipher-suite, иначе клиента.
    pub honor_cipher_order: bool,
}

impl ServerProfile {
    /// Современный серверный профиль: TLS 1.3/1.2, выбор suite по порядку сервера.
    pub const MODERN: Self = Self {
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303],
        _groups: TlsGroups::MODERN,
        _signatures: TlsSignatures::BROWSER_STANDARD,
        _alpn: &["h2", "http/1.1"],
        _session_tickets: true,
        honor_cipher_order: true,
    };

    /// Совместимый профиль: те же suite'ы плюс CBC-варианты — на случай, если
    /// понадобится отвечать клиентам/зондам, которые в своём (настоящем, не
    /// нашем) `ClientHello` не предлагают ни одного suite из [`MODERN`](Self::MODERN).
    /// Сейчас не используется по умолчанию (`ServerHandler` берёт `MODERN`),
    /// заготовлен как второй вариант — так же, как раньше `FIREFOX_130` был
    /// заготовкой без пути включения.
    pub const COMPAT: Self = Self {
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],
        _groups: TlsGroups::MODERN,
        _signatures: TlsSignatures::BROWSER_STANDARD,
        _alpn: &["h2", "http/1.1"],
        _session_tickets: true,
        honor_cipher_order: true,
    };
}
