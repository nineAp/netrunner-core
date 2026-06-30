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

    /// Отпечаток Firefox 130: без GREASE и ALPS, без паддинга, TLS 1.3+1.2.
    /// Заготовка-альтернатива Chrome (сейчас в бою используется Chrome).
    #[allow(dead_code)]
    pub const FIREFOX_130: Self = Self {
        groups: TlsGroups::MODERN,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::EDGE_130,

        has_grease: false,
        alps_protocols: &[],
        target_padding_len: 0,
    };
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
}
