use crate::tlseng::types::{ExtensionOrder, TlsGroups, TlsSignatures, TlsVersions};

/// Represents a complete TLS fingerprint profile for a specific browser.
///
/// This struct contains all the necessary information to generate a TLS
/// fingerprint for a specific browser, including the groups, signatures,
/// delegated signatures, versions, ALPN, and extension order.
pub struct BrowserProfile {
    /// The name of the browser profile.
    pub name: &'static str,

    /// The groups supported by the browser.
    pub groups: TlsGroups,

    /// The signatures supported by the browser.
    pub signatures: TlsSignatures,

    /// The delegated signatures supported by the browser.
    pub delegated_signatures: TlsSignatures,

    /// The versions of TLS supported by the browser.
    pub versions: TlsVersions,

    /// The ALPN protocols supported by the browser.
    pub alpn: &'static [&'static str],

    /// The specific order of Extension IDs (e.g., [0x0000, 0x0017, ...])
    pub extension_order: ExtensionOrder,

    /// Whether the browser is based on Chromium.
    pub is_chromium: bool,
}

impl BrowserProfile {
    pub const CHROME_131: Self = Self {
        name: "Chrome 131 (Windows)",
        groups: TlsGroups::CHROMIUM,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::TLS_13_ONLY,
        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::CHROMIUM_131,
        is_chromium: true,
    };

    pub const EDGE: Self = Self {
        name: "Edge",
        groups: TlsGroups::CHROMIUM, // Edge использует тот же набор, что и Chrome
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,
        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::EDGE_130,
        is_chromium: true,
    };

    pub const DEFAULT: Self = Self::CHROME_131;
}
/// Represents a TLS configuration profile for the server side.
pub struct ServerProfile {
    /// Имя профиля (например, "Modern-TLS-1.3-Only" или "Compatible-Nginx-Style")
    pub name: &'static str,

    /// Поддерживаемые версии TLS. Сервер выберет высшую общую с клиентом.
    pub versions: TlsVersions,

    /// Приоритетный список шифров (Cipher Suites).
    /// В TLS 1.3 это обычно [0x1301, 0x1302, 0x1303].
    pub cipher_suites: &'static [u16],

    /// Группы для обмена ключами (Key Exchange Groups).
    pub groups: TlsGroups,

    /// Поддерживаемые алгоритмы подписи для аутентификации сервера.
    pub signatures: TlsSignatures,

    /// Протоколы ALPN, которые сервер готов подтвердить (h2, http/1.1).
    pub alpn: &'static [&'static str],

    /// Настройки сессий
    pub session_tickets: bool,

    /// Нужно ли форсировать порядок шифров сервера (Server Preference),
    /// игнорируя порядок предпочтений клиента.
    pub honor_cipher_order: bool,
}

impl ServerProfile {
    pub const MODERN: Self = Self {
        name: "Modern-Secure",
        versions: TlsVersions::MODERN, // Допустим, у тебя есть такой хелпер
        cipher_suites: &[
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
        ],
        groups: TlsGroups::MODERN, // X25519, P-256
        signatures: TlsSignatures::BROWSER_STANDARD,
        alpn: &["h2", "http/1.1"],
        session_tickets: true,
        honor_cipher_order: true,
    };
}
