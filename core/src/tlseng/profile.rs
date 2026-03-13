use crate::tlseng::types::{ExtensionOrder, TlsGroups, TlsSignatures, TlsVersions};

pub struct BrowserProfile {
    pub name: &'static str,

    pub groups: TlsGroups,

    pub signatures: TlsSignatures,

    pub delegated_signatures: TlsSignatures,

    pub versions: TlsVersions,

    pub alpn: &'static [&'static str],

    pub extension_order: ExtensionOrder,

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
        groups: TlsGroups::CHROMIUM,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,
        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::EDGE_130,
        is_chromium: true,
    };

    pub const DEFAULT: Self = Self::CHROME_131;
}

pub struct ServerProfile {
    pub name: &'static str,

    pub versions: TlsVersions,

    pub cipher_suites: &'static [u16],

    pub groups: TlsGroups,

    pub signatures: TlsSignatures,

    pub alpn: &'static [&'static str],

    pub session_tickets: bool,

    pub honor_cipher_order: bool,
}

impl ServerProfile {
    pub const MODERN: Self = Self {
        name: "Modern-Secure",
        versions: TlsVersions::MODERN,
        cipher_suites: &[0x1301, 0x1302, 0x1303],
        groups: TlsGroups::MODERN,
        signatures: TlsSignatures::BROWSER_STANDARD,
        alpn: &["h2", "http/1.1"],
        session_tickets: true,
        honor_cipher_order: true,
    };
}
