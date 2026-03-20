use crate::tlseng::types::{
    ExtensionOrder, ProtocolVersion, TlsGroups, TlsSignatures, TlsVersions,
};
pub struct BrowserProfile {
    pub name: &'static str,
    pub groups: TlsGroups,
    pub signatures: TlsSignatures,
    pub delegated_signatures: TlsSignatures,
    pub versions: TlsVersions,
    pub alpn: &'static [&'static str],
    pub extension_order: ExtensionOrder,
    pub is_chromium: bool,
    pub cipher_suites: &'static [u16],
    pub record_layer_version: ProtocolVersion,
    pub target_padding_len: u16,
    pub alps_protocols: &'static [&'static str],
    pub has_grease: bool,
}

impl BrowserProfile {
    pub const CHROME_131: Self = Self {
        name: "Chrome 131 (Windows)",
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

        is_chromium: true,
        has_grease: true,

        alps_protocols: &["h2"],

        target_padding_len: 512,
    };

    pub const FIREFOX_130: Self = Self {
        name: "Firefox 130 (Windows)",
        groups: TlsGroups::MODERN,
        signatures: TlsSignatures::BROWSER_STANDARD,
        delegated_signatures: TlsSignatures::BROWSER_STANDARD,
        versions: TlsVersions::MODERN,

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],

        alpn: &["h2", "http/1.1"],
        extension_order: ExtensionOrder::EDGE_130,

        is_chromium: false,
        has_grease: false,
        alps_protocols: &[],
        target_padding_len: 0,
    };
}

pub struct ServerProfile {
    pub name: &'static str,
    pub versions: TlsVersions,

    pub record_layer_version: ProtocolVersion,

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

        record_layer_version: ProtocolVersion::Tls12,

        cipher_suites: &[0x1301, 0x1302, 0x1303],
        groups: TlsGroups::MODERN,
        signatures: TlsSignatures::BROWSER_STANDARD,
        alpn: &["h2", "http/1.1"],
        session_tickets: true,
        honor_cipher_order: true,
    };
}
