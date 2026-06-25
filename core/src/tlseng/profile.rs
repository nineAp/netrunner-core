use crate::tlseng::types::{
    ExtensionOrder, ProtocolVersion, TlsGroups, TlsSignatures, TlsVersions,
};
pub(crate) struct BrowserProfile {
    pub groups: TlsGroups,
    pub signatures: TlsSignatures,
    pub delegated_signatures: TlsSignatures,
    pub versions: TlsVersions,
    pub alpn: &'static [&'static str],
    pub extension_order: ExtensionOrder,
    pub cipher_suites: &'static [u16],
    pub record_layer_version: ProtocolVersion,
    pub target_padding_len: u16,
    pub alps_protocols: &'static [&'static str],
    pub has_grease: bool,
}

impl BrowserProfile {
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

pub(crate) struct ServerProfile {
    pub versions: TlsVersions,
    pub record_layer_version: ProtocolVersion,
    pub cipher_suites: &'static [u16],
    pub _groups: TlsGroups,
    pub _signatures: TlsSignatures,
    pub _alpn: &'static [&'static str],
    pub _session_tickets: bool,
    pub honor_cipher_order: bool,
}

impl ServerProfile {
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
