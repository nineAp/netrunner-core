use crate::tlseng::params::{TlsGroups, TlsSignatures, TlsVersions};

/// Represents a complete TLS fingerprint profile for a specific browser.
pub struct BrowserProfile {
    pub name: &'static str,
    pub groups: TlsGroups,
    pub signatures: TlsSignatures,
    pub delegated_signatures: TlsSignatures,
    pub versions: TlsVersions,
    pub alpn: &'static [&'static str],
    /// The specific order of Extension IDs (e.g., [0x0000, 0x0017, ...])
    pub extension_order: &'static [u16],
    pub is_chromium: bool,
}
