use crate::tlseng::{
    params::TlsVersions,
    profile::{
        groups::{
            chrome_groups::{
                CHROME_ALPN_PROTOCOLS, CHROME_DELEGATED_ALGS, CHROME_GROUPS, CHROME_SIGNATURES,
                CHROMIUM_EXT_ORDER,
            },
            edge_groups::{
                EDGE_ALPN_PROTOCOLS, EDGE_DELEGATED_ALGS, EDGE_EXT_ORDER, EDGE_GROUPS,
                EDGE_SIGNATURES,
            },
            shared::MODERN_VERSIONS,
        },
        profile::BrowserProfile,
    },
};

// --- Versions ---
pub const TLS_13_ONLY: TlsVersions = TlsVersions(&[0x0304]);

// --- CHROME 131 PROFILE ---
pub const CHROME_131: BrowserProfile = BrowserProfile {
    name: "Chrome 131 (Windows)",
    groups: CHROME_GROUPS,
    signatures: CHROME_SIGNATURES,
    alpn: CHROME_ALPN_PROTOCOLS,
    delegated_signatures: CHROME_DELEGATED_ALGS,
    versions: TLS_13_ONLY,
    extension_order: CHROMIUM_EXT_ORDER,
    is_chromium: true,
};

// --- FIREFOX 133 PROFILE (Example) ---
// Note: Firefox uses different groups and no ALPS
pub const EDGE_PROFILE: BrowserProfile = BrowserProfile {
    name: "Edge",
    groups: EDGE_GROUPS,
    signatures: EDGE_SIGNATURES, // Usually identical to Chrome
    alpn: EDGE_ALPN_PROTOCOLS,
    delegated_signatures: EDGE_DELEGATED_ALGS,
    versions: MODERN_VERSIONS,
    extension_order: EDGE_EXT_ORDER,
    is_chromium: true,
};
