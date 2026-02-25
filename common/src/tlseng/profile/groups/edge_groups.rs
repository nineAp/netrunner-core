use crate::tlseng::consts::*;
use crate::tlseng::params::{TlsGroups, TlsSignatures};
use crate::tlseng::values::{
    GROUP_SECP256R1, GROUP_SECP384R1, GROUP_X25519, SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384, SIG_RSA_PKCS1_SHA256, SIG_RSA_PKCS1_SHA384, SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512,
};

// --- MICROSOFT EDGE ---
// Edge often mirrors Chrome exactly but sometimes removes specific
// experimental GREASE values or adds Windows-specific signature prefs.
pub const EDGE_GROUPS: TlsGroups = TlsGroups(&[
    0x0a0a, // GREASE
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
]);

pub const EDGE_SIGNATURES: TlsSignatures = TlsSignatures(&[
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA512,
]);

pub const EDGE_DELEGATED_ALGS: TlsSignatures = TlsSignatures(&[
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
]);

pub const EDGE_ALPN_PROTOCOLS: &[&str] = &["h2", "http/1.1"];

// Microsoft Edge Extension Order (Chromium v130+)
pub const EDGE_EXT_ORDER: &[u16] = &[
    0x1a1a,                     // GREASE
    EXT_TYPE_SNI,               // 0x0000
    EXT_EXTENDED_MASTER_SECRET, // 0x0017
    EXT_SESSION_TICKET,         // 0x0023
    EXT_SUPPORTED_GROUPS,       // 0x000a
    EXT_EC_POINT_FORMATS,       // 0x000b
    EXT_SIGNATURE_ALGORITHMS,   // 0x000d
    EXT_ALPN,                   // 0x0010
    EXT_ALPS,                   // 0x44cd
    EXT_STATUS_REQUEST,         // 0x0005
    EXT_KEY_SHARE,              // 0x0033
    EXT_SUPPORTED_VERSIONS,     // 0x002b
    EXT_PSK_KEY_EXCHANGE_MODES, // 0x002d
    EXT_COMPRESS_CERTIFICATE,   // 0x001b
    EXT_SIGNED_CERT_TIMESTAMP,  // 0x0012
    EXT_DELEGATED_CREDENTIAL,   // 0x0022
    EXT_PADDING,                // 0x0015
    0x3a3a,                     // GREASE
];
