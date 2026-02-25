// --- Core Handshake Identifiers ---
/// ClientHello handshake message type
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

// --- TLS Extension Type Codes (IANA) ---
/// Server Name Indication (SNI) - maps a hostname to the IP
pub const EXT_TYPE_SNI: u16 = 0x0000;
/// Certificate Status Request (OCSP Stapling)
pub const EXT_STATUS_REQUEST: u16 = 0x0005;
/// Supported Elliptic Curves (Named Groups)
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// Supported Point Formats (Legacy, but required for compatibility)
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
/// Signature Algorithms the client can verify
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// Application-Layer Protocol Negotiation (h2, http/1.1)
pub const EXT_ALPN: u16 = 0x0010;
/// Signed Certificate Timestamp (SCT) - used for Certificate Transparency
pub const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
/// Padding extension to avoid MTU issues or fingerprinting
pub const EXT_PADDING: u16 = 0x0015;
/// Extended Master Secret - prevents MITM key synchronization attacks
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// Certificate Compression (Used by modern browsers like Chrome)
pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
/// Delegated Credentials (RFC 9345)
pub const EXT_DELEGATED_CREDENTIAL: u16 = 0x0022;
///SESSION TICKET
pub const EXT_SESSION_TICKET: u16 = 0x0023;
/// Negotiated TLS Versions (Crucial for TLS 1.3)
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// Pre-Shared Key (PSK) Exchange Modes
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// Key Share - carries the Diffie-Hellman public keys
pub const EXT_KEY_SHARE: u16 = 0x0033;
/// Application Settings (ALPS) - Chrome specific protocol settings
pub const EXT_ALPS: u16 = 0x44cd;

// --- Compatibility & Anti-Detection (Fingerprinting) ---
/// Secure Renegotiation Indication (RFC 5746)
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// GREASE (Generate Random Extensions And Sustain Extensibility)
/// Used to prevent server bugs where unknown extensions cause failures.
pub const GREASE_IDENTIFIERS: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];
