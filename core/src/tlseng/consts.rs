/// Handshake message types
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// SNI (Server Name Indication) specific
pub const TYPE_HOST_NAME: u8 = 0x00;

/// PSK (Pre-Shared Key) modes
pub const PSK_DHE_KE_MODE: u8 = 0x01;

/// Certificate compression algorithms
pub const CERT_COMPRESSION_BROTLI: u16 = 0x0002;

/// Extension internal status types
pub const OCSP_STATUS_TYPE: u8 = 0x01;
//pub const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0x00;

/// GREASE (Generate Random Extensions And Sustain Extensibility)
/// Используется для предотвращения ошибок серверов при встрече с неизвестными ID.
pub const GREASE_IDENTIFIERS: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];
