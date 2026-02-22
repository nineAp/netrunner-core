pub const TYPE_HOST_NAME: u8 = 0x00;

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;

// Signature Algorithms (Signature Schemes)
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
pub const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;

// Versions & Modes
pub const PSK_DHE_KE_MODE: u8 = 0x01;
pub const CERT_COMPRESSION_BROTLI: u16 = 0x0002;
pub const OCSP_STATUS_TYPE: u8 = 0x01;
pub const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0x00;
