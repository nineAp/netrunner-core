/// TLS Content Types as defined in the TLS Record Protocol.
/// These identify what is contained within the TLS Record payload.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum ContentType {
    /// Handshake messages (e.g., ClientHello, ServerHello)
    Handshake = 0x16,
    /// Encrypted application data (the actual traffic)
    ApplicationData = 0x17,
    /// Notification messages (e.g., CloseNotify or error signals)
    Alert = 0x15,
}

impl TryFrom<u8> for ContentType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x16 => Ok(ContentType::Handshake),
            0x17 => Ok(ContentType::ApplicationData),
            0x15 => Ok(ContentType::Alert),
            _ => Err("This is not ContentType"),
        }
    }
}

/// Known TLS protocol versions.
/// Note: TLS 1.3 often uses legacy versions in headers for compatibility.
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
pub enum ProtocolVersion {
    Tls10 = 0x0301,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = &'static str;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0301 => Ok(ProtocolVersion::Tls10),
            0x0303 => Ok(ProtocolVersion::Tls12),
            0x0304 => Ok(ProtocolVersion::Tls13),
            _ => Err("This is not Protocol Version"),
        }
    }
}

pub enum HelloType {
    Client = 0x01,
    Server = 0x02,
}

impl TryFrom<u8> for HelloType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(HelloType::Client),
            0x02 => Ok(HelloType::Server),
            _ => Err("This is not Hello header"),
        }
    }
}
