use bytes::{BufMut, Bytes, BytesMut};

use crate::tlseng::types::{ContentType, ProtocolVersion};

/// The TLS Record Layer structure.
/// This is the outer envelope that wraps all TLS messages sent over the wire.
#[derive(Debug)]
pub struct TlsRecord {
    /// The type of data contained (Handshake, ApplicationData, etc.)
    pub content_type: ContentType,
    /// The record layer version (usually 0x0301 for legacy support)
    pub version: ProtocolVersion,

    pub len: u16,
    /// The actual data being transported (e.g., a serialized ClientHello)
    pub payload: Bytes,
}

impl TlsRecord {
    /// Creates a new TLS Record Layer from the given parameters.
    ///
    /// # Arguments
    ///
    /// * `content_type`: The type of data contained (Handshake, ApplicationData, etc.).
    /// * `version`: The record layer version (usually 0x0301 for legacy support).
    /// * `payload`: The actual data being transported (e.g., a serialized ClientHello).
    ///
    /// # Returns
    ///
    /// A new TLS Record Layer structure with the given parameters.
    pub fn new(content_type: ContentType, version: ProtocolVersion, payload: Bytes) -> Self {
        Self {
            content_type,
            version,
            len: payload.len() as u16,
            payload,
        }
    }

    /// Serializes the Record Layer header and payload.
    /// Wire Format: [Type (1)] [Version (2)] [Length (2)] [Payload (N)]
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.payload.len());

        buf.put_u8(self.content_type as u8);
        buf.put_u16(self.version as u16);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    pub fn build_application_data(payload: Bytes) -> Bytes {
        tracing::trace!(payload_len = payload.len(), "Building TlsRecord from Bytes");

        let record = Self::new(
            ContentType::ApplicationData,
            ProtocolVersion::Tls12,
            payload,
        );
        record.serialize()
    }
}
