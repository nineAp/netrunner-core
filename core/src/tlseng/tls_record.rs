use bytes::{BufMut, Bytes, BytesMut};

use crate::tlseng::types::{ContentType, ProtocolVersion};

#[derive(Debug)]
pub struct TlsRecord {
    pub content_type: ContentType,

    pub version: ProtocolVersion,

    pub _len: u16,

    pub payload: Bytes,
}

impl TlsRecord {
    pub fn new(content_type: ContentType, version: ProtocolVersion, payload: Bytes) -> Self {
        Self {
            content_type,
            version,
            _len: payload.len() as u16,
            payload,
        }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.payload.len());

        buf.put_u8(self.content_type as u8);
        buf.put_u16(self.version as u16);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    pub fn build_application_data(payload: Bytes) -> Bytes {
        netrunner_logger::trace!(payload_len = payload.len(), "Building TlsRecord from Bytes");

        let record = Self::new(
            ContentType::ApplicationData,
            ProtocolVersion::Tls12,
            payload,
        );
        record.serialize()
    }
}
