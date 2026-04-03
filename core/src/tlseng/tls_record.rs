use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    nrxp::{ErrorAction, ErrorStage, TlsError},
    parser::Parser,
    tlseng::types::{ContentType, ProtocolVersion},
};

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

impl Parser for TlsRecord {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < 5 {
            return false;
        }

        let content_type = bytes[0];
        let is_valid_type = content_type == ContentType::Handshake as u8
            || content_type == ContentType::ApplicationData as u8
            || content_type == ContentType::Alert as u8;

        if !is_valid_type {
            return false;
        }

        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        if content_type == ContentType::ApplicationData as u8 {
            if record_len < 17 {
                return false;
            }
        }

        bytes.len() >= 5 + record_len
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<TlsRecord>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let raw_content_type = bytes.get_u8();
        let raw_version = bytes.get_u16();
        let record_len = bytes.get_u16() as usize;

        let content_type = ContentType::try_from(raw_content_type)
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Redirect, Bytes::new()))?;

        let version = ProtocolVersion::try_from(raw_version)
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let payload = bytes.split_to(record_len).freeze();

        Ok(Some(TlsRecord::new(content_type, version, payload)))
    }
}

pub struct ApplicationData {
    pub _len: usize,
    pub payload: Bytes,
}

impl Parser for ApplicationData {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        !bytes.is_empty()
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        let _len = bytes.len();
        if _len == 0 {
            return Ok(None);
        }
        let payload = bytes.split_to(_len).freeze();
        Ok(Some(Self { _len, payload }))
    }
}
