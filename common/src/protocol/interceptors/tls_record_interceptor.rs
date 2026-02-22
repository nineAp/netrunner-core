use bytes::{Buf, Bytes, BytesMut};

use crate::{
    protocol::interceptors::{
        error_interceptor::interceptor_error::{ErrorAction, ErrorType, InterceptorError},
        interceptor::Interceptor,
    },
    tlseng::tls::{ContentType, ProtocolVersion, TlsRecord},
};

impl Interceptor for TlsRecord {
    type Error = InterceptorError;
    fn can_handle(bytes: &BytesMut) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let is_valid = match bytes[0] {
            x if x == ContentType::Handshake as u8 => true,
            x if x == ContentType::ApplicationData as u8 => true,
            x if x == ContentType::Alert as u8 => true,
            _ => false,
        };
        is_valid
    }
    fn intercept(bytes: &mut BytesMut) -> Result<Option<TlsRecord>, Self::Error> {
        if bytes.len() < 5 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([bytes[3], bytes[4]]);
        if bytes.len() < 5 + len as usize {
            return Ok(None);
        }
        let raw_content_type = bytes.get_u8();
        let raw_version = bytes.get_u16();
        let content_type = ContentType::try_from(raw_content_type).map_err(|e| {
            InterceptorError::new(
                ErrorType::Tls(e),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&raw_content_type.to_be_bytes()),
            )
        })?;
        let version = ProtocolVersion::try_from(raw_version).map_err(|e| {
            InterceptorError::new(
                ErrorType::Tls(e),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&raw_version.to_be_bytes()),
            )
        })?;
        let _raw_len = bytes.get_u16();
        let payload = bytes.split_to(len as usize).freeze();
        Ok(Some(TlsRecord {
            content_type,
            version,
            len,
            payload,
        }))
    }
}
