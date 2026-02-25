use bytes::{Buf, Bytes};

use crate::{
    protocol::{
        interceptors::error_interceptor::{ErrorAction, ErrorType, InterceptorError},
        parser::parser::FrameParser,
    },
    tlseng::{handshake::hello_header::HelloHeader, types::HelloType},
    utils::u24::{BufExt, U24},
};

impl FrameParser for HelloHeader {
    type Error = InterceptorError;
    fn can_parse(bytes: &bytes::BytesMut) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let is_valid = match bytes[0] {
            x if x == HelloType::Client as u8 => true,
            x if x == HelloType::Server as u8 => true,
            _ => false,
        };
        is_valid
    }

    fn parse(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized,
    {
        if bytes.len() < 4 {
            return Ok(None);
        }
        let raw_header_type = bytes.get_u8();
        let header_type = HelloType::try_from(raw_header_type).map_err(|e| {
            InterceptorError::new(
                ErrorType::Handshake(e),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&raw_header_type.to_be_bytes()),
            )
        })?;
        let len = bytes.get_u24();
        Ok(Some(Self {
            header_type,
            len: U24::from_u32(len),
        }))
    }
}
