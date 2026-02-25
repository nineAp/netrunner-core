use bytes::{Bytes, BytesMut};

use crate::{
    protocol::{
        interceptors::error_interceptor::{ErrorAction, ErrorType, InterceptorError},
        parser::parser::FrameParser,
    },
    tlseng::tls_record::TlsRecord,
};

pub trait TlsInterceptor {
    type Output;
    fn start_process(buffer: &mut BytesMut) -> Result<Option<Self::Output>, InterceptorError> {
        match TlsRecord::parse(buffer) {
            Ok(Some(record)) => Self::handle_record(record),
            Ok(None) => Err(InterceptorError::new(
                ErrorType::Tls("Not full Data"),
                ErrorAction::Wait,
                Bytes::new(),
            )),
            Err(e) => Err(e),
        }
    }
    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, InterceptorError>;
}
