use bytes::{Bytes, BytesMut};

use crate::{
    protocol::{
        codec::bridges::tls::tls_interceptor::TlsInterceptor,
        interceptors::error_interceptor::{ErrorAction, ErrorType, InterceptorError},
    },
    tlseng::{application_data::ApplicationData, tls_record::TlsRecord, types::ContentType},
};

impl TlsInterceptor for ApplicationData {
    type Output = ApplicationData;

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, InterceptorError> {
        let mut payload = BytesMut::from(record.payload.as_ref());
        match record.content_type {
            ContentType::ApplicationData => Self::handle_application_data(&mut payload),
            _ => {
                println!("content type byte is: {:?}", record.content_type);
                Err(InterceptorError::new(
                    ErrorType::ApplicationData("Not Application Data"),
                    ErrorAction::Drop,
                    record.serialize(),
                ))
            }
        }
    }
}

impl ApplicationData {
    fn handle_application_data(payload: &mut BytesMut) -> Result<Option<Self>, InterceptorError> {
        println!("Bytes here?: {:?}", &payload);
        let data_option = ApplicationData::start_process(payload)?;
        let data = data_option.ok_or_else(|| {
            InterceptorError::new(
                ErrorType::ApplicationData("AppData Err TODO"),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&[]),
            )
        })?;
        println!("Получены Application Data: {} байт", payload.len());
        Ok(Some(data))
    }
}
