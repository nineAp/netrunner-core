use crate::{
    protocol::interceptors::{
        error_interceptor::interceptor_error::InterceptorError, interceptor::Interceptor,
    },
    tlseng::tls::ApplicationData,
};

impl Interceptor for ApplicationData {
    type Error = InterceptorError;

    fn can_handle(bytes: &bytes::BytesMut) -> bool {
        // Application Data не может быть пустым по спецификации (хотя бы 1 байт)
        !bytes.is_empty()
    }

    fn intercept(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized,
    {
        let len = bytes.len();

        if len == 0 {
            return Ok(None);
        }

        let payload = bytes.split_to(len).freeze();

        Ok(Some(Self {
            length: len,
            payload,
        }))
    }
}
