use crate::{
    protocol::{interceptors::error_interceptor::InterceptorError, parser::parser::FrameParser},
    tlseng::application_data::ApplicationData,
};

impl FrameParser for ApplicationData {
    type Error = InterceptorError;

    fn can_parse(bytes: &bytes::BytesMut) -> bool {
        // Application Data не может быть пустым по спецификации (хотя бы 1 байт)
        !bytes.is_empty()
    }

    fn parse(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized,
    {
        let len = bytes.len();

        if len == 0 {
            return Ok(None);
        }

        let payload = bytes.split_to(len).freeze();

        Ok(Some(Self { len, payload }))
    }
}
