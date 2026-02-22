use bytes::BytesMut;

pub trait Interceptor {
    type Error;
    fn can_handle(bytes: &BytesMut) -> bool;
    fn intercept(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized;
}
