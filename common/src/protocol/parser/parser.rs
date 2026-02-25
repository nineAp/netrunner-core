use bytes::BytesMut;

pub trait FrameParser {
    type Error;
    fn can_parse(bytes: &BytesMut) -> bool;
    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized;
}
