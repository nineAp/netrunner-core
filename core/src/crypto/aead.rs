use bytes::BytesMut;

pub(crate) trait AeadPacker {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<(), chacha20poly1305::aead::Error>;
    fn decrypt(&mut self, data: &mut BytesMut) -> Result<(), chacha20poly1305::aead::Error>;
}
