use bytes::{Bytes, BytesMut};

pub trait AeadPacker {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<Bytes, chacha20poly1305::aead::Error>;
    fn decrypt(&mut self, data: &mut BytesMut) -> Result<Bytes, chacha20poly1305::aead::Error>;
}
