use chacha20poly1305::aead::Buffer;

pub trait AeadPacker {
    fn encrypt<B: Buffer>(&mut self, data: &mut B) -> Result<(), chacha20poly1305::aead::Error>;
    fn decrypt<B: Buffer>(&mut self, data: &mut B) -> Result<(), chacha20poly1305::aead::Error>;
}
