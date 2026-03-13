use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::crypto::aead::AeadPacker;

pub struct NonceState {
    counter: u64,
    base_iv: [u8; 12],
}

impl NonceState {
    pub fn new(base_iv: [u8; 12]) -> Self {
        Self {
            counter: 0,
            base_iv,
        }
    }

    pub fn next_nonce(&mut self) -> Nonce {
        let mut iv = self.base_iv;

        let counter_bytes = self.counter.to_be_bytes();

        for i in 0..8 {
            iv[i + 4] ^= counter_bytes[i];
        }

        self.counter += 1;
        *GenericArray::from_slice(&iv)
    }
}

pub struct ChaChaCipher {
    pub encrypt_cipher: ChaCha20Poly1305,
    pub decrypt_cipher: ChaCha20Poly1305,
    pub encrypt_state: NonceState,
    pub decrypt_state: NonceState,
}

impl ChaChaCipher {
    pub fn new() -> Self {
        let start_key = Key::from([0u8; 32]);
        let encrypt_cipher = ChaCha20Poly1305::new(&start_key);
        let decrypt_cipher = ChaCha20Poly1305::new(&start_key);
        Self {
            encrypt_state: NonceState::new([0u8; 12]),
            decrypt_state: NonceState::new([0u8; 12]),
            encrypt_cipher,
            decrypt_cipher,
        }
    }

    pub fn set_keys(&mut self, w_key: [u8; 32], w_iv: [u8; 12], r_key: [u8; 32], r_iv: [u8; 12]) {
        self.encrypt_cipher = ChaCha20Poly1305::new(Key::from_slice(&w_key));
        self.decrypt_cipher = ChaCha20Poly1305::new(Key::from_slice(&r_key));

        self.encrypt_state = NonceState::new(w_iv);
        self.decrypt_state = NonceState::new(r_iv);

        tracing::debug!("Cipher keys and IVs updated for both directions");
    }
}
impl AeadPacker for ChaChaCipher {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<Bytes, chacha20poly1305::aead::Error> {
        let current_counter = self.encrypt_state.counter;
        let nonce = self.encrypt_state.next_nonce();
        let data_len = data.len();

        match self.encrypt_cipher.encrypt_in_place(&nonce, &nonce, data) {
            Ok(_) => {
                tracing::trace!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Encryption successful"
                );
                Ok(data.split().freeze())
            }
            Err(e) => {
                tracing::error!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    error = ?e,
                    "AEAD encryption failure"
                );
                Err(e)
            }
        }
    }

    fn decrypt(&mut self, data: &mut BytesMut) -> Result<Bytes, chacha20poly1305::aead::Error> {
        let current_counter = self.decrypt_state.counter;
        let nonce = self.decrypt_state.next_nonce();
        let data_len = data.len();

        match self.decrypt_cipher.decrypt_in_place(&nonce, &nonce, data) {
            Ok(_) => {
                tracing::trace!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Decryption successful"
                );
                Ok(data.split().freeze())
            }
            Err(e) => {
                let data_prefix = if data.len() >= 8 {
                    hex::encode(&data[..8])
                } else {
                    hex::encode(data.as_ref())
                };
                tracing::error!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    prefix = %data_prefix,
                    error = ?e,
                    "AEAD decryption failure! Verification failed or data malformed"
                );
                Err(e)
            }
        }
    }
}
