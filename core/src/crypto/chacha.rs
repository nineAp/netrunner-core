use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::crypto::aead::AeadPacker;

struct NonceState {
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

// Универсальная структура для одного направления трафика (Tx или Rx)
pub struct ChaChaStream {
    cipher: ChaCha20Poly1305,
    state: NonceState,
}

impl ChaChaStream {
    pub fn new(key: &[u8; 32], iv: [u8; 12]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            state: NonceState::new(iv),
        }
    }
}

// Реализуем трейт AeadPacker для однонаправленного потока
impl AeadPacker for ChaChaStream {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<Bytes, chacha20poly1305::aead::Error> {
        let current_counter = self.state.counter;
        let nonce = self.state.next_nonce();
        let data_len = data.len();

        match self.cipher.encrypt_in_place(&nonce, &nonce, data) {
            Ok(_) => {
                netrunner_logger::trace!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Encryption successful"
                );
                Ok(data.split().freeze())
            }
            Err(e) => {
                netrunner_logger::error!(
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
        let current_counter = self.state.counter;
        let nonce = self.state.next_nonce();
        let data_len = data.len();

        match self.cipher.decrypt_in_place(&nonce, &nonce, data) {
            Ok(_) => {
                netrunner_logger::trace!(
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
                netrunner_logger::error!(
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

// Контейнер для двух потоков, который легко разделяется
pub struct ChaChaCipher {
    pub tx: ChaChaStream,
    pub rx: ChaChaStream,
}

impl ChaChaCipher {
    pub fn new() -> Self {
        Self {
            tx: ChaChaStream::new(&[0u8; 32], [0u8; 12]),
            rx: ChaChaStream::new(&[0u8; 32], [0u8; 12]),
        }
    }

    pub fn set_keys(&mut self, w_key: [u8; 32], w_iv: [u8; 12], r_key: [u8; 32], r_iv: [u8; 12]) {
        self.tx = ChaChaStream::new(&w_key, w_iv);
        self.rx = ChaChaStream::new(&r_key, r_iv);
        netrunner_logger::debug!("Cipher keys and IVs updated for both directions");
    }

    // Возвращает независимые потоки (Rx, Tx) для параллельной работы в Tokio
    pub fn split(self) -> (ChaChaStream, ChaChaStream) {
        (self.rx, self.tx)
    }
}
