use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Buffer, OsRng};
use chacha20poly1305::{
    AeadCore, AeadInPlace, ChaCha20Poly1305, ChaChaPoly1305, Key, KeyInit, Nonce,
};

use crate::crypto::aead::AeadPacker;

pub struct NonceState {
    counter: u64,
    nonce: Nonce,
    handshake: bool,
}

impl NonceState {
    pub fn new() -> Self {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        println!("Nonce is {:?}", nonce);
        Self {
            counter: 0,
            nonce,
            handshake: false,
        }
    }

    pub fn get_handshake(&self) -> bool {
        return self.handshake;
    }

    pub fn set_nonce(&mut self, nonce: Nonce) {
        self.nonce = nonce;
        self.handshake = true
    }

    pub fn increase_counter(&mut self) {
        self.counter += 1;
        let counter_bytes = self.counter.to_be_bytes();
        self.nonce[4..12].copy_from_slice(&counter_bytes);
        println!("Current Nonce is {:?}", self.nonce);
    }
}

pub struct ChaChaCipher {
    key: Key,
    pub encrypt_state: NonceState,
    pub decrypt_state: NonceState,
    pub cipher: ChaCha20Poly1305,
}

impl ChaChaCipher {
    pub fn new() -> Self {
        let key = GenericArray::clone_from_slice(&[0; 32]);
        let cipher = ChaCha20Poly1305::new(&key);
        Self {
            key,
            encrypt_state: NonceState::new(),
            decrypt_state: NonceState::new(),
            cipher,
        }
    }

    pub fn set_key(&mut self, key: Key) -> () {
        self.key = key;
        self.cipher = ChaChaPoly1305::new(&self.key);
    }
}

impl AeadPacker for ChaChaCipher {
    fn encrypt<B: Buffer>(&mut self, data: &mut B) -> Result<(), chacha20poly1305::aead::Error> {
        self.cipher
            .encrypt_in_place(&self.encrypt_state.nonce, &[], data)?;
        self.encrypt_state.increase_counter();
        Ok(())
    }

    fn decrypt<B: Buffer>(&mut self, data: &mut B) -> Result<(), chacha20poly1305::aead::Error> {
        println!("Buffer: {:?}", data.as_mut());
        println!("nonce: {:?}", &self.decrypt_state.nonce);
        self.cipher
            .decrypt_in_place(&self.decrypt_state.nonce, &[], data)?;
        self.decrypt_state.increase_counter();
        Ok(())
    }
}
