use x25519_dalek::PublicKey;

use crate::crypto::{ecdh::ECDH, hkdf::HKDF, salt_pair::SaltPair};

pub struct KeyPair {
    pub aead_key: [u8; 32],
    pub hmac_key: [u8; 32],
}

pub struct SessionKeys {
    pub salt: SaltPair,
    pub ecdh: ECDH,
    key_pair: KeyPair,
}

impl SessionKeys {
    pub fn new(is_initiator: bool) -> Self {
        Self {
            salt: SaltPair::new(is_initiator),
            ecdh: ECDH::new(),
            key_pair: KeyPair {
                aead_key: [0; 32],
                hmac_key: [0; 32],
            },
        }
    }

    pub fn generate_keys(&mut self, public_key: &PublicKey) -> Result<(), ()> {
        let shared_key = self.ecdh.get_shared(public_key);
        match shared_key {
            Some(key) => {
                let hkdf = HKDF::extract_key(&self.salt.get_total(), &key);
                let aead = HKDF::expand_key::<32>(&hkdf, b"aead").map_err(|e| {
                    println!("Aead Key expand Error: {}", e);
                })?;
                self.key_pair.aead_key = aead;
                let hmac: [u8; 32] = HKDF::expand_key::<32>(&hkdf, b"hmac").map_err(|e| {
                    println!("HMAC Key expand Error: {}", e);
                })?;
                self.key_pair.hmac_key = hmac;
                Ok(())
            }
            None => {
                println!("Error while generate keys. No Shared key");
                Err(())
            }
        }
    }
}
