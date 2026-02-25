use aead::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
pub struct ECDH {
    pub public_key: PublicKey,
    pub private_key: Option<EphemeralSecret>,
}

impl ECDH {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private_key: Some(secret),
            public_key: public,
        }
    }

    pub fn get_shared(&mut self, public: &PublicKey) -> Option<[u8; 32]> {
        let private_key = self.private_key.take()?;
        let shared = private_key.diffie_hellman(&public);
        Some(*shared.as_bytes())
    }
}
