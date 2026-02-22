use aead::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
pub struct ECDH {
    pub public_key: PublicKey,
    secret_key: EphemeralSecret,
}

impl ECDH {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret_key: secret,
            public_key: public,
        }
    }

    pub fn get_shared(self, public: &PublicKey) -> [u8; 32] {
        let shared = self.secret_key.diffie_hellman(&public);
        *shared.as_bytes()
    }
}
