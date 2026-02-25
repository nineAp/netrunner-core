use aead::{rand_core::RngCore, OsRng};

pub struct SaltPair {
    local_salt: [u8; 32],
    remote_salt: [u8; 32],
    is_initiator: bool,
}

impl SaltPair {
    pub fn new(is_initiator: bool) -> Self {
        let mut local_salt = [0u8; 32];
        OsRng.fill_bytes(&mut local_salt);
        Self {
            local_salt,
            remote_salt: [0; 32],
            is_initiator,
        }
    }

    pub fn get_local(&self) -> [u8; 32] {
        self.local_salt
    }

    pub fn set_remote_salt(&mut self, salt: [u8; 32]) {
        self.remote_salt = salt
    }

    pub fn get_total(&self) -> [u8; 64] {
        let mut salt = [0u8; 64];
        if self.is_initiator {
            salt[..32].copy_from_slice(&self.local_salt);
            salt[32..].copy_from_slice(&self.remote_salt);
            salt
        } else {
            salt[..32].copy_from_slice(&self.remote_salt);
            salt[32..].copy_from_slice(&self.local_salt);
            salt
        }
    }
}
