use x25519_dalek::PublicKey;

use crate::{
    crypto::{ecdh::ECDH, hkdf::HKDF},
    tlseng::extension::ExtensionStack,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

pub struct SessionKeys {
    pub salt: SaltPair,
    pub ecdh: ECDH,
    pub auth_key: [u8; 32],
}

impl SessionKeys {
    pub fn new(is_initiator: bool) -> Self {
        Self {
            salt: SaltPair::new(is_initiator),
            ecdh: ECDH::new(),
            auth_key: [0u8; 32],
        }
    }

    pub fn update_keys(
        &mut self,
        salt: [u8; 32],
        extensions: &ExtensionStack,
        is_server: bool, // true если мы Сервер (парсим ClientHello), false если Клиент
    ) -> Result<([u8; 32], [u8; 12], [u8; 32], [u8; 12]), String> {
        // Сохраняем соль от удаленной стороны
        self.salt.set_remote_salt(salt);

        tracing::debug!(
            remote_salt = %hex::encode(&salt[..8]),
            local_salt = %hex::encode(&self.salt.get_local()[..8]),
            total_salt = %hex::encode(&self.salt.get_total()[28..36]),
            "Updating keys with new salt"
        );

        const EXT_KEY_SHARE: u16 = 0x0033;

        if let Some(dh_data) = extensions.find_by_type(EXT_KEY_SHARE) {
            let mut key_bytes = [0u8; 32];

            if is_server {
                // МЫ СЕРВЕР: Парсим ClientHello KeyShare (там список)
                // Минимум: 2 (длина списка) + 2 (группа) + 2 (длина ключа) + 32 (ключ) = 38
                if dh_data.len() < 38 {
                    return Err(format!(
                        "Client KeyShare too short: {} bytes",
                        dh_data.len()
                    ));
                }

                let mut found = false;
                // Ищем маркер x25519 (00 1d) и длину 32 (00 20)
                for i in 2..=(dh_data.len() - 34) {
                    if dh_data[i..i + 4] == [0x00, 0x1d, 0x00, 0x20] {
                        key_bytes.copy_from_slice(&dh_data[i + 4..i + 36]);
                        found = true;
                        break;
                    }
                }

                if !found {
                    return Err("Could not find x25519 key in ClientHello".into());
                }
            } else {
                // МЫ КЛИЕНТ: Парсим ServerHello KeyShare (там сразу группа и ключ)
                // [Group:2] [KeyLen:2] [Key:32] = 36 байт
                if dh_data.len() < 36 {
                    return Err("Server KeyShare too short".into());
                }
                key_bytes.copy_from_slice(&dh_data[4..36]);
            }

            // Проверка на "кривой" ключ
            if key_bytes.iter().all(|&x| x == 0) {
                return Err("Extracted remote public key is all ZEROS!".into());
            }

            let public_key = PublicKey::from(key_bytes);

            tracing::debug!(
                remote_pub = %hex::encode(&key_bytes[..4]),
                role = if is_server { "Server" } else { "Client" },
                "Key exchange successful, deriving material..."
            );

            // Вызываем генерацию, которая вернет (w_key, w_iv, r_key, r_iv)
            self.generate_keys(&public_key, is_server)
        } else {
            Err("No KeyShare extension found in handshake".into())
        }
    }
    fn generate_keys(
        &mut self,
        public_key: &PublicKey,
        is_server: bool,
    ) -> Result<([u8; 32], [u8; 12], [u8; 32], [u8; 12]), String> {
        let shared_key = self
            .ecdh
            .get_shared(public_key)
            .ok_or_else(|| "No shared secret".to_string())?;

        tracing::debug!(
            shared_prefix = %hex::encode(&shared_key[..8]),
            "DH Shared secret derived"
        );

        let hkdf = HKDF::extract_key(&self.salt.get_total(), &shared_key);

        let c_key = HKDF::expand_key::<32>(&hkdf, b"client_aead").map_err(|e| e.to_string())?;
        let c_iv = HKDF::expand_key::<12>(&hkdf, b"client_iv").map_err(|e| e.to_string())?;
        let s_key = HKDF::expand_key::<32>(&hkdf, b"server_aead").map_err(|e| e.to_string())?;
        let s_iv = HKDF::expand_key::<12>(&hkdf, b"server_iv").map_err(|e| e.to_string())?;

        let auth_secret = HKDF::expand_key::<32>(&hkdf, b"auth_key").map_err(|e| e.to_string())?;
        self.auth_key = auth_secret;
        tracing::info!(
            client_key_short = %hex::encode(&c_key[..4]),
            server_key_short = %hex::encode(&s_key[..4]),
            "HKDF expansion complete"
        );

        // Распределяем: (write_key, write_iv, read_key, read_iv)
        if is_server {
            Ok((s_key, s_iv, c_key, c_iv)) // Сервер пишет своим, читает клиентским
        } else {
            Ok((c_key, c_iv, s_key, s_iv)) // Клиент пишет своим, читает серверным
        }
    }

    fn compute_tag(secret: &[u8], step: u64) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC error");
        mac.update(&step.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[..16]);
        tag
    }

    pub fn generate_auth_tag(&self) -> [u8; 16] {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Генерируем на основе текущей минуты
        Self::compute_tag(&self.auth_key, now / 60)
    }

    pub fn verify_auth_tag(&self, received_tag: &[u8; 16]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let current_step = now / 60;

        // 1. Проверяем текущую минуту (самый вероятный случай)
        if &Self::compute_tag(&self.auth_key, current_step) == received_tag {
            return true;
        }

        // 2. Проверяем предыдущую минуту (на случай стыка минут или задержки сети)
        if &Self::compute_tag(&self.auth_key, current_step - 1) == received_tag {
            tracing::debug!("Auth tag valid (matched previous minute window)");
            return true;
        }

        // Если ни один не подошел — тег невалиден
        false
    }

    // Вспомогательная функция для генерации конкретного тега
}
