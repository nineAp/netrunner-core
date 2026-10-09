//! Ключ роя и личность узла в рое.
//!
//! **Рой** — сеть, члены которой знают общий 32-байтовый `swarm_key`. Из него
//! выводится входной секрет каждого узла: `nrxp_secret(id) = HKDF(swarm_key, id)`.
//! Поэтому в публичных записях секретов нет вообще (раньше каталог панели раздавал
//! `nrxp_secret` каждого узла всем узлам), а участник рассчитывает барьер любого
//! соседа сам. Кто ключа не знает — не пройдёт даже тег `ClientHello`.
//!
//! Это **промежуточное** звено этапа A: ключ роя — разделяемый секрет, и его
//! утечка снимает входной барьер всей сети (но не позволяет подменить узел —
//! его личность держит статический ключ в хендшейке). Следующие этапы заменяют его
//! парными секретами из статического DH и токенами-способностями.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use super::descriptor::{derive_node_id, derive_signing_key, node_id_hex, NodeId};

#[derive(Clone)]
pub struct SwarmKey([u8; 32]);

impl std::fmt::Debug for SwarmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwarmKey([REDACTED])")
    }
}

impl SwarmKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let b = hex::decode(s.trim()).map_err(|e| format!("swarm key: {e}"))?;
        let a: [u8; 32] = b.try_into().map_err(|_| "swarm key must be 32 bytes (64 hex chars)".to_string())?;
        Ok(Self(a))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Новый случайный ключ роя.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// Входной секрет узла `id` (hex, 64 символа) — то, что узел держит как
    /// `PROXY_NRXP_SECRET`, а соседи используют для тега `ClientHello`.
    pub fn node_secret(&self, id: &NodeId) -> String {
        let hk = Hkdf::<Sha256>::new(Some(b"nrxp-swarm-v1"), &self.0);
        let mut out = [0u8; 32];
        hk.expand(&[b"node-secret:".as_slice(), id.as_slice()].concat(), &mut out)
            .expect("32 bytes is a valid HKDF output length");
        hex::encode(out)
    }

    /// Проверка секрета пира в постоянное время.
    pub fn check_node_secret(&self, id: &NodeId, presented: &str) -> bool {
        use subtle::ConstantTimeEq;
        let want = self.node_secret(id);
        want.as_bytes().ct_eq(presented.trim().to_ascii_lowercase().as_bytes()).into()
    }
}

/// Личность узла: ключи и производные от них идентификаторы.
pub struct SwarmIdentity {
    pub node_id: NodeId,
    pub static_private: [u8; 32],
    pub static_pub: [u8; 32],
    pub signing: SigningKey,
}

impl SwarmIdentity {
    pub fn from_static_private(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let static_pub = *PublicKey::from(&secret).as_bytes();
        let signing = derive_signing_key(&private);
        let node_id = derive_node_id(&signing.verifying_key().to_bytes(), &static_pub);
        Self {
            node_id,
            static_private: private,
            static_pub,
            signing,
        }
    }

    pub fn from_private_hex(hex_key: &str) -> Result<Self, String> {
        let b = hex::decode(hex_key.trim()).map_err(|e| format!("static private key: {e}"))?;
        let a: [u8; 32] = b
            .try_into()
            .map_err(|_| "static private key must be 32 bytes (64 hex chars)".to_string())?;
        Ok(Self::from_static_private(a))
    }

    pub fn node_id_hex(&self) -> String {
        node_id_hex(&self.node_id)
    }
}
