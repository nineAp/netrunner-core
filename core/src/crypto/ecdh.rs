//! Эфемерный обмен ключами по схеме X25519 (Elliptic-Curve Diffie-Hellman).
//!
//! Один экземпляр [`ECDH`] обслуживает ровно один хендшейк: на старте генерится
//! эфемерная пара ключей, публичная половина уходит в `ClientHello`/`ServerHello`,
//! а приватная расходуется один раз при вычислении общего секрета и сразу
//! уничтожается. Это и есть механизм forward secrecy: даже компрометация
//! долговременных секретов в будущем не расшифрует записанный ранее трафик.

use aead::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Состояние одной стороны ECDH-обмена.
///
/// `private_key` обёрнут в [`Option`], потому что [`EphemeralSecret`] потребляется
/// при вычислении общего секрета (`diffie_hellman` забирает `self` по значению).
/// После [`ECDH::get_shared`] поле становится `None` и повторный обмен невозможен.
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct ECDH {
    /// Публичный ключ, который отправляется удалённой стороне в KeyShare.
    pub public_key: PublicKey,
    /// Приватный эфемерный ключ. `Some` до первого `get_shared`, затем `None`.
    pub private_key: Option<EphemeralSecret>,
}

impl ECDH {
    /// Генерирует свежую эфемерную пару ключей из системного ГСЧ ([`OsRng`]).
    pub(crate) fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private_key: Some(secret),
            public_key: public,
        }
    }

    /// Вычисляет общий секрет с публичным ключом удалённой стороны.
    ///
    /// Приватный ключ **расходуется**: `take()` извлекает его из `Option`, после
    /// чего поле остаётся `None`. Возвращает `None`, если метод уже вызывался
    /// (т.е. приватного ключа больше нет) — защита от повторного использования.
    pub(crate) fn get_shared(&mut self, public: &PublicKey) -> Option<[u8; 32]> {
        let private_key = self.private_key.take()?;
        let shared = private_key.diffie_hellman(public);
        Some(*shared.as_bytes())
    }
}
