//! Расширение ключей по HKDF-SHA256 (RFC 5869).
//!
//! Общий секрет, полученный из [`ECDH`](super::ecdh), сам по себе как ключ не
//! используется. Через HKDF из него детерминированно «разворачивается» несколько
//! независимых ключей под разные цели (см. [`session`](super::session)):
//! AEAD-ключи и IV для каждого направления плюс ключ для time-based аутентификации.
//!
//! Схема двухфазная:
//! - **extract**: `PRK = HKDF-Extract(salt, ikm)` — «сжимает» энтропию секрета;
//! - **expand**: `okm = HKDF-Expand(PRK, label, N)` — выдаёт ключ нужной длины,
//!   уникальный для каждого `label` (`mark`).

use hkdf::Hkdf;
use sha2::Sha256;

/// Безсостоятельная обёртка над `hkdf::Hkdf<Sha256>` с двумя удобными методами.
pub(crate) struct HKDF;

impl HKDF {
    /// Фаза **extract**: связывает соль и входной материал ключа (`ikm`,
    /// общий ECDH-секрет) в псевдослучайный ключ `PRK`.
    ///
    /// Возвращает готовый к фазе expand экстрактор. Соль здесь — это
    /// объединённые локальная+удалённая соли сторон (см. `SaltPair::get_total`).
    pub(crate) fn extract_key(salt: &[u8], ikm: &[u8]) -> Hkdf<Sha256> {
        let extracted_key = Hkdf::<Sha256>::new(Some(salt), ikm);
        extracted_key
    }

    /// Фаза **expand**: выводит ключ длины `N` байт под меткой `mark`.
    ///
    /// `mark` (например `b"client_aead"`) играет роль контекстного лейбла:
    /// разные метки из одного и того же `PRK` дают криптографически независимые
    /// ключи. `N` — параметр-константа, поэтому длина проверяется на этапе
    /// компиляции (32 для ключа, 12 для IV и т.п.).
    pub(crate) fn expand_key<const N: usize>(
        extracted_key: &Hkdf<Sha256>,
        mark: &[u8],
    ) -> Result<[u8; N], String> {
        let mut expanded_key: [u8; N] = [0u8; N];
        extracted_key
            .expand(mark, &mut expanded_key)
            .map_err(|e| e.to_string())?;
        Ok(expanded_key)
    }
}
