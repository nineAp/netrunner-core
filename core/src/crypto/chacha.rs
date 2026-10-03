//! Потоковое AEAD-шифрование ChaCha20-Poly1305.
//!
//! Это «горячий путь» крипто-блока: через него проходит каждый кадр данных.
//! Ключевые свойства:
//!
//! - **Раздельные направления.** [`ChaChaCipher`] держит два независимых потока —
//!   `tx` (исходящий) и `rx` (входящий), у каждого свой ключ, IV и счётчик nonce.
//! - **Детерминированный nonce.** Nonce не передаётся по сети: обе стороны
//!   синхронно считают `nonce = base_iv XOR counter` (см. [`NonceState`]).
//!   Счётчики растут строго в ногу, поэтому любой пропуск/повтор кадра ломает
//!   расшифровку — это и есть встроенная защита целостности потока.
//! - **In-place.** Шифр работает прямо в [`BytesMut`] без копий и аллокаций.

use bytes::BytesMut;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{AeadCipher, AeadError, AeadPacker, AeadSuite};
use crate::crypto::hkdf::HKDF;

/// Implicit key update cadence for the ordered NRXP record stream. Both peers
/// count authenticated records independently in each direction, so no new
/// wire field or round trip is required.
const STREAM_REKEY_AFTER_RECORDS: u64 = 1 << 20;

/// Генератор nonce для одного направления.
///
/// Nonce строится как `base_iv XOR big_endian(counter)` по младшим 8 байтам IV.
/// `counter` монотонно растёт на каждый кадр, гарантируя уникальность nonce в
/// пределах ключа (повтор nonce при одном ключе фатален для ChaCha20-Poly1305).
struct NonceState {
    /// Счётчик кадров. Должен совпадать у отправителя и получателя по направлению.
    counter: u64,
    /// Базовый IV (12 байт), полученный из HKDF; неизменен на всю сессию.
    base_iv: [u8; 12],
}

impl NonceState {
    pub fn new(base_iv: [u8; 12]) -> Self {
        Self {
            counter: 0,
            base_iv,
        }
    }

    /// Возвращает nonce для текущего кадра и инкрементирует счётчик.
    ///
    /// Затирание `base_iv` см. в [`Drop for NonceState`](NonceState#impl-Drop).
    ///
    /// XOR накладывается на байты `iv[4..12]` (младшие 8 байт 12-байтового IV),
    /// старшие 4 байта остаются «солью» из IV. После вызова `counter`
    /// увеличивается, поэтому следующий кадр получит другой nonce.
    pub fn next_nonce(&mut self) -> Result<[u8; 12], AeadError> {
        let next = self
            .counter
            .checked_add(1)
            .ok_or(AeadError::NonceExhausted)?;
        let mut iv = self.base_iv;
        let counter_bytes = self.counter.to_be_bytes();

        for i in 0..8 {
            iv[i + 4] ^= counter_bytes[i];
        }

        self.counter = next;
        Ok(iv)
    }
}

/// Затирание базового IV.
///
/// IV — не ключ, но выводится тем же HKDF из того же секрета сессии, и вместе с
/// утёкшим ключом даёт готовый nonce для каждого кадра. Сам ключ `ChaCha20Poly1305`
/// затирает уже сам (`ZeroizeOnDrop` в `chacha20poly1305`), так что это добирает
/// вторую половину пары.
impl Drop for NonceState {
    fn drop(&mut self) {
        self.base_iv.zeroize();
    }
}

/// Однонаправленный шифр: одна пара (ключ, IV) + её счётчик nonce.
///
/// Реализует [`AeadPacker`]. Используется парами внутри [`ChaChaCipher`].
pub struct AeadStream {
    cipher: AeadCipher,
    state: NonceState,
    suite: AeadSuite,
    legacy_chacha_aad: bool,
    ratchet: Zeroizing<[u8; 32]>,
    records_in_epoch: u64,
}

impl AeadStream {
    pub fn new(key: &[u8; 32], iv: [u8; 12]) -> Self {
        Self::with_suite_and_legacy_chacha_aad(AeadSuite::ChaCha20Poly1305, key, iv, true)
    }

    pub fn with_suite(suite: AeadSuite, key: &[u8; 32], iv: [u8; 12]) -> Self {
        Self::with_suite_and_legacy_chacha_aad(suite, key, iv, false)
    }

    pub fn with_suite_and_legacy_chacha_aad(
        suite: AeadSuite,
        key: &[u8; 32],
        iv: [u8; 12],
        legacy_chacha_aad: bool,
    ) -> Self {
        Self {
            cipher: AeadCipher::new(suite, key).expect("fixed-size AEAD key is valid"),
            state: NonceState::new(iv),
            suite,
            legacy_chacha_aad: legacy_chacha_aad && suite == AeadSuite::ChaCha20Poly1305,
            ratchet: Zeroizing::new(*key),
            records_in_epoch: 0,
        }
    }

    fn rekey(&mut self) {
        let root_hk = HKDF::from_prk(&self.ratchet);
        let mut next_root = HKDF::expand_key::<32>(&root_hk, b"nrxp-stream-ratchet-next")
            .expect("fixed-length HKDF-expand cannot fail");
        let epoch_hk = HKDF::from_prk(&next_root);
        let mut key = HKDF::expand_key::<32>(&epoch_hk, b"nrxp-stream-aead-key")
            .expect("fixed-length HKDF-expand cannot fail");
        let mut iv = HKDF::expand_key::<12>(&epoch_hk, b"nrxp-stream-aead-iv")
            .expect("fixed-length HKDF-expand cannot fail");

        self.cipher =
            AeadCipher::new(self.suite, &key).expect("fixed-size AEAD rekey material is valid");
        self.state = NonceState::new(iv);
        self.ratchet = Zeroizing::new(next_root);
        self.records_in_epoch = 0;
        next_root.zeroize();
        key.zeroize();
        iv.zeroize();
    }

    fn should_rekey(&self) -> bool {
        self.suite != AeadSuite::ChaCha20Poly1305
            && self.records_in_epoch >= STREAM_REKEY_AFTER_RECORDS
    }
}

impl AeadPacker for AeadStream {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<(), AeadError> {
        if self.should_rekey() {
            self.rekey();
        }
        let current_counter = self.state.counter;
        let nonce = self.state.next_nonce()?;
        let data_len = data.len();

        // Убеждаемся, что в BytesMut есть место для тега, чтобы избежать аллокации
        data.reserve(16);

        let aad: &[u8] = if self.legacy_chacha_aad { &nonce } else { &[] };
        match self.cipher.seal(nonce, aad, data) {
            Ok(_) => {
                netrunner_logger::trace!(
                    counter = current_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Encryption successful"
                );
                self.records_in_epoch += 1;
                Ok(())
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

    fn decrypt(&mut self, data: &mut BytesMut) -> Result<(), AeadError> {
        if self.should_rekey() {
            self.rekey();
        }
        let saved_counter = self.state.counter;
        let nonce = self.state.next_nonce()?;
        let data_len = data.len();

        let aad: &[u8] = if self.legacy_chacha_aad { &nonce } else { &[] };
        match self.cipher.open(nonce, aad, data) {
            Ok(_) => {
                netrunner_logger::trace!(
                    counter = saved_counter,
                    nonce = %hex::encode(nonce),
                    len = data_len,
                    "Decryption successful"
                );
                self.records_in_epoch += 1;
                Ok(())
            }
            Err(e) => {
                // Roll back the counter: the plaintext was not produced, so the
                // peer's TX counter is still at saved_counter. If the caller
                // decides to retry (e.g., after a corrective re-read) rather
                // than drop the connection, the next decrypt attempt will use
                // the same nonce and succeed. In practice we always Drop on
                // AEAD failure, but correctness requires the rollback.
                self.state.counter = saved_counter;

                let data_prefix = if data.len() >= 8 {
                    hex::encode(&data[..8])
                } else {
                    hex::encode(data.as_ref())
                };
                netrunner_logger::error!(
                    counter = saved_counter,
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

/// Двунаправленный шифр сессии: исходящий (`tx`) и входящий (`rx`) потоки.
///
/// Создаётся «пустым» (нулевые ключи) до завершения хендшейка, затем
/// [`set_keys`](ChaChaCipher::set_keys) заряжает реальные ключи из HKDF.
pub struct SessionCipher {
    /// Исходящее направление (шифрование того, что отправляем).
    pub tx: AeadStream,
    /// Входящее направление (расшифровка того, что приняли).
    pub rx: AeadStream,
    suite: AeadSuite,
    legacy_chacha_aad: bool,
}

impl SessionCipher {
    /// Создаёт шифр с нулевыми ключами-заглушками (до хендшейка).
    pub fn new() -> Self {
        Self::with_suite_and_legacy_chacha_aad(AeadSuite::ChaCha20Poly1305, true)
    }

    pub fn with_suite(suite: AeadSuite) -> Self {
        Self::with_suite_and_legacy_chacha_aad(suite, false)
    }

    pub fn with_suite_and_legacy_chacha_aad(suite: AeadSuite, legacy_chacha_aad: bool) -> Self {
        Self {
            tx: AeadStream::with_suite_and_legacy_chacha_aad(
                suite,
                &[0u8; 32],
                [0u8; 12],
                legacy_chacha_aad,
            ),
            rx: AeadStream::with_suite_and_legacy_chacha_aad(
                suite,
                &[0u8; 32],
                [0u8; 12],
                legacy_chacha_aad,
            ),
            suite,
            legacy_chacha_aad: legacy_chacha_aad && suite == AeadSuite::ChaCha20Poly1305,
        }
    }

    /// Заряжает реальные ключи/IV после хендшейка: `w_*` — на запись (tx),
    /// `r_*` — на чтение (rx). Сбрасывает счётчики nonce в 0 для обоих направлений.
    pub fn set_keys(
        &mut self,
        mut w_key: [u8; 32],
        w_iv: [u8; 12],
        mut r_key: [u8; 32],
        r_iv: [u8; 12],
    ) {
        self.tx = AeadStream::with_suite_and_legacy_chacha_aad(
            self.suite,
            &w_key,
            w_iv,
            self.legacy_chacha_aad,
        );
        self.rx = AeadStream::with_suite_and_legacy_chacha_aad(
            self.suite,
            &r_key,
            r_iv,
            self.legacy_chacha_aad,
        );
        // Ключи пришли по значению — это копии на стеке поверх тех, что уже
        // легли внутрь шифра. Свои копии затираем сразу: дальше они не нужны,
        // а `[u8; 32]` при выходе из области видимости не затирается сам.
        // IV затрутся вместе с `NonceState` предыдущих потоков (Drop выше).
        w_key.zeroize();
        r_key.zeroize();
        netrunner_logger::debug!("Cipher keys and IVs updated for both directions");
    }

    /// Разбирает шифр на два независимых потока `(rx, tx)`.
    ///
    /// Нужно, чтобы отдать чтение и запись в разные задачи tokio (reader/writer),
    /// не деля шифр под мьютексом — каждое направление владеет своим потоком.
    pub fn split(self) -> (AeadStream, AeadStream) {
        (self.rx, self.tx)
    }
}

pub(crate) type ChaChaStream = AeadStream;
pub(crate) type ChaChaCipher = SessionCipher;

#[cfg(all(test, feature = "ring-aead"))]
mod tests {
    use super::*;

    #[test]
    fn implicit_stream_rekey_is_synchronized_without_a_wire_marker() {
        let key = [0x41; 32];
        let iv = [0x27; 12];
        let mut tx = AeadStream::with_suite(AeadSuite::Aes128Gcm, &key, iv);
        let mut rx = AeadStream::with_suite(AeadSuite::Aes128Gcm, &key, iv);

        // Fast-forward both ordered directions to the rekey boundary. The next
        // record must transparently use the next key and nonce sequence.
        tx.records_in_epoch = STREAM_REKEY_AFTER_RECORDS;
        rx.records_in_epoch = STREAM_REKEY_AFTER_RECORDS;
        tx.state.counter = STREAM_REKEY_AFTER_RECORDS;
        rx.state.counter = STREAM_REKEY_AFTER_RECORDS;

        let mut record = BytesMut::from(&b"record after implicit update"[..]);
        tx.encrypt(&mut record).unwrap();
        rx.decrypt(&mut record).unwrap();
        assert_eq!(&record[..], b"record after implicit update");
        assert_eq!(tx.records_in_epoch, 1);
        assert_eq!(rx.records_in_epoch, 1);
    }

    #[test]
    fn ring_aes_gcm_round_trips_with_associated_data() {
        for suite in [AeadSuite::Aes128Gcm, AeadSuite::Aes256Gcm] {
            let key = [0x5a; 32];
            let nonce = [0x93; 12];
            let tx = AeadCipher::new(suite, &key).unwrap();
            let rx = AeadCipher::new(suite, &key).unwrap();
            let mut data = BytesMut::from(&b"ring data plane"[..]);
            tx.seal(nonce, b"nrxp header", &mut data).unwrap();
            rx.open(nonce, b"nrxp header", &mut data).unwrap();
            assert_eq!(&data[..], b"ring data plane");
        }
    }
}
