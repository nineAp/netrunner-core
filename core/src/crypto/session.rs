//! Оркестрация сессии: от хендшейка до пер-кадровой аутентификации.
//!
//! Файл связывает воедино [`ecdh`](super::ecdh) и [`hkdf`](super::hkdf) и делится
//! на две фазы, отражённые в коде комментариями-разделителями:
//!
//! 1. **Handshake / генерация ключей** ([`SaltPair`], [`SessionKeys`]).
//!    Стороны обмениваются солью и публичными ключами X25519 (внутри TLS-кадров
//!    `ClientHello`/`ServerHello`), затем независимо выводят один и тот же набор
//!    ключей: AEAD-ключ+IV на каждое направление и общий `auth_key`.
//!
//! 2. **Data phase / аутентификация кадров** ([`SessionAuth`]).
//!    Лёгкая копируемая структура с одним лишь `auth_key`, которую забирают
//!    кодеки. Считает и проверяет TOTP-подобный тег, привязанный ко времени, —
//!    защита от replay-атак на уровне DPI.
//!
//! ## Симметрия ролей
//!
//! Чтобы обе стороны вывели идентичные ключи, важен порядок конкатенации соли и
//! назначение направлений. Инициатор (клиент) и ответчик (сервер) собирают
//! «полную соль» в зеркальном порядке (см. [`SaltPair::get_total`]), а в
//! [`SessionKeys::generate_keys`] флаг `is_server` решает, какой из выведенных
//! ключей идёт на tx, а какой на rx.

use netrunner_logger::{AppError, ERR_NET_TLS_TAMPER};
use x25519_dalek::PublicKey;

use crate::{
    crypto::{ecdh::ECDH, hkdf::HKDF},
    net::{AUTH_TIME_STEP, AUTH_WINDOW_SIZE},
    tlseng::ExtensionStack,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use aead::{rand_core::RngCore, OsRng};

// ==========================================
// 1. HANDSHAKE (Генерация ключей)
// ==========================================

/// Пара солей сторон, используемая как salt в HKDF-Extract.
///
/// Каждая сторона генерирует случайную локальную соль и узнаёт удалённую из
/// хендшейка. Итоговая соль детерминированно собирается из обеих половин в
/// порядке, зависящем от роли (см. [`get_total`](SaltPair::get_total)), так что
/// клиент и сервер приходят к одному значению.
pub(crate) struct SaltPair {
    /// Своя случайная соль (32 байта), уходит удалённой стороне.
    local_salt: [u8; 32],
    /// Соль удалённой стороны; нули до вызова [`set_remote_salt`](SaltPair::set_remote_salt).
    remote_salt: [u8; 32],
    /// Роль: `true` у инициатора (клиента) — определяет порядок конкатенации.
    is_initiator: bool,
}

impl SaltPair {
    pub(crate) fn new(is_initiator: bool) -> Self {
        let mut local_salt = [0u8; 32];
        OsRng.fill_bytes(&mut local_salt);
        Self {
            local_salt,
            remote_salt: [0; 32],
            is_initiator,
        }
    }

    pub(crate) fn get_local(&self) -> [u8; 32] {
        self.local_salt
    }

    pub(crate) fn set_remote_salt(&mut self, salt: [u8; 32]) {
        self.remote_salt = salt
    }

    /// Собирает 64-байтовую «полную соль» для HKDF.
    ///
    /// Порядок зеркальный по ролям: инициатор кладёт `local || remote`, ответчик —
    /// `remote || local`. Благодаря этому обе стороны получают **одинаковый**
    /// буфер соли, хотя «локальное» и «удалённое» у них поменяны местами.
    pub(crate) fn get_total(&self) -> [u8; 64] {
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

/// Полное состояние криптографического хендшейка одной стороны.
///
/// Держит свою соль, эфемерный ECDH и — после [`update_keys`](SessionKeys::update_keys) —
/// выведенные ключи. Кортеж `current_aead` упакован как
/// `(tx_key, tx_iv, rx_key, rx_iv)` уже с учётом роли: его можно напрямую отдать
/// в [`ChaChaCipher::set_keys`](super::chacha::ChaChaCipher::set_keys).
pub struct SessionKeys {
    /// Пара солей (локальная + удалённая) для HKDF.
    salt: SaltPair,
    /// Эфемерный ключ X25519; расходуется при выводе общего секрета.
    ecdh: ECDH,
    /// Ключ для time-based аутентификации кадров (HMAC). Заполняется в HKDF-фазе.
    auth_key: [u8; 32],
    /// Выведенные AEAD-параметры `(tx_key, tx_iv, rx_key, rx_iv)`; `None` до хендшейка.
    current_aead: Option<([u8; 32], [u8; 12], [u8; 32], [u8; 12])>,
}

impl SessionKeys {
    pub(crate) fn new(is_initiator: bool) -> Self {
        Self {
            salt: SaltPair::new(is_initiator),
            ecdh: ECDH::new(),
            auth_key: [0u8; 32],
            current_aead: None,
        }
    }

    pub(crate) fn get_aead_parameters(&self) -> ([u8; 32], [u8; 12], [u8; 32], [u8; 12]) {
        self.current_aead
            .expect("Keys not generated yet. Call update_keys first.")
    }

    pub fn get_auth_key(&self) -> [u8; 32] {
        self.auth_key
    }

    /// Завершает хендшейк: принимает удалённую соль и публичный ключ из
    /// TLS-расширений, выводит все ключи сессии.
    ///
    /// Публичный ключ X25519 извлекается из расширения KeyShare (`0x0033`).
    /// Парсинг асимметричен: у сервера (`is_server`) `ClientHello` содержит список
    /// именованных групп, поэтому ключ ищется по маркеру `00 1d 00 20` (X25519,
    /// 32 байта); у клиента `ServerHello` отдаёт ровно один ключ по фиксированному
    /// смещению. Любая аномалия (короткий буфер, нет KeyShare, нулевой ключ)
    /// трактуется как [`ERR_NET_TLS_TAMPER`] — признак вмешательства/несовместимости.
    pub(crate) fn update_keys(
        &mut self,
        salt: [u8; 32],
        extensions: &ExtensionStack,
        is_server: bool,
    ) -> Result<([u8; 32], [u8; 12], [u8; 32], [u8; 12]), AppError> {
        self.salt.set_remote_salt(salt);

        netrunner_logger::debug!(
            remote_salt = %hex::encode(&salt[..8]),
            local_salt = %hex::encode(&self.salt.get_local()[..8]),
            total_salt = %hex::encode(&self.salt.get_total()[28..36]),
            "Updating keys with new salt"
        );

        const EXT_KEY_SHARE: u16 = 0x0033;

        if let Some(dh_data) = extensions.find_by_type(EXT_KEY_SHARE) {
            let mut key_bytes = [0u8; 32];

            if is_server {
                if dh_data.len() < 38 {
                    return Err(AppError::new(
                        ERR_NET_TLS_TAMPER,
                        "Ошибка маскировки",
                        format!("Client KeyShare too short: {}", dh_data.len()),
                    ));
                }

                let mut found = false;
                for i in 2..=(dh_data.len() - 34) {
                    if dh_data[i..i + 4] == [0x00, 0x1d, 0x00, 0x20] {
                        key_bytes.copy_from_slice(&dh_data[i + 4..i + 36]);
                        found = true;
                        break;
                    }
                }

                if !found {
                    return Err(AppError::new(
                        ERR_NET_TLS_TAMPER,
                        "Ошибка маскировки",
                        "Could not find x25519 key in ClientHello",
                    ));
                }
            } else {
                if dh_data.len() < 36 {
                    return Err(AppError::new(
                        ERR_NET_TLS_TAMPER,
                        "Ошибка маскировки",
                        "Server KeyShare too short",
                    ));
                }
                key_bytes.copy_from_slice(&dh_data[4..36]);
            }

            if key_bytes.iter().all(|&x| x == 0) {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка шифрования",
                    "Extracted remote public key is all ZEROS!",
                ));
            }

            let public_key = PublicKey::from(key_bytes);
            self.generate_keys(&public_key, is_server)
        } else {
            Err(AppError::new(
                ERR_NET_TLS_TAMPER,
                "Ошибка маскировки",
                "No KeyShare extension found in handshake",
            ))
        }
    }

    /// Низкоуровневый вывод ключей: ECDH → HKDF-Extract → пять HKDF-Expand.
    ///
    /// Из общего секрета и полной соли выводятся пять значений по фиксированным
    /// лейблам (`client_aead`, `client_iv`, `server_aead`, `server_iv`, `auth_key`).
    /// Затем `is_server` назначает направления: для сервера tx=`server_*`,
    /// rx=`client_*`, для клиента — наоборот. Так одна и та же пара ключей
    /// у клиента служит на запись, а у сервера — на чтение, и наоборот.
    fn generate_keys(
        &mut self,
        public_key: &PublicKey,
        is_server: bool,
    ) -> Result<([u8; 32], [u8; 12], [u8; 32], [u8; 12]), AppError> {
        let shared_key = self
            .ecdh
            .get_shared(public_key)
            .ok_or_else(|| AppError::new(ERR_NET_TLS_TAMPER, "Сбой", "No shared secret"))?;

        let hkdf = HKDF::extract_key(&self.salt.get_total(), &shared_key);

        let c_key = HKDF::expand_key::<32>(&hkdf, b"client_aead")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;
        let c_iv = HKDF::expand_key::<12>(&hkdf, b"client_iv")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;
        let s_key = HKDF::expand_key::<32>(&hkdf, b"server_aead")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;
        let s_iv = HKDF::expand_key::<12>(&hkdf, b"server_iv")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;

        self.auth_key = HKDF::expand_key::<32>(&hkdf, b"auth_key")
            .map_err(|e| AppError::new(ERR_NET_TLS_TAMPER, "Ошибка ключей", e))?;

        let keys = if is_server {
            (s_key, s_iv, c_key, c_iv)
        } else {
            (c_key, c_iv, s_key, s_iv)
        };

        self.current_aead = Some(keys);
        Ok(keys)
    }

    pub(crate) fn local_salt(&self) -> [u8; 32] {
        self.salt.get_local()
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.ecdh.public_key.to_bytes()
    }

    pub(crate) fn auth_key_fingerprint(&self) -> String {
        hex::encode(&self.auth_key[..4])
    }
}

// ==========================================
// 2. DATA PHASE (Авторизация Кодека)
// ==========================================

/// Лёгкий копируемый «аутентификатор кадров», который забирают `RxCodec`/`TxCodec`
/// после хендшейка.
///
/// Реализует TOTP-подобную схему: тег кадра = первые 16 байт
/// `HMAC-SHA256(auth_key, current_time_step)`, где `step = unix_secs /
/// AUTH_TIME_STEP`. Тег меняется каждые `AUTH_TIME_STEP` секунд, поэтому
/// записанный ранее DPI-перехват нельзя «переиграть» позже — окно валидности
/// уезжает. Допуск на рассинхрон часов задаётся `AUTH_WINDOW_SIZE`.
/// Текущее unix-время в секундах — `std::time::SystemTime::now()` panics with
/// "time not implemented on this platform" on wasm32-unknown-unknown (no OS
/// clock syscall there), which is exactly the target `client-edge`
/// (Cloudflare Workers) builds for. `web-time` is an API-compatible drop-in
/// backed by JS `Date.now()` on that target only; native targets keep using
/// `std::time` unchanged.
#[cfg(target_arch = "wasm32")]
fn now_unix_secs() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // NTP step-back can make this return Err; saturate to 0. Both call
        // sites tolerate this: generate_current_tag just produces a tag for
        // step 0, and verify_tag's window comparison will simply fail and
        // log AUTH MISMATCH rather than panicking.
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy)]
pub struct SessionAuth {
    auth_key: [u8; 32],
}

impl SessionAuth {
    pub fn new(auth_key: [u8; 32]) -> Self {
        Self { auth_key }
    }

    /// Чистая функция: тег для конкретного временного шага `step`.
    ///
    /// Вынесена отдельно, чтобы и генерация, и проверка считали тег одинаково.
    pub fn compute_tag(secret: &[u8], step: u64) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC error");
        mac.update(&step.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result[..16]);
        tag
    }

    /// Тег для текущего момента времени — кладётся в исходящий кадр.
    pub fn generate_current_tag(&self) -> [u8; 16] {
        let now = now_unix_secs();

        Self::compute_tag(&self.auth_key, now / AUTH_TIME_STEP)
    }

    /// Проверяет тег входящего кадра против окна `[step-W .. step+W]`.
    ///
    /// # Инвариант безопасности (НЕ ЛОМАТЬ)
    ///
    /// Цикл **всегда** прогоняет все `2*AUTH_WINDOW_SIZE + 1` кандидатов и
    /// сравнивает теги побайтово через накопление `diff |= a ^ b`, без раннего
    /// `break` и без ветвления по результату внутри цикла. Это постоянное по
    /// времени сравнение: длительность `verify_tag` не зависит от того, какой шаг
    /// (и совпал ли вообще) подошёл, иначе по таймингу можно подбирать тег.
    pub fn verify_tag(&self, received_tag: &[u8; 16]) -> bool {
        let now = now_unix_secs();

        let current_step = now / AUTH_TIME_STEP;

        // Constant-time path: always evaluate ALL 2*AUTH_WINDOW_SIZE+1 candidates
        // so the loop duration doesn't leak which step (if any) matched.
        let mut matched_step: Option<u64> = None;
        for step in (current_step.saturating_sub(AUTH_WINDOW_SIZE))
            ..=(current_step.saturating_add(AUTH_WINDOW_SIZE))
        {
            let candidate = Self::compute_tag(&self.auth_key, step);
            let mut diff = 0u8;
            for (a, b) in candidate.iter().zip(received_tag.iter()) {
                diff |= a ^ b;
            }
            if diff == 0 && matched_step.is_none() {
                matched_step = Some(step);
                // Do NOT break — iterate full window for constant time.
            }
        }

        match matched_step {
            Some(step) => {
                if step != current_step {
                    netrunner_logger::debug!(expected = %current_step, matched = %step, "Auth tag valid with time offset");
                }
                true
            }
            None => {
                netrunner_logger::warn!(
                    current_step = %current_step,
                    "AUTH MISMATCH: All tags rejected for current window"
                );
                false
            }
        }
    }
}
