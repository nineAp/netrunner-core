//! Абстракция проверки клиентского токена и учёта расхода трафика на
//! control-plane бэкенде. Ядро знает только этот трейт — конкретную реализацию
//! (HTTP-клиент к `netrunner-backend`) даёт связывающий бинарь (`netrunner-server`),
//! чтобы ядро не тянуло HTTP-клиент как обязательную зависимость.
//!
//! Включается/выключается на инстанс целиком через `--require-auth` (см.
//! `server/src/main.rs`): если сервер запущен без флага, [`ServerHandler`]
//! вообще не спрашивает валидатор, и поведение не отличается от того, что
//! было до этой фичи.

use async_trait::async_trait;
use netrunner_logger::AppError;

/// Результат успешной проверки токена клиента.
#[derive(Debug, Clone)]
pub struct UserQuota {
    pub user_id: String,
    /// `None` — безлимит.
    pub limit_bytes: Option<u64>,
    pub used_bytes: u64,
}

/// Ответ на отчёт о расходе трафика.
#[derive(Debug, Clone)]
pub struct UsageReport {
    pub used_bytes: u64,
    pub limit_bytes: Option<u64>,
    pub over_limit: bool,
}

#[async_trait]
pub trait AuthValidator: Send + Sync {
    /// Проверяет Bearer-токен клиента (JWT, выданный бэкендом при логине).
    async fn validate(&self, token: &str) -> Result<UserQuota, AppError>;
    /// Отчитывается о переданных байтах и синхронно узнаёт, не превышен ли лимит.
    async fn report_usage(&self, user_id: &str, delta_bytes: u64) -> Result<UsageReport, AppError>;
}
