//! HTTP-клиент к control-plane бэкенду (`netrunner-backend`), реализующий
//! [`AuthValidator`] для ядра — только эта нода тянет `reqwest` и
//! `PROXY_INTERNAL_SECRET`, ядро видит лишь трейт (см. `core::net::auth`).
//!
//! Валидация токена кешируется на короткий TTL: одна сессия открывает
//! [`MAX_TUNNEL_LEGS`] ног, и без кеша каждая била бы бэкенд отдельным
//! запросом на один и тот же токен.

use async_trait::async_trait;
use dashmap::DashMap;
use netrunner_core::net::{AuthValidator, UsageReport, UserQuota};
use netrunner_logger::AppError;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const VALIDATE_CACHE_TTL: Duration = Duration::from_secs(60);

pub struct BackendClient {
    http: reqwest::Client,
    base_url: String,
    internal_secret: String,
    validate_cache: DashMap<String, (UserQuota, Instant)>,
}

impl BackendClient {
    pub fn new(base_url: String, internal_secret: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            internal_secret,
            validate_cache: DashMap::new(),
        }
    }
}

#[derive(Serialize)]
struct ValidateRequest<'a> {
    token: &'a str,
}

#[derive(Deserialize)]
struct ValidateResponse {
    user_id: String,
    limit_bytes: Option<u64>,
    used_bytes: u64,
}

#[derive(Serialize)]
struct UsageRequest<'a> {
    user_id: &'a str,
    delta_bytes: u64,
}

#[derive(Deserialize)]
struct UsageResponse {
    used_bytes: u64,
    limit_bytes: Option<u64>,
    over_limit: bool,
}

#[async_trait]
impl AuthValidator for BackendClient {
    async fn validate(&self, token: &str) -> Result<UserQuota, AppError> {
        if token.is_empty() {
            return Err(AppError::new(
                netrunner_logger::ERR_AUTH_FAILED,
                "Доступ запрещен",
                "Empty auth token on a --require-auth instance",
            ));
        }

        if let Some(entry) = self.validate_cache.get(token) {
            let (quota, cached_at) = entry.value();
            if cached_at.elapsed() < VALIDATE_CACHE_TTL {
                return Ok(quota.clone());
            }
        }

        let resp = self
            .http
            .post(format!("{}/api/v1/internal/validate", self.base_url))
            .header("X-Internal-Secret", &self.internal_secret)
            .json(&ValidateRequest { token })
            .send()
            .await
            .map_err(|e| {
                AppError::new(
                    netrunner_logger::ERR_INFRA_TIMEOUT,
                    "Бэкенд недоступен",
                    e.to_string(),
                )
            })?;

        if !resp.status().is_success() {
            return Err(AppError::new(
                netrunner_logger::ERR_AUTH_FAILED,
                "Доступ запрещен",
                format!("Backend rejected token: HTTP {}", resp.status()),
            ));
        }

        let body: ValidateResponse = resp.json().await.map_err(|e| {
            AppError::new(
                netrunner_logger::ERR_INFRA_TIMEOUT,
                "Ошибка бэкенда",
                e.to_string(),
            )
        })?;

        let quota = UserQuota {
            user_id: body.user_id,
            limit_bytes: body.limit_bytes,
            used_bytes: body.used_bytes,
        };
        self.validate_cache
            .insert(token.to_string(), (quota.clone(), Instant::now()));
        Ok(quota)
    }

    async fn report_usage(&self, user_id: &str, delta_bytes: u64) -> Result<UsageReport, AppError> {
        let resp = self
            .http
            .post(format!("{}/api/v1/internal/usage", self.base_url))
            .header("X-Internal-Secret", &self.internal_secret)
            .json(&UsageRequest {
                user_id,
                delta_bytes,
            })
            .send()
            .await
            .map_err(|e| {
                AppError::new(
                    netrunner_logger::ERR_INFRA_TIMEOUT,
                    "Бэкенд недоступен",
                    e.to_string(),
                )
            })?;

        if !resp.status().is_success() {
            return Err(AppError::new(
                netrunner_logger::ERR_INFRA_TIMEOUT,
                "Ошибка бэкенда",
                format!("Usage report rejected: HTTP {}", resp.status()),
            ));
        }

        let body: UsageResponse = resp.json().await.map_err(|e| {
            AppError::new(
                netrunner_logger::ERR_INFRA_TIMEOUT,
                "Ошибка бэкенда",
                e.to_string(),
            )
        })?;

        Ok(UsageReport {
            used_bytes: body.used_bytes,
            limit_bytes: body.limit_bytes,
            over_limit: body.over_limit,
        })
    }
}
