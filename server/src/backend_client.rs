//! HTTP-клиент к control-plane бэкенду (`netrunner-backend`), реализующий
//! [`AuthValidator`] для ядра — только эта нода тянет `reqwest` и
//! `PROXY_INTERNAL_SECRET`, ядро видит лишь трейт (см. `core::net::auth`).
//!
//! Валидация токена кешируется на короткий TTL: одна сессия открывает
//! [`MAX_TUNNEL_LEGS`] ног, и без кеша каждая била бы бэкенд отдельным
//! запросом на один и тот же токен.

use async_trait::async_trait;
use dashmap::DashMap;
use netrunner_core::net::{AuthValidator, NodeHealthReport, UsageReport, UserQuota};
use netrunner_logger::{warn, AppError};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const VALIDATE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Таймаут одного HTTP-запроса к бэкенду. Без него `reqwest::Client` ждёт
/// ответ неограниченно долго на зависшем (не упавшем — именно зависшем)
/// бэкенде: каждая проверка токена на КАЖДОМ новом клиенте висела бы, блокируя
/// подключение новых пользователей, а не только тех, чей токен уже в кеше.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// После скольких подряд неудач (сетевая ошибка/таймаут/5xx — НЕ 4xx, отказ
/// по конкретному токену не значит, что бэкенд нездоров) размыкаем цепь.
const FAILURE_THRESHOLD: u32 = 5;
/// Сколько цепь остаётся разомкнутой (запросы отклоняются мгновенно, без
/// попытки реального HTTP-вызова и его таймаута) перед следующей пробой.
const CIRCUIT_OPEN_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Default)]
struct CircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// Простейший circuit breaker: без внешней библиотеки, состояние — один
/// `Mutex` с редкими короткими блокировками (проверка/запись пары полей,
/// не сам HTTP-вызов). Цель — не ждать `REQUEST_TIMEOUT` на каждом клиенте
/// подряд, если бэкенд уже несколько раз подряд не ответил, а быстро
/// отказывать, пока не пройдёт cooldown.
struct Circuit {
    state: Mutex<CircuitState>,
}

impl Circuit {
    fn new() -> Self {
        Self {
            state: Mutex::new(CircuitState::default()),
        }
    }

    /// `true`, если цепь разомкнута прямо сейчас — вызывающий код должен
    /// отказать быстро, не делая реальный HTTP-запрос.
    fn is_open(&self) -> bool {
        let state = self.state.lock().unwrap();
        matches!(state.open_until, Some(until) if Instant::now() < until)
    }

    fn record_success(&self) {
        let mut state = self.state.lock().unwrap();
        state.consecutive_failures = 0;
        state.open_until = None;
        metrics::gauge!("netrunner_circuit_breaker_open").set(0.0);
    }

    /// Считать неудачей только сетевые ошибки/таймауты/5xx — HTTP 401/403 на
    /// конкретный невалидный токен НЕ признак нездоровья бэкенда.
    fn record_failure(&self) {
        let mut state = self.state.lock().unwrap();
        state.consecutive_failures += 1;
        if state.consecutive_failures >= FAILURE_THRESHOLD {
            state.open_until = Some(Instant::now() + CIRCUIT_OPEN_COOLDOWN);
            metrics::gauge!("netrunner_circuit_breaker_open").set(1.0);
            warn!(
                failures = state.consecutive_failures,
                "Circuit breaker разомкнут: бэкенд не отвечает {} раз подряд",
                state.consecutive_failures
            );
        }
    }
}

pub struct BackendClient {
    http: reqwest::Client,
    base_url: String,
    internal_secret: String,
    validate_cache: DashMap<String, (UserQuota, Instant)>,
    circuit: Circuit,
}

impl BackendClient {
    pub fn new(base_url: String, internal_secret: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("Failed to build reqwest client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            internal_secret,
            validate_cache: DashMap::new(),
            circuit: Circuit::new(),
        }
    }

    fn circuit_open_error() -> AppError {
        AppError::new(
            netrunner_logger::ERR_INFRA_TIMEOUT,
            "Бэкенд недоступен",
            "Circuit breaker open: backend недавно не отвечал несколько раз подряд, короткий отказ без повторной попытки",
        )
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
            metrics::counter!("netrunner_auth_failures_total").increment(1);
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

        if self.circuit.is_open() {
            return Err(Self::circuit_open_error());
        }

        let request_start = Instant::now();
        let resp = self
            .http
            .post(format!("{}/api/v1/internal/validate", self.base_url))
            .header("X-Internal-Secret", &self.internal_secret)
            .json(&ValidateRequest { token })
            .send()
            .await
            .map_err(|e| {
                self.circuit.record_failure();
                AppError::new(
                    netrunner_logger::ERR_INFRA_TIMEOUT,
                    "Бэкенд недоступен",
                    e.to_string(),
                )
            })?;
        metrics::histogram!("netrunner_auth_validate_duration_seconds")
            .record(request_start.elapsed().as_secs_f64());

        // 5xx — признак нездоровья самого бэкенда, считается неудачей для
        // circuit breaker'а. 4xx (например 401 на невалидный токен) — это
        // ожидаемый легитимный ответ на конкретный запрос, не поломка бэкенда.
        if resp.status().is_server_error() {
            self.circuit.record_failure();
        }
        if !resp.status().is_success() {
            metrics::counter!("netrunner_auth_failures_total").increment(1);
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

        self.circuit.record_success();
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
        if self.circuit.is_open() {
            return Err(Self::circuit_open_error());
        }

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
                self.circuit.record_failure();
                AppError::new(
                    netrunner_logger::ERR_INFRA_TIMEOUT,
                    "Бэкенд недоступен",
                    e.to_string(),
                )
            })?;

        if resp.status().is_server_error() {
            self.circuit.record_failure();
        }
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

        self.circuit.record_success();
        Ok(UsageReport {
            used_bytes: body.used_bytes,
            limit_bytes: body.limit_bytes,
            over_limit: body.over_limit,
        })
    }

    /// Пушит агрегированный, полностью анонимный снимок состояния ноды на
    /// control-plane — единая точка сбора вместо локальных файлов на диске
    /// ноды (см. doc-комментарий на `NodeHealthReport`). Best-effort: не идёт
    /// через circuit breaker и не ретраит — телеметрия, а не критичный путь;
    /// пропуск одного тика ничего не ломает, а следующий тик придёт через
    /// TOPOLOGY_PRINT_INTERVAL.
    async fn report_node_health(&self, report: NodeHealthReport) -> Result<(), AppError> {
        let resp = self
            .http
            .post(format!("{}/api/v1/internal/node-health", self.base_url))
            .header("X-Internal-Secret", &self.internal_secret)
            .json(&report)
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
                format!("Node health report rejected: HTTP {}", resp.status()),
            ));
        }
        Ok(())
    }
}
