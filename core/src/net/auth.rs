//! Абстракция проверки клиентского токена и учёта расхода трафика на
//! control-plane бэкенде. Ядро знает только этот трейт — конкретную реализацию
//! (HTTP-клиент к `netrunner-backend`) даёт связывающий бинарь (`netrunner-server`),
//! чтобы ядро не тянуло HTTP-клиент как обязательную зависимость.
//!
//! Включается/выключается на инстанс целиком через `--require-auth` (см.
//! `server/src/main.rs`): если сервер запущен без флага, [`ServerHandler`]
//! вообще не спрашивает валидатор, и поведение не отличается от того, что
//! было до этой фичи.

use crate::net::diagnostics::ErrorCounters;
use async_trait::async_trait;
use netrunner_logger::AppError;

/// Public connection data for one node in the mesh. The control plane returns
/// only nodes that are eligible to receive an egress hop; node-to-node data
/// still travels directly between the peers.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct MeshPeer {
    pub node_id: String,
    pub host: String,
    pub port: u16,
    pub decoy_sni: String,
    pub nrxp_secret: String,
    pub nrxp_static_public: String,
}

impl std::fmt::Debug for MeshPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshPeer")
            .field("node_id", &self.node_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("decoy_sni", &self.decoy_sni)
            .field("nrxp_secret", &"[REDACTED]")
            .field("nrxp_static_public", &self.nrxp_static_public)
            .finish()
    }
}

impl MeshPeer {
    pub fn address(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

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

/// Агрегированный, полностью анонимный снимок состояния ноды — ровно то, что
/// нужно для поддержания туннеля (жива ли нода, сколько сейчас соединений,
/// сколько трафика прошло суммарно, были ли ошибки), и НИЧЕГО о конкретных
/// клиентах: ни IP, ни хостов назначения, ни user_id. Заменяет локальные
/// JSON/JSONL-файлы на диске ноды (см. историю инцидентов на proxy-fr1) —
/// периодически пушится на control-plane вместо того, чтобы копиться на
/// диске самой ноды.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeHealthReport {
    pub active_sessions: usize,
    pub active_legs: usize,
    pub active_streams: usize,
    pub bytes_up_total_mb: f64,
    pub bytes_down_total_mb: f64,
    pub error_totals: ErrorCounters,
    pub uptime_secs: u64,
}

#[async_trait]
pub trait AuthValidator: Send + Sync {
    /// Проверяет Bearer-токен клиента (JWT, выданный бэкендом при логине).
    async fn validate(&self, token: &str) -> Result<UserQuota, AppError>;
    /// Отчитывается о переданных байтах и синхронно узнаёт, не превышен ли лимит.
    async fn report_usage(&self, user_id: &str, delta_bytes: u64) -> Result<UsageReport, AppError>;
    /// Отправляет агрегированный снимок состояния ноды на control-plane —
    /// единая точка сбора вместо локальных файлов на диске ноды.
    async fn report_node_health(&self, report: NodeHealthReport) -> Result<(), AppError>;

    /// Returns the current online mesh peers for this node. Older validators
    /// can omit mesh support; the server then leaves mesh routing disabled.
    async fn list_mesh_peers(&self) -> Result<Vec<MeshPeer>, AppError> {
        Err(AppError::new(
            netrunner_logger::ERR_AUTH_FAILED,
            "Mesh unavailable",
            "Mesh peer discovery is not configured",
        ))
    }

    /// Confirms that `peer_id` is an active node allowed to use this node as
    /// an egress. The node secret is sent only inside the authenticated NRXP
    /// tunnel, then verified by the control plane over its internal API.
    async fn validate_mesh_peer(&self, _peer_id: &str, _peer_secret: &str) -> Result<(), AppError> {
        Err(AppError::new(
            netrunner_logger::ERR_AUTH_FAILED,
            "Mesh peer rejected",
            "Mesh peer validation is not configured",
        ))
    }
}
