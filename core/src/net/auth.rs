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

pub const MAX_MESH_HOPS: u8 = 8;
pub const MESH_ROUTE_READY: &[u8] = b"NRXP-MESH2-READY";

/// How the next peer is selected for a stream route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshRouteSelection {
    Nearest,
    WeightedRandom,
}

impl MeshRouteSelection {
    pub(crate) fn as_wire_value(self) -> &'static str {
        match self {
            Self::Nearest => "nearest",
            Self::WeightedRandom => "weighted-random",
        }
    }

    fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "nearest" => Some(Self::Nearest),
            "weighted-random" => Some(Self::WeightedRandom),
            _ => None,
        }
    }
}

/// Stream-scoped route. `remaining_hops` includes the node that receives this
/// route; `visited` includes the originating ingress and every node selected so
/// far. New mesh3 routes also carry the egress selected by the ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshRoute {
    pub remaining_hops: u8,
    pub selection: MeshRouteSelection,
    /// Exit selected by the ingress for this flow. `None` is retained for
    /// legacy mesh2 routes and older nearest-egress routes.
    pub egress_node_id: Option<String>,
    pub visited: Vec<String>,
}

#[derive(Debug)]
pub struct MeshAuth {
    pub peer_id: String,
    pub peer_secret: String,
    pub route: Option<MeshRoute>,
}

/// Parse peer authentication carried inside an encrypted NRXP session.
/// `mesh:` remains supported for old nodes and means a direct egress. `mesh2:`
/// carries a hop budget and loop-prevention path. `mesh3:` additionally pins
/// the selected egress for one flow.
pub fn parse_mesh_auth_token(token: &str) -> Result<Option<MeshAuth>, &'static str> {
    let versioned_claim = token
        .strip_prefix("mesh3:")
        .map(|claim| (claim, true))
        .or_else(|| token.strip_prefix("mesh2:").map(|claim| (claim, false)));
    if let Some((claim, has_pinned_egress)) = versioned_claim {
        let mut fields = claim.splitn(if has_pinned_egress { 6 } else { 5 }, ':');
        let peer_id = fields.next().unwrap_or_default();
        let peer_secret = fields.next().unwrap_or_default();
        let remaining_hops = fields
            .next()
            .and_then(|value| value.parse::<u8>().ok())
            .ok_or("invalid mesh hop budget")?;
        let selection = fields
            .next()
            .and_then(MeshRouteSelection::from_wire_value)
            .ok_or("invalid mesh route selection")?;
        let egress_node_id = if has_pinned_egress {
            let value = fields.next().unwrap_or_default();
            if value.is_empty()
                || value.len() > 64
                || !value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
            {
                return Err("mesh route contains an invalid egress node id");
            }
            Some(value.to_owned())
        } else {
            None
        };
        let visited = fields
            .next()
            .ok_or("missing mesh route path")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();

        if peer_id.is_empty() || peer_secret.is_empty() || visited.is_empty() {
            return Err("incomplete mesh peer credentials or route");
        }
        if remaining_hops == 0 || remaining_hops > MAX_MESH_HOPS {
            return Err("mesh hop budget is outside the allowed range");
        }
        let route_size = remaining_hops as usize + visited.len().saturating_sub(1);
        if route_size > MAX_MESH_HOPS as usize || visited.len() > MAX_MESH_HOPS as usize {
            return Err("mesh route exceeds the maximum hop count");
        }
        if visited.iter().any(|node_id| {
            node_id.is_empty()
                || node_id.len() > 64
                || !node_id
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        }) {
            return Err("mesh route contains an invalid node id");
        }
        for (index, node_id) in visited.iter().enumerate() {
            if visited[..index]
                .iter()
                .any(|previous| previous.eq_ignore_ascii_case(node_id))
            {
                return Err("mesh route contains a loop");
            }
        }
        if let Some(egress) = egress_node_id.as_ref() {
            let egress_is_last = visited
                .last()
                .is_some_and(|visited_node| visited_node.eq_ignore_ascii_case(egress));
            let egress_was_visited_early = visited[..visited.len().saturating_sub(1)]
                .iter()
                .any(|visited_node| visited_node.eq_ignore_ascii_case(egress));
            if egress_was_visited_early
                || (remaining_hops == 1 && !egress_is_last)
                || (remaining_hops > 1 && egress_is_last)
            {
                return Err("mesh route egress does not match the path");
            }
        }

        return Ok(Some(MeshAuth {
            peer_id: peer_id.to_owned(),
            peer_secret: peer_secret.to_owned(),
            route: Some(MeshRoute {
                remaining_hops,
                selection,
                egress_node_id,
                visited,
            }),
        }));
    }

    if let Some(claim) = token.strip_prefix("mesh:") {
        let (peer_id, peer_secret) = claim
            .split_once(':')
            .ok_or("malformed mesh peer credentials")?;
        if peer_id.is_empty() || peer_secret.is_empty() {
            return Err("incomplete mesh peer credentials");
        }
        return Ok(Some(MeshAuth {
            peer_id: peer_id.to_owned(),
            peer_secret: peer_secret.to_owned(),
            route: None,
        }));
    }

    Ok(None)
}

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
