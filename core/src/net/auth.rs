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
use std::collections::HashMap;

pub const MAX_MESH_HOPS: u8 = 8;
pub const MESH_ROUTE_READY: &[u8] = b"NRXP-MESH2-READY";
pub const MESH_ONION_READY: &[u8] = b"NRXP-MESH-ONION1-READY";
/// Internal stream-setup failure propagated from an exhausted egress chain.
pub const MESH_EGRESS_EXHAUSTED: &[u8] = b"NRXP-MESH-EGRESS-EXHAUSTED";
pub(crate) const ERR_MESH_EGRESS_EXHAUSTED: &str = "MESH_EGRESS_EXHAUSTED";

/// Client preference for how the ingress should route its traffic. The server's
/// `--mesh-max-hops` is always a hard upper bound; `ServerDefault` preserves the
/// node's existing policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MeshRoutePreference {
    #[default]
    ServerDefault,
    Direct,
    TwoHop,
    RandomUpTo(u8),
}

impl MeshRoutePreference {
    /// Parse the stable app/FFI values. Unknown values keep server policy.
    pub fn from_config(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("direct") => Self::Direct,
            Some("two-hop") => Self::TwoHop,
            Some(value) => value
                .strip_prefix("x-hop-")
                .and_then(|hops| hops.parse::<u8>().ok())
                .filter(|hops| (3..=MAX_MESH_HOPS).contains(hops))
                .map(Self::RandomUpTo)
                .unwrap_or_default(),
            None => Self::ServerDefault,
        }
    }

    /// Clamp the requested cap to the node's configured maximum.
    pub fn effective_max_hops(self, server_max_hops: u8) -> u8 {
        let server_max_hops = server_max_hops.clamp(1, MAX_MESH_HOPS);
        match self {
            Self::ServerDefault => server_max_hops,
            Self::Direct => 1,
            Self::TwoHop => 2.min(server_max_hops),
            Self::RandomUpTo(requested) if (3..=MAX_MESH_HOPS).contains(&requested) => {
                requested.min(server_max_hops)
            }
            Self::RandomUpTo(_) => server_max_hops,
        }
    }

    pub(crate) fn wire_codes(self) -> (u8, u8) {
        match self {
            Self::ServerDefault => (0, 0),
            Self::Direct => (1, 1),
            Self::TwoHop => (2, 2),
            Self::RandomUpTo(hops) if (3..=MAX_MESH_HOPS).contains(&hops) => (3, hops),
            Self::RandomUpTo(_) => (0, 0),
        }
    }

    pub(crate) fn from_wire_codes(mode: u8, hops: u8) -> Option<Self> {
        match (mode, hops) {
            (0, 0) => Some(Self::ServerDefault),
            (1, 1) => Some(Self::Direct),
            (2, 2) => Some(Self::TwoHop),
            (3, hops) if (3..=MAX_MESH_HOPS).contains(&hops) => Some(Self::RandomUpTo(hops)),
            _ => None,
        }
    }
}

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
    if token.len() > 1024
        && (token.starts_with("mesh:")
            || token.starts_with("mesh2:")
            || token.starts_with("mesh3:")
            || token.starts_with("mesh4:"))
    {
        return Err("mesh credential exceeds the maximum size");
    }
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

        if !valid_mesh_node_id(peer_id)
            || !valid_mesh_peer_secret(peer_secret)
            || visited.is_empty()
        {
            return Err("incomplete mesh peer credentials or route");
        }
        if remaining_hops == 0 || remaining_hops > MAX_MESH_HOPS {
            return Err("mesh hop budget is outside the allowed range");
        }
        let route_size = remaining_hops as usize + visited.len().saturating_sub(1);
        if route_size > MAX_MESH_HOPS as usize || visited.len() > MAX_MESH_HOPS as usize {
            return Err("mesh route exceeds the maximum hop count");
        }
        if visited.iter().any(|node_id| !valid_mesh_node_id(node_id)) {
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
        if !valid_mesh_node_id(peer_id) || !valid_mesh_peer_secret(peer_secret) {
            return Err("incomplete mesh peer credentials");
        }
        return Ok(Some(MeshAuth {
            peer_id: peer_id.to_owned(),
            peer_secret: peer_secret.to_owned(),
            route: None,
        }));
    }

    // mesh4 carries no route, egress ID, or visited list. Per-stream route
    // instructions arrive separately as HPKE onion capsules.
    if let Some(claim) = token.strip_prefix("mesh4:") {
        let (peer_id, peer_secret) = claim
            .split_once(':')
            .ok_or("malformed mesh peer credentials")?;
        if !valid_mesh_node_id(peer_id) || !valid_mesh_peer_secret(peer_secret) {
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

fn valid_mesh_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn valid_mesh_peer_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
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

/// One user's byte delta accumulated since the previous usage report tick.
pub type UsageDelta = (String, u64);

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
    /// Проверяет токен узла, который хочет быть reverse-egress (выходом для клиентов этого ingress).
    /// По умолчанию — отказ: роль выдаётся явно, обычный клиентский токен её не даёт
    /// (иначе любой клиент мог бы перехватывать чужой трафик, назначив себя выходом).
    async fn validate_egress(&self, _token: &str) -> Result<UserQuota, AppError> {
        Err(AppError::new(
            netrunner_logger::ERR_AUTH_FAILED,
            "Доступ запрещен",
            "This validator does not grant the reverse-egress role",
        ))
    }
    /// Отчитывается о переданных байтах и синхронно узнаёт, не превышен ли лимит.
    async fn report_usage(&self, user_id: &str, delta_bytes: u64) -> Result<UsageReport, AppError>;
    /// Отчитывается о нескольких пользователях одним идемпотентным пакетом.
    async fn report_usage_batch(
        &self,
        batch_id: &str,
        deltas: &[UsageDelta],
    ) -> Result<HashMap<String, UsageReport>, AppError>;
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

#[cfg(test)]
mod mesh_auth_token_tests {
    use super::{parse_mesh_auth_token, MeshRoutePreference, MeshRouteSelection};

    #[test]
    fn route_preferences_parse_and_obey_server_hop_cap() {
        assert_eq!(
            MeshRoutePreference::from_config(None),
            MeshRoutePreference::ServerDefault
        );
        assert_eq!(
            MeshRoutePreference::from_config(Some("direct")),
            MeshRoutePreference::Direct
        );
        assert_eq!(
            MeshRoutePreference::from_config(Some("two-hop")),
            MeshRoutePreference::TwoHop
        );
        assert_eq!(
            MeshRoutePreference::from_config(Some("x-hop-5")),
            MeshRoutePreference::RandomUpTo(5)
        );
        assert_eq!(
            MeshRoutePreference::from_config(Some("x-hop-9")),
            MeshRoutePreference::ServerDefault
        );

        assert_eq!(MeshRoutePreference::Direct.effective_max_hops(8), 1);
        assert_eq!(MeshRoutePreference::TwoHop.effective_max_hops(8), 2);
        assert_eq!(MeshRoutePreference::TwoHop.effective_max_hops(1), 1);
        assert_eq!(MeshRoutePreference::RandomUpTo(5).effective_max_hops(3), 3);
        assert_eq!(MeshRoutePreference::RandomUpTo(5).effective_max_hops(8), 5);
        assert_eq!(MeshRoutePreference::ServerDefault.effective_max_hops(5), 5);
    }

    #[test]
    fn route_preferences_have_strict_wire_encoding() {
        for preference in [
            MeshRoutePreference::ServerDefault,
            MeshRoutePreference::Direct,
            MeshRoutePreference::TwoHop,
            MeshRoutePreference::RandomUpTo(3),
            MeshRoutePreference::RandomUpTo(8),
        ] {
            assert_eq!(
                MeshRoutePreference::from_wire_codes(
                    preference.wire_codes().0,
                    preference.wire_codes().1
                ),
                Some(preference)
            );
        }
        for (mode, hops) in [(0, 1), (1, 0), (2, 3), (3, 2), (3, 9), (4, 4)] {
            assert!(MeshRoutePreference::from_wire_codes(mode, hops).is_none());
        }
    }

    #[test]
    fn accepts_legacy_and_versioned_mesh_claims() {
        let legacy = parse_mesh_auth_token("mesh:node-a:secret")
            .unwrap()
            .unwrap();
        assert_eq!(legacy.peer_id, "node-a");
        assert!(legacy.route.is_none());

        let mesh4 = parse_mesh_auth_token("mesh4:node-a:secret")
            .unwrap()
            .unwrap();
        assert_eq!(mesh4.peer_id, "node-a");
        assert!(mesh4.route.is_none());

        let mesh2 = parse_mesh_auth_token("mesh2:node-a:secret:2:weighted-random:node-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            mesh2.route.unwrap().selection,
            MeshRouteSelection::WeightedRandom
        );

        let mesh3 =
            parse_mesh_auth_token("mesh3:node-b:secret:2:weighted-random:node-c:node-a,node-b")
                .unwrap()
                .unwrap();
        let route = mesh3.route.unwrap();
        assert_eq!(route.egress_node_id.as_deref(), Some("node-c"));
        assert_eq!(route.visited, ["node-a", "node-b"]);

        let final_hop = parse_mesh_auth_token(
            "mesh3:node-b:secret:1:weighted-random:node-c:node-a,node-b,node-c",
        )
        .unwrap()
        .unwrap();
        assert_eq!(final_hop.route.unwrap().remaining_hops, 1);
        assert!(parse_mesh_auth_token("a.valid.client.token")
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_loops_invalid_egress_and_out_of_range_claims() {
        for claim in [
            "mesh2:node-a:secret:2:nearest:node-a,Node-A",
            "mesh3:node-a:secret:2:nearest:node-a:node-a,node-b",
            "mesh3:node-a:secret:2:nearest:node-c:node-a,node-c",
            "mesh3:node-a:secret:1:nearest:node-c:node-a,node-b",
            "mesh2:node-a:secret:0:nearest:node-a",
            "mesh2:node-a:secret:9:nearest:node-a",
            "mesh2:node-a:secret:2:unknown:node-a",
            "mesh2:node/a:secret:2:nearest:node-a",
        ] {
            assert!(parse_mesh_auth_token(claim).is_err(), "accepted {claim}");
        }
    }

    #[test]
    fn rejects_unbounded_peer_credentials_and_claims() {
        let long_secret = "s".repeat(129);
        let long_node_id = "n".repeat(65);
        assert!(parse_mesh_auth_token(&format!("mesh:node:{long_secret}")).is_err());
        assert!(parse_mesh_auth_token(&format!("mesh:{long_node_id}:secret")).is_err());
        assert!(parse_mesh_auth_token(&format!("mesh:{}", "x".repeat(1025))).is_err());
        assert!(parse_mesh_auth_token(&"opaque-client-token".repeat(100))
            .unwrap()
            .is_none());
    }
}
