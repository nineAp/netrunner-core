//! # Каталог узлов без панели (этап A децентрализации)
//!
//! Узлы знают друг о друге из подписанных самоописаний ([`descriptor`]), хранят их
//! по ограниченным правилам допуска ([`store`]) и обмениваются ими по уже
//! аутентифицированным mesh-сессиям ([`gossip`]). Панель остаётся для учётных
//! записей и биллинга, но не нужна для того, чтобы узел нашёл соседей.
//!
//! Подробности, модель угроз и дальнейшие этапы — `docs/DECENTRALIZATION.md`.
//!
//! ```text
//!   seed-узлы ─▶ Directory ◀── gossip (Digest / Reply / Push) ──▶ соседи
//!                   │
//!                   ├─ peers()               → NodeMesh::update_peers   (вместо list_mesh_peers панели)
//!                   └─ validate_mesh_peer()  → допуск пира               (вместо /mesh/validate панели)
//! ```

pub mod descriptor;
pub mod gossip;
pub mod store;
pub mod swarm;
mod validator;

#[cfg(test)]
mod net_tests;
#[cfg(test)]
mod tests;

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub use descriptor::{
    derive_node_id, features, host_is_public, node_id_hex, parse_node_id, DescriptorError,
    Endpoint, EndpointKind, NodeDescriptor, NodeId, Roles, MAX_VALIDITY_SECS,
};
pub use gossip::{GossipError, Message, Stats};
pub use store::{DescriptorStore, Insert, Reject, StoreConfig};
pub use swarm::{SwarmIdentity, SwarmKey};
pub use validator::DirectoryValidator;

use super::auth::MeshPeer;

/// Текущее время Unix, секунды.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Настройки каталога узла.
#[derive(Debug, Clone)]
pub struct DirectoryConfig {
    pub store: StoreConfig,
    /// Публичные адреса этого узла (попадают в его запись).
    pub advertise: Vec<Endpoint>,
    pub decoy_sni: String,
    pub roles: u8,
    /// Диапазон принимаемых версий NRXP.
    pub proto: (u8, u8),
    /// Срок жизни своей записи.
    pub validity_secs: u64,
    /// Не чаще одного входящего обмена за столько секунд на весь узел.
    pub max_requests_per_window: u32,
    pub window_secs: u64,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            store: StoreConfig::default(),
            advertise: Vec::new(),
            decoy_sni: String::new(),
            roles: Roles::RELAY,
            proto: (2, 6),
            validity_secs: 24 * 3600,
            max_requests_per_window: 60,
            window_secs: 10,
        }
    }
}

struct Inner {
    store: DescriptorStore,
    own: NodeDescriptor,
    round: u64,
    window_start: u64,
    window_count: u32,
}

/// Каталог одного узла. Все методы принимают `now` (Unix, секунды), чтобы
/// поведение было детерминированным в тестах.
pub struct Directory {
    identity: SwarmIdentity,
    swarm: SwarmKey,
    cfg: DirectoryConfig,
    inner: Mutex<Inner>,
}

/// Итог входящего обмена.
#[derive(Debug)]
pub enum Handled {
    /// Нужно ответить этими байтами.
    Reply(Vec<u8>),
    /// Ответа нет (получили `Push`).
    Absorbed(Stats),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryError {
    Gossip(GossipError),
    RateLimited,
    /// Ждали запрос, пришёл ответ (или наоборот).
    UnexpectedMessage,
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gossip(e) => write!(f, "{e}"),
            Self::RateLimited => write!(f, "gossip rate limit exceeded"),
            Self::UnexpectedMessage => write!(f, "unexpected gossip message"),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl From<GossipError> for DirectoryError {
    fn from(e: GossipError) -> Self {
        Self::Gossip(e)
    }
}

impl Directory {
    pub fn new(identity: SwarmIdentity, swarm: SwarmKey, cfg: DirectoryConfig, now: u64) -> Self {
        let store = DescriptorStore::new(cfg.store.clone(), Some(identity.node_id));
        let own = Self::sign_own(&identity, &cfg, now, now);
        Self {
            identity,
            swarm,
            cfg,
            inner: Mutex::new(Inner {
                store,
                own,
                round: 0,
                window_start: now,
                window_count: 0,
            }),
        }
    }

    fn sign_own(identity: &SwarmIdentity, cfg: &DirectoryConfig, seq: u64, now: u64) -> NodeDescriptor {
        NodeDescriptor::sign(
            &identity.signing,
            identity.static_pub,
            Roles(cfg.roles),
            features::GOSSIP,
            cfg.proto,
            seq,
            now,
            cfg.validity_secs,
            cfg.decoy_sni.clone(),
            cfg.advertise.clone(),
        )
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id
    }

    pub fn node_id_hex(&self) -> String {
        self.identity.node_id_hex()
    }

    pub fn identity(&self) -> &SwarmIdentity {
        &self.identity
    }

    pub fn swarm(&self) -> &SwarmKey {
        &self.swarm
    }

    /// Своя запись; перевыпускается, когда осталось меньше трети срока.
    pub fn own(&self, now: u64) -> NodeDescriptor {
        let mut g = self.inner.lock().unwrap();
        let remaining = g.own.valid_until.saturating_sub(now);
        if remaining < self.cfg.validity_secs.min(MAX_VALIDITY_SECS) / 3 {
            let seq = (g.own.seq + 1).max(now);
            g.own = Self::sign_own(&self.identity, &self.cfg, seq, now);
        }
        g.own.clone()
    }

    /// Принимает запись (из файла, seed, чужого gossip) по общим правилам хранилища.
    pub fn insert(&self, d: NodeDescriptor, now: u64) -> Insert {
        self.inner.lock().unwrap().store.insert(d, now)
    }

    /// Принимает запись в бинарной форме.
    pub fn insert_bytes(&self, b: &[u8], now: u64) -> Insert {
        match NodeDescriptor::decode(b) {
            Ok(d) => self.insert(d, now),
            Err(e) => Insert::Rejected(Reject::Invalid(e)),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn gc(&self, now: u64) -> usize {
        self.inner.lock().unwrap().store.gc(now)
    }

    pub fn export(&self, now: u64) -> Vec<u8> {
        self.inner.lock().unwrap().store.export(now)
    }

    pub fn import(&self, bytes: &[u8], now: u64) -> usize {
        self.inner.lock().unwrap().store.import(bytes, now)
    }

    fn peer_of(&self, d: &NodeDescriptor) -> Option<MeshPeer> {
        let tcp = d.endpoint(EndpointKind::Tcp)?;
        Some(MeshPeer {
            node_id: node_id_hex(&d.node_id),
            host: tcp.host.clone(),
            port: tcp.port,
            decoy_sni: d.decoy_sni.clone(),
            nrxp_secret: self.swarm.node_secret(&d.node_id),
            nrxp_static_public: hex::encode(d.static_pub),
        })
    }

    /// Живые соседи в виде, который понимает `NodeMesh` (себя там нет).
    pub fn peers(&self, now: u64) -> Vec<MeshPeer> {
        let g = self.inner.lock().unwrap();
        let mut v: Vec<MeshPeer> = g
            .store
            .live(now)
            .filter(|d| d.roles.has(Roles::RELAY))
            .filter_map(|d| self.peer_of(d))
            .collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    /// Соседи, которым можно слать gossip (старым узлам неизвестный кадр рвёт ногу).
    pub fn gossip_peers(&self, now: u64) -> Vec<MeshPeer> {
        let g = self.inner.lock().unwrap();
        g.store
            .live(now)
            .filter(|d| d.supports_gossip())
            .filter_map(|d| self.peer_of(d))
            .collect()
    }

    /// Допуск mesh-пира: он знает секрет роя для своего `node_id`.
    pub fn validate_mesh_peer(&self, peer_id: &str, secret: &str) -> bool {
        parse_node_id(peer_id).is_some_and(|id| self.swarm.check_node_secret(&id, secret))
    }

    /// Первое сообщение обмена (дайджест). Счётчик раундов сдвигает окно дайджеста.
    pub fn begin_exchange(&self, now: u64) -> Vec<u8> {
        let own = self.own(now);
        let mut g = self.inner.lock().unwrap();
        g.round += 1;
        let round = g.round;
        gossip::build_digest(&g.store, Some(&own), now, round).encode()
    }

    /// Входящее сообщение: `Digest` → ответ, `Push` → поглощено.
    pub fn handle_incoming(&self, payload: &[u8], now: u64) -> Result<Handled, DirectoryError> {
        let msg = Message::decode(payload)?;
        let own = self.own(now);
        let mut g = self.inner.lock().unwrap();
        if now.saturating_sub(g.window_start) >= self.cfg.window_secs {
            g.window_start = now;
            g.window_count = 0;
        }
        g.window_count += 1;
        if g.window_count > self.cfg.max_requests_per_window {
            return Err(DirectoryError::RateLimited);
        }
        match msg {
            Message::Digest(remote) => {
                Ok(Handled::Reply(gossip::respond(&g.store, Some(&own), &remote, now).encode()))
            }
            Message::Push(_) => Ok(Handled::Absorbed(gossip::absorb(&mut g.store, msg, now)?)),
            Message::Reply { .. } => Err(DirectoryError::UnexpectedMessage),
        }
    }

    /// Ответ на наш дайджест: принять записи, подготовить `Push` с запрошенным.
    pub fn complete_exchange(
        &self,
        reply: &[u8],
        now: u64,
    ) -> Result<(Stats, Option<Vec<u8>>), DirectoryError> {
        let msg = Message::decode(reply)?;
        let own = self.own(now);
        let mut g = self.inner.lock().unwrap();
        let (stats, push) = gossip::finish(&mut g.store, Some(&own), msg, now)?;
        Ok((stats, push.map(|m| m.encode())))
    }
}
