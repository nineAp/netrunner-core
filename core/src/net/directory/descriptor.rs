//! Самоописание узла: подписанная запись «этот ключ живёт по этому адресу».
//!
//! Раньше о соседях узел узнавал только от панели (`list_mesh_peers`), и никакая
//! запись не была подписана самим узлом. Здесь запись **самосертифицируется**:
//! `node_id = H(sign_pub ‖ static_pub)`, подпись ставит ключ `sign_pub`, поэтому
//! подменить адрес или ключ чужого узла нельзя, а доставить запись можно любым
//! каналом (gossip, CDN, файл) — проверка не зависит от того, кто её принёс.
//!
//! Чего запись **не** доказывает: что узел «хороший» и вправе быть в сети. Это
//! решает политика допуска ([`super::store::StoreConfig`], дальше — токены и
//! поручительство, см. `docs/DECENTRALIZATION.md`).
//!
//! Срок жизни записи ограничен ([`MAX_VALIDITY_SECS`]): старая запись не
//! воскреснет, а `seq` не даёт откатить адрес назад.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Версия формата записи.
pub const DESCRIPTOR_VERSION: u8 = 1;
/// Не больше стольких адресов в одной записи.
pub const MAX_ENDPOINTS: usize = 4;
/// Максимальный срок жизни записи (выпуск → истечение).
pub const MAX_VALIDITY_SECS: u64 = 72 * 3600;
/// Насколько «из будущего» может быть `issued_at` (расхождение часов).
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Идентификатор узла: 16 байт хеша обоих ключей.
pub type NodeId = [u8; 16];

pub fn node_id_hex(id: &NodeId) -> String {
    hex::encode(id)
}

pub fn parse_node_id(s: &str) -> Option<NodeId> {
    let b = hex::decode(s.trim()).ok()?;
    b.try_into().ok()
}

/// `node_id` по ключам. Включает оба ключа, чтобы нельзя было приписать узлу
/// чужой статический ключ под своей подписью (и наоборот).
pub fn derive_node_id(sign_pub: &[u8; 32], static_pub: &[u8; 32]) -> NodeId {
    let mut h = Sha256::new();
    h.update(b"nrxp-node-id-v1");
    h.update(sign_pub);
    h.update(static_pub);
    let d = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    id
}

/// Ключ подписи выводится из приватного статического ключа узла: отдельной
/// настройки не нужно, а потеря одного ключа не создаёт расхождения личностей.
pub fn derive_signing_key(static_private: &[u8; 32]) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(None, static_private);
    let mut seed = [0u8; 32];
    hk.expand(b"nrxp-directory-sign-v1", &mut seed)
        .expect("32 bytes is a valid HKDF output length");
    SigningKey::from_bytes(&seed)
}

/// Роли узла (битовая маска).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roles(pub u8);

impl Roles {
    /// Средний хоп.
    pub const RELAY: u8 = 1;
    /// Выход в интернет (включается явно оператором).
    pub const EXIT: u8 = 2;
    /// Вход для пользователей. **Не распространяется gossip'ом**: адреса мостов
    /// выдаются порциями (см. документ), иначе перечисление сети тривиально.
    pub const BRIDGE: u8 = 4;

    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Можно ли пересказывать запись соседям.
    pub fn gossipable(self) -> bool {
        !self.has(Self::BRIDGE)
    }
}

/// Возможности узла (битовая маска) — вместо повышения версии хендшейка.
pub mod features {
    /// Узел понимает кадр `PeerGossip`. Старым узлам неизвестный тип кадра
    /// рвёт ногу, поэтому им gossip не шлют.
    pub const GOSSIP: u8 = 1;
}

/// Тип адреса входа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// Основной NRXP порт (TCP, TLS-мимикрия) — вход клиентов и mesh-пиров.
    Tcp = 0,
    /// Mesh-QUIC порт.
    MeshQuic = 1,
}

impl EndpointKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Tcp),
            1 => Some(Self::MeshQuic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: EndpointKind,
    pub host: String,
    pub port: u16,
}

/// Почему запись отвергнута.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    Malformed(&'static str),
    BadVersion(u8),
    /// `node_id` не соответствует ключам.
    BadNodeId,
    BadSignature,
    Expired,
    /// `issued_at` слишком далеко в будущем.
    FromTheFuture,
    /// Срок жизни дольше [`MAX_VALIDITY_SECS`] либо не положителен.
    BadValidity,
    BadEndpoint(&'static str),
    /// Адрес не публичный (loopback/частный/link-local), а политика требует публичный.
    NonPublicAddress,
}

impl std::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(w) => write!(f, "malformed descriptor: {w}"),
            Self::BadVersion(v) => write!(f, "unsupported descriptor version {v}"),
            Self::BadNodeId => write!(f, "node_id does not match the keys"),
            Self::BadSignature => write!(f, "bad signature"),
            Self::Expired => write!(f, "descriptor expired"),
            Self::FromTheFuture => write!(f, "descriptor issued in the future"),
            Self::BadValidity => write!(f, "invalid validity period"),
            Self::BadEndpoint(w) => write!(f, "bad endpoint: {w}"),
            Self::NonPublicAddress => write!(f, "non-public address"),
        }
    }
}

impl std::error::Error for DescriptorError {}

/// Подписанное самоописание узла.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    pub node_id: NodeId,
    /// X25519: личность для хендшейка.
    pub static_pub: [u8; 32],
    /// Ed25519: подпись записей.
    pub sign_pub: [u8; 32],
    pub roles: Roles,
    pub features: u8,
    /// Диапазон версий NRXP, которые узел принимает.
    pub proto_min: u8,
    pub proto_max: u8,
    /// Монотонный номер: побеждает запись с большим `seq`.
    pub seq: u64,
    pub issued_at: u64,
    pub valid_until: u64,
    pub decoy_sni: String,
    pub endpoints: Vec<Endpoint>,
    pub signature: [u8; 64],
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

impl NodeDescriptor {
    /// Тело записи без подписи (то, что подписывается).
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.push(DESCRIPTOR_VERSION);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.static_pub);
        out.extend_from_slice(&self.sign_pub);
        out.push(self.roles.0);
        out.push(self.features);
        out.push(self.proto_min);
        out.push(self.proto_max);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.valid_until.to_be_bytes());
        put_str(&mut out, &self.decoy_sni);
        out.push(self.endpoints.len() as u8);
        for e in &self.endpoints {
            out.push(e.kind as u8);
            put_str(&mut out, &e.host);
            out.extend_from_slice(&e.port.to_be_bytes());
        }
        out
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut m = b"nrxp-descriptor-v1\0".to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    /// Выпускает подписанную запись.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        signing: &SigningKey,
        static_pub: [u8; 32],
        roles: Roles,
        features: u8,
        proto: (u8, u8),
        seq: u64,
        issued_at: u64,
        valid_secs: u64,
        decoy_sni: String,
        endpoints: Vec<Endpoint>,
    ) -> Self {
        let sign_pub = signing.verifying_key().to_bytes();
        let mut d = Self {
            node_id: derive_node_id(&sign_pub, &static_pub),
            static_pub,
            sign_pub,
            roles,
            features,
            proto_min: proto.0,
            proto_max: proto.1,
            seq,
            issued_at,
            valid_until: issued_at + valid_secs.min(MAX_VALIDITY_SECS),
            decoy_sni,
            endpoints,
            signature: [0u8; 64],
        };
        d.signature = signing.sign(&d.signing_bytes()).to_bytes();
        d
    }

    /// Бинарная форма (с подписью).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Разбор. Только структура: подпись и сроки — в [`verify`](Self::verify).
    pub fn decode(b: &[u8]) -> Result<Self, DescriptorError> {
        let mut c = Cursor { b, p: 0 };
        let version = c.u8()?;
        if version != DESCRIPTOR_VERSION {
            return Err(DescriptorError::BadVersion(version));
        }
        let node_id: NodeId = c.arr()?;
        let static_pub: [u8; 32] = c.arr()?;
        let sign_pub: [u8; 32] = c.arr()?;
        let roles = Roles(c.u8()?);
        let features = c.u8()?;
        let proto_min = c.u8()?;
        let proto_max = c.u8()?;
        let seq = c.u64()?;
        let issued_at = c.u64()?;
        let valid_until = c.u64()?;
        let decoy_sni = c.string()?;
        let n = c.u8()? as usize;
        if n == 0 || n > MAX_ENDPOINTS {
            return Err(DescriptorError::Malformed("endpoint count"));
        }
        let mut endpoints = Vec::with_capacity(n);
        for _ in 0..n {
            let kind = EndpointKind::from_u8(c.u8()?).ok_or(DescriptorError::Malformed("endpoint kind"))?;
            let host = c.string()?;
            let port = u16::from_be_bytes(c.arr()?);
            endpoints.push(Endpoint { kind, host, port });
        }
        let signature: [u8; 64] = c.arr()?;
        if c.p != b.len() {
            return Err(DescriptorError::Malformed("trailing bytes"));
        }
        Ok(Self {
            node_id,
            static_pub,
            sign_pub,
            roles,
            features,
            proto_min,
            proto_max,
            seq,
            issued_at,
            valid_until,
            decoy_sni,
            endpoints,
            signature,
        })
    }

    /// Полная проверка: структура, личность, подпись, сроки, адреса.
    /// `allow_private` — разрешить частные адреса (тесты, LAN, локальные стенды).
    pub fn verify(&self, now: u64, allow_private: bool) -> Result<(), DescriptorError> {
        if self.node_id != derive_node_id(&self.sign_pub, &self.static_pub) {
            return Err(DescriptorError::BadNodeId);
        }
        if self.proto_min > self.proto_max {
            return Err(DescriptorError::Malformed("proto range"));
        }
        if self.valid_until <= self.issued_at || self.valid_until - self.issued_at > MAX_VALIDITY_SECS {
            return Err(DescriptorError::BadValidity);
        }
        if self.issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(DescriptorError::FromTheFuture);
        }
        if self.valid_until <= now {
            return Err(DescriptorError::Expired);
        }
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_ENDPOINTS {
            return Err(DescriptorError::Malformed("endpoint count"));
        }
        for e in &self.endpoints {
            validate_host(&e.host)?;
            if e.port == 0 {
                return Err(DescriptorError::BadEndpoint("port 0"));
            }
            if !allow_private && !host_is_public(&e.host) {
                return Err(DescriptorError::NonPublicAddress);
            }
        }
        if !self.decoy_sni.is_empty() {
            validate_host(&self.decoy_sni).map_err(|_| DescriptorError::BadEndpoint("decoy sni"))?;
        }
        let vk = VerifyingKey::from_bytes(&self.sign_pub).map_err(|_| DescriptorError::BadSignature)?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(&self.signing_bytes(), &sig)
            .map_err(|_| DescriptorError::BadSignature)
    }

    /// Первый адрес заданного типа.
    pub fn endpoint(&self, kind: EndpointKind) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| e.kind == kind)
    }

    pub fn supports_gossip(&self) -> bool {
        self.features & features::GOSSIP != 0
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DescriptorError> {
        let s = self.b.get(self.p..self.p + n).ok_or(DescriptorError::Malformed("truncated"))?;
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DescriptorError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, DescriptorError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], DescriptorError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn string(&mut self) -> Result<String, DescriptorError> {
        let n = self.u8()? as usize;
        let s = self.take(n)?;
        String::from_utf8(s.to_vec()).map_err(|_| DescriptorError::Malformed("utf8"))
    }
}

/// Имя хоста либо IP-литерал, без пробелов и управляющих символов.
fn validate_host(h: &str) -> Result<(), DescriptorError> {
    if h.is_empty() || h.len() > 253 {
        return Err(DescriptorError::BadEndpoint("host length"));
    }
    if h.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let ok = h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !ok || h.starts_with('.') || h.starts_with('-') || h.ends_with('.') {
        return Err(DescriptorError::BadEndpoint("host characters"));
    }
    Ok(())
}

/// Публичен ли адрес. Имя хоста считается публичным (DNS проверить на месте нельзя),
/// кроме `localhost`.
pub fn host_is_public(h: &str) -> bool {
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT
                || o[0] >= 240)
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80) // link-local
        }
        Err(_) => !h.eq_ignore_ascii_case("localhost") && !h.ends_with(".local") && !h.ends_with(".internal"),
    }
}

/// Группа «рядом» для ограничения числа узлов в одной сети: IPv4 /24, IPv6 /48,
/// для имён — последние две метки.
pub fn host_prefix(h: &str) -> String {
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            format!("v4:{}.{}.{}", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            format!("v6:{:x}:{:x}:{:x}", s[0], s[1], s[2])
        }
        Err(_) => {
            let labels: Vec<&str> = h.rsplit('.').take(2).collect();
            format!("dns:{}", labels.into_iter().rev().collect::<Vec<_>>().join(".").to_ascii_lowercase())
        }
    }
}
