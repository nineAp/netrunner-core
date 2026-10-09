//! Обмен записями между узлами (peer exchange, режим push-pull).
//!
//! Один обмен — два кадра по одному потоку уже аутентифицированной mesh-сессии:
//!
//! ```text
//!  инициатор                                   отвечающий
//!   Digest{(id, seq)…}  ───────────────────▶
//!                       ◀───────────────────  Reply{записи, которых нет/старее у инициатора;
//!                                                   want: чьи записи нужны нам}
//!   Push{записи из want} ──────────────────▶   (ответа нет)
//! ```
//!
//! Дайджест — это пары `(node_id, seq)`, а не сами записи: канал остаётся
//! дешёвым, а подпись проверяет каждый получатель сам, поэтому доверять
//! рассказчику не нужно. Адреса мостов ([`Roles::BRIDGE`](super::descriptor::Roles))
//! не пересказываются. Все размеры ограничены так, чтобы сообщение целиком
//! помещалось в один кадр NRXP и не давало усилить нагрузку (читаем и
//! проверяем не больше десятков подписей на сообщение).

use super::descriptor::{NodeDescriptor, NodeId};
use super::store::{DescriptorStore, Insert};

/// Потолок размера сообщения: с запасом меньше `MAX_FRAME_PAYLOAD` (16360).
pub const MAX_MSG_BYTES: usize = 15_000;
const MAX_DIGEST_ITEMS: usize = 512;
const MAX_RECORDS: usize = 64;
const MAX_WANT: usize = 256;

const TAG_DIGEST: u8 = 1;
const TAG_REPLY: u8 = 2;
const TAG_PUSH: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Digest(Vec<(NodeId, u64)>),
    Reply {
        records: Vec<NodeDescriptor>,
        want: Vec<NodeId>,
    },
    Push(Vec<NodeDescriptor>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipError {
    Empty,
    UnknownTag(u8),
    Malformed(&'static str),
    TooLarge,
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty gossip message"),
            Self::UnknownTag(t) => write!(f, "unknown gossip tag {t}"),
            Self::Malformed(w) => write!(f, "malformed gossip message: {w}"),
            Self::TooLarge => write!(f, "gossip message too large"),
        }
    }
}

impl std::error::Error for GossipError {}

fn put_records(out: &mut Vec<u8>, records: &[NodeDescriptor]) {
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for r in records {
        let e = r.encode();
        out.extend_from_slice(&(e.len() as u16).to_be_bytes());
        out.extend_from_slice(&e);
    }
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Digest(items) => {
                out.push(TAG_DIGEST);
                out.extend_from_slice(&(items.len() as u16).to_be_bytes());
                for (id, seq) in items {
                    out.extend_from_slice(id);
                    out.extend_from_slice(&seq.to_be_bytes());
                }
            }
            Self::Reply { records, want } => {
                out.push(TAG_REPLY);
                put_records(&mut out, records);
                out.extend_from_slice(&(want.len() as u16).to_be_bytes());
                for id in want {
                    out.extend_from_slice(id);
                }
            }
            Self::Push(records) => {
                out.push(TAG_PUSH);
                put_records(&mut out, records);
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, GossipError> {
        if b.len() > MAX_MSG_BYTES {
            return Err(GossipError::TooLarge);
        }
        let (&tag, rest) = b.split_first().ok_or(GossipError::Empty)?;
        let mut r = Reader { b: rest, p: 0 };
        let msg = match tag {
            TAG_DIGEST => {
                let n = r.u16()? as usize;
                if n > MAX_DIGEST_ITEMS {
                    return Err(GossipError::Malformed("digest too long"));
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    let id: NodeId = r.arr()?;
                    let seq = u64::from_be_bytes(r.arr()?);
                    items.push((id, seq));
                }
                Self::Digest(items)
            }
            TAG_REPLY => {
                let records = r.records()?;
                let n = r.u16()? as usize;
                if n > MAX_WANT {
                    return Err(GossipError::Malformed("want too long"));
                }
                let mut want = Vec::with_capacity(n);
                for _ in 0..n {
                    want.push(r.arr()?);
                }
                Self::Reply { records, want }
            }
            TAG_PUSH => Self::Push(r.records()?),
            t => return Err(GossipError::UnknownTag(t)),
        };
        if r.p != r.b.len() {
            return Err(GossipError::Malformed("trailing bytes"));
        }
        Ok(msg)
    }

    /// Это сообщение — запрос, на который отвечают (а не ответ).
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Digest(_))
    }
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], GossipError> {
        let s = self.b.get(self.p..self.p + n).ok_or(GossipError::Malformed("truncated"))?;
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, GossipError> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], GossipError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn records(&mut self) -> Result<Vec<NodeDescriptor>, GossipError> {
        let n = self.u16()? as usize;
        if n > MAX_RECORDS {
            return Err(GossipError::Malformed("too many records"));
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let len = self.u16()? as usize;
            let rec = self.take(len)?;
            out.push(NodeDescriptor::decode(rec).map_err(|_| GossipError::Malformed("bad record"))?);
        }
        Ok(out)
    }
}

/// Сводка принятого из сообщения.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub added: usize,
    pub updated: usize,
    pub stale: usize,
    pub rejected: usize,
}

impl Stats {
    pub fn learned(&self) -> usize {
        self.added + self.updated
    }
}

/// Все пересказываемые записи: хранилище и собственная (если можно).
fn shareable<'a>(
    store: &'a DescriptorStore,
    own: Option<&'a NodeDescriptor>,
    now: u64,
) -> Vec<&'a NodeDescriptor> {
    let mut v: Vec<&NodeDescriptor> = store.live(now).filter(|d| d.roles.gossipable()).collect();
    if let Some(o) = own.filter(|o| o.valid_until > now && o.roles.gossipable()) {
        v.push(o);
    }
    v
}

/// Дайджест инициатора.
pub fn build_digest(
    store: &DescriptorStore,
    own: Option<&NodeDescriptor>,
    now: u64,
    round: u64,
) -> Message {
    let mut items = store.digest(now, round);
    if let Some(o) = own.filter(|o| o.valid_until > now && o.roles.gossipable()) {
        if !items.iter().any(|(id, _)| *id == o.node_id) {
            items.push((o.node_id, o.seq));
        }
    }
    items.truncate(MAX_DIGEST_ITEMS);
    Message::Digest(items)
}

/// Набирает записи, пока влезают в бюджет сообщения.
fn take_within_budget(mut candidates: Vec<&NodeDescriptor>, reserve: usize) -> Vec<NodeDescriptor> {
    // Короче — первыми: больше записей на сообщение; порядок детерминирован.
    candidates.sort_by_key(|d| (d.encode().len(), d.node_id));
    let mut used = reserve + 8;
    let mut out = Vec::new();
    for d in candidates {
        let len = d.encode().len() + 2;
        if used + len > MAX_MSG_BYTES || out.len() >= MAX_RECORDS {
            break;
        }
        used += len;
        out.push(d.clone());
    }
    out
}

/// Ответ на дайджест: что у нас новее/есть сверх, и что нужно нам.
pub fn respond(
    store: &DescriptorStore,
    own: Option<&NodeDescriptor>,
    remote: &[(NodeId, u64)],
    now: u64,
) -> Message {
    use std::collections::HashMap;
    let theirs: HashMap<NodeId, u64> = remote.iter().copied().collect();
    let ours = shareable(store, own, now);

    let send: Vec<&NodeDescriptor> = ours
        .iter()
        .copied()
        .filter(|d| theirs.get(&d.node_id).is_none_or(|&s| s < d.seq))
        .collect();

    let our_seq: HashMap<NodeId, u64> = ours.iter().map(|d| (d.node_id, d.seq)).collect();
    let mut want: Vec<NodeId> = remote
        .iter()
        .filter(|(id, seq)| our_seq.get(id).is_none_or(|s| *s < *seq))
        // Про себя мы знаем лучше всех — своё не запрашиваем.
        .filter(|(id, _)| own.is_none_or(|o| o.node_id != *id))
        .map(|(id, _)| *id)
        .collect();
    want.truncate(MAX_WANT);

    let records = take_within_budget(send, want.len() * 16 + 4);
    Message::Reply { records, want }
}

fn count(store: &mut DescriptorStore, records: Vec<NodeDescriptor>, now: u64) -> Stats {
    let mut st = Stats::default();
    for d in records {
        if !d.roles.gossipable() {
            // Мост по gossip не приходит: либо ошибка, либо попытка засорить.
            st.rejected += 1;
            continue;
        }
        match store.insert(d, now) {
            Insert::Added => st.added += 1,
            Insert::Updated => st.updated += 1,
            Insert::Stale => st.stale += 1,
            Insert::Rejected(_) => st.rejected += 1,
        }
    }
    st
}

/// Обрабатывает ответ: принимает записи и готовит `Push` с тем, что просили.
pub fn finish(
    store: &mut DescriptorStore,
    own: Option<&NodeDescriptor>,
    reply: Message,
    now: u64,
) -> Result<(Stats, Option<Message>), GossipError> {
    let Message::Reply { records, want } = reply else {
        return Err(GossipError::Malformed("expected a reply"));
    };
    let stats = count(store, records, now);
    let wanted: Vec<&NodeDescriptor> = {
        let mut v = Vec::new();
        for id in &want {
            if let Some(o) = own.filter(|o| o.node_id == *id) {
                v.push(o);
            } else if let Some(d) = store.get(id).filter(|d| d.valid_until > now && d.roles.gossipable()) {
                v.push(d);
            }
        }
        v
    };
    let push = if wanted.is_empty() {
        None
    } else {
        Some(Message::Push(take_within_budget(wanted, 0)))
    };
    Ok((stats, push))
}

/// Принимает `Push`.
pub fn absorb(store: &mut DescriptorStore, push: Message, now: u64) -> Result<Stats, GossipError> {
    let Message::Push(records) = push else {
        return Err(GossipError::Malformed("expected a push"));
    };
    Ok(count(store, records, now))
}
