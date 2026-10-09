//! Локальное хранилище подписанных самоописаний соседей и правила допуска.
//!
//! Хранилище — единственное место, где решается, чему из услышанного верить.
//! Правила намеренно простые и ограниченные по ресурсам (память, число записей
//! с одной сети), потому что отравить каталог чужими адресами — первая
//! атака на любую сеть с peer exchange:
//!
//! * запись принимается только с корректной подписью и сроком (см.
//!   [`NodeDescriptor::verify`]);
//! * побеждает больший `seq`; равный и меньший — «устарела»;
//! * с одной сети (IPv4 /24, IPv6 /48, домен второго уровня) — не больше
//!   [`StoreConfig::max_per_prefix`] узлов: дешёвый Sybil с одного хостинга
//!   не заполнит каталог;
//! * при переполнении вытесняется запись с самым близким истечением, и только
//!   если новая живёт дольше.

use std::collections::HashMap;

use super::descriptor::{host_prefix, DescriptorError, Endpoint, NodeDescriptor, NodeId};

/// Сколько записей отдаётся в одном дайджесте.
pub const MAX_DIGEST_ENTRIES: usize = 480;

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub max_records: usize,
    pub max_per_prefix: usize,
    /// Разрешить частные адреса (LAN, тесты). В боевой сети — `false`.
    pub allow_private: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_records: 2048,
            max_per_prefix: 3,
            allow_private: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    Invalid(DescriptorError),
    /// Слишком много узлов из одной сети.
    PrefixLimit,
    /// Хранилище заполнено более долгоживущими записями.
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insert {
    Added,
    Updated,
    /// Уже есть такая или более новая запись (или это мы сами).
    Stale,
    Rejected(Reject),
}

pub struct DescriptorStore {
    cfg: StoreConfig,
    self_id: Option<NodeId>,
    map: HashMap<NodeId, NodeDescriptor>,
}

fn prefix_of(d: &NodeDescriptor) -> String {
    d.endpoints.first().map(|e: &Endpoint| host_prefix(&e.host)).unwrap_or_default()
}

impl DescriptorStore {
    pub fn new(cfg: StoreConfig, self_id: Option<NodeId>) -> Self {
        Self {
            cfg,
            self_id,
            map: HashMap::new(),
        }
    }

    pub fn config(&self) -> &StoreConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, id: &NodeId) -> Option<&NodeDescriptor> {
        self.map.get(id)
    }

    /// Принимает запись, если она проходит все правила.
    pub fn insert(&mut self, d: NodeDescriptor, now: u64) -> Insert {
        if let Err(e) = d.verify(now, self.cfg.allow_private) {
            return Insert::Rejected(Reject::Invalid(e));
        }
        if self.self_id == Some(d.node_id) {
            return Insert::Stale; // о себе мы знаем лучше всех
        }
        let existing_seq = self.map.get(&d.node_id).map(|o| o.seq);
        if existing_seq.is_some_and(|s| d.seq <= s) {
            return Insert::Stale;
        }

        let prefix = prefix_of(&d);
        let same_prefix = self
            .map
            .values()
            .filter(|o| o.node_id != d.node_id && prefix_of(o) == prefix)
            .count();
        if same_prefix >= self.cfg.max_per_prefix {
            return Insert::Rejected(Reject::PrefixLimit);
        }

        if existing_seq.is_none() && self.map.len() >= self.cfg.max_records {
            // Вытесняем самую скоро истекающую, но только если новая живёт дольше.
            let victim = self
                .map
                .values()
                .min_by_key(|o| o.valid_until)
                .map(|o| (o.node_id, o.valid_until));
            match victim {
                Some((id, until)) if until < d.valid_until => {
                    self.map.remove(&id);
                }
                _ => return Insert::Rejected(Reject::Full),
            }
        }

        let outcome = if existing_seq.is_some() { Insert::Updated } else { Insert::Added };
        self.map.insert(d.node_id, d);
        outcome
    }

    /// Удаляет истёкшие записи, возвращает их число.
    pub fn gc(&mut self, now: u64) -> usize {
        let before = self.map.len();
        self.map.retain(|_, d| d.valid_until > now);
        before - self.map.len()
    }

    /// Живые записи.
    pub fn live(&self, now: u64) -> impl Iterator<Item = &NodeDescriptor> {
        self.map.values().filter(move |d| d.valid_until > now)
    }

    /// Пары `(node_id, seq)` для обмена. Адреса мостов не пересказываются. Если
    /// записей больше окна, окно сдвигается с номером раунда — за несколько
    /// раундов проходит весь каталог (для сотен узлов хватает; для тысяч нужен
    /// компактный дайджест вроде IBLT — см. документ).
    pub fn digest(&self, now: u64, round: u64) -> Vec<(NodeId, u64)> {
        let mut all: Vec<(NodeId, u64)> = self
            .live(now)
            .filter(|d| d.roles.gossipable())
            .map(|d| (d.node_id, d.seq))
            .collect();
        all.sort_unstable();
        if all.len() <= MAX_DIGEST_ENTRIES {
            return all;
        }
        let start = (round as usize).wrapping_mul(MAX_DIGEST_ENTRIES) % all.len();
        (0..MAX_DIGEST_ENTRIES).map(|i| all[(start + i) % all.len()]).collect()
    }

    /// Снимок для сохранения на диск.
    pub fn export(&self, now: u64) -> Vec<u8> {
        let live: Vec<&NodeDescriptor> = self.live(now).collect();
        let mut out = b"NRXPDIR1".to_vec();
        out.extend_from_slice(&(live.len() as u32).to_be_bytes());
        for d in live {
            let e = d.encode();
            out.extend_from_slice(&(e.len() as u16).to_be_bytes());
            out.extend_from_slice(&e);
        }
        out
    }

    /// Загружает снимок; каждая запись проходит полную проверку заново.
    /// Возвращает число принятых.
    pub fn import(&mut self, bytes: &[u8], now: u64) -> usize {
        let Some(rest) = bytes.strip_prefix(b"NRXPDIR1") else {
            return 0;
        };
        let Some((count, mut rest)) = rest.split_first_chunk::<4>() else {
            return 0;
        };
        let count = u32::from_be_bytes(*count) as usize;
        let mut accepted = 0;
        for _ in 0..count.min(self.cfg.max_records) {
            let Some((len, tail)) = rest.split_first_chunk::<2>() else { break };
            let len = u16::from_be_bytes(*len) as usize;
            let Some(rec) = tail.get(..len) else { break };
            rest = &tail[len..];
            if let Ok(d) = NodeDescriptor::decode(rec) {
                if matches!(self.insert(d, now), Insert::Added | Insert::Updated) {
                    accepted += 1;
                }
            }
        }
        accepted
    }
}
