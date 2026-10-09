//! Несколько узлов в конфиге и выбор рабочего при старте.
//!
//! Раньше клиент знал ровно один узел: заблокировали его адрес — туннель мёртв,
//! пока человек не поправит конфиг. Теперь в `client.toml` можно перечислить
//! запасные узлы (`[[nodes]]`); при запуске клиент проверяет их достижимость и
//! подключается к первому живому, предпочитая тот, что работал в прошлый раз.
//!
//! Смена узла посреди сессии не делается намеренно: маршруты и kill-switch
//! привязаны к адресу узла, и перекладывать их на лету опаснее, чем перезапуск.
//! Если все ноги мертвы дольше `TUNNEL_DEAD_AFTER`, движок завершается сам, процесс
//! выходит с ошибкой, и сервис-менеджер (systemd/procd) запускает клиент заново —
//! уже с выбором следующего живого узла. Подробности — `docs/DECENTRALIZATION.md`.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Запасной узел в `client.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEntry {
    /// `ip:port` (пока только IPv4, как и основной `remote_address`).
    pub address: String,
    pub node_secret: Option<String>,
    pub node_public_key: Option<String>,
    /// Домен-декой для `ClientHello`; не задан — как у основного узла.
    pub sni: Option<String>,
}

/// Узел, готовый к подключению.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    pub address: String,
    pub proxy: SocketAddr,
    pub sni: String,
    pub node_secret: Option<String>,
    pub node_public_key: Option<String>,
}

impl NodeEntry {
    /// Проверяет запись и превращает в кандидата; `default_sni` — SNI основного узла.
    pub fn into_candidate(self, default_sni: &str) -> Result<NodeCandidate> {
        let address = self.address.trim().to_owned();
        let proxy: SocketAddr = address
            .parse()
            .with_context(|| format!("nodes.address должен иметь вид IPv4:port: {address}"))?;
        if !proxy.is_ipv4() {
            bail!("nodes.address: пока поддерживается только IPv4 ({address})");
        }
        let secret = self.node_secret.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        let public = self.node_public_key.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        if secret.is_some() != public.is_some() {
            bail!("nodes[{address}]: node_secret и node_public_key должны быть заданы вместе");
        }
        Ok(NodeCandidate {
            address,
            proxy,
            sni: self
                .sni
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default_sni.to_owned()),
            node_secret: secret,
            node_public_key: public,
        })
    }
}

/// Порядок попыток: прошлый рабочий узел (если он в списке) первым, остальные — как
/// в конфиге (основной — раньше запасных).
pub fn order_candidates(mut all: Vec<NodeCandidate>, last_good: Option<&str>) -> Vec<NodeCandidate> {
    if let Some(i) = last_good.and_then(|last| all.iter().position(|c| c.address == last)) {
        let c = all.remove(i);
        all.insert(0, c);
    }
    all
}

/// Индекс первого достижимого узла в порядке попыток.
pub fn first_reachable(reachable: &[bool]) -> Option<usize> {
    reachable.iter().position(|r| *r)
}

const LAST_GOOD_FILE: &str = "last_node";

pub fn read_last_good(cache_dir: &Path) -> Option<String> {
    std::fs::read_to_string(cache_dir.join(LAST_GOOD_FILE))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

pub fn write_last_good(cache_dir: &Path, address: &str) {
    let _ = std::fs::write(cache_dir.join(LAST_GOOD_FILE), address);
}

/// Достижимость по TCP (SYN/ACK), без передачи чего-либо узлу.
pub async fn tcp_reachable(addr: SocketAddr, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Проверяет все узлы одновременно и возвращает выбранный (или `None`, если живых нет).
pub async fn pick(candidates: &[NodeCandidate], timeout: Duration) -> Option<usize> {
    let mut set = tokio::task::JoinSet::new();
    for (i, c) in candidates.iter().enumerate() {
        let addr = c.proxy;
        set.spawn(async move { (i, tcp_reachable(addr, timeout).await) });
    }
    let mut reachable = vec![false; candidates.len()];
    while let Some(Ok((i, ok))) = set.join_next().await {
        reachable[i] = ok;
    }
    first_reachable(&reachable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(addr: &str) -> NodeCandidate {
        NodeEntry {
            address: addr.into(),
            node_secret: None,
            node_public_key: None,
            sni: None,
        }
        .into_candidate("www.example.org")
        .unwrap()
    }

    #[test]
    fn last_good_node_goes_first_and_the_rest_keep_config_order() {
        let all = vec![cand("198.51.100.1:443"), cand("198.51.100.2:443"), cand("198.51.100.3:443")];
        let ordered = order_candidates(all.clone(), Some("198.51.100.3:443"));
        let addrs: Vec<_> = ordered.iter().map(|c| c.address.as_str()).collect();
        assert_eq!(addrs, ["198.51.100.3:443", "198.51.100.1:443", "198.51.100.2:443"]);
        // неизвестный «прошлый» узел порядок не меняет
        assert_eq!(order_candidates(all.clone(), Some("203.0.113.9:1")), all);
        assert_eq!(order_candidates(all.clone(), None), all);
    }

    #[test]
    fn first_reachable_follows_the_attempt_order() {
        assert_eq!(first_reachable(&[false, true, true]), Some(1));
        assert_eq!(first_reachable(&[true, true]), Some(0));
        assert_eq!(first_reachable(&[false, false]), None);
        assert_eq!(first_reachable(&[]), None);
    }

    #[test]
    fn entries_are_validated() {
        let ok = NodeEntry {
            address: " 198.51.100.7:8443 ".into(),
            node_secret: Some("aa".into()),
            node_public_key: Some("bb".into()),
            sni: Some("cdn.example".into()),
        }
        .into_candidate("default.example")
        .unwrap();
        assert_eq!(ok.address, "198.51.100.7:8443");
        assert_eq!(ok.sni, "cdn.example");

        let half = NodeEntry { address: "198.51.100.7:443".into(), node_secret: Some("aa".into()), node_public_key: None, sni: None };
        assert!(half.into_candidate("x").is_err());
        let bad = NodeEntry { address: "node.example:443".into(), node_secret: None, node_public_key: None, sni: None };
        assert!(bad.into_candidate("x").is_err());
        let v6 = NodeEntry { address: "[2001:db8::1]:443".into(), node_secret: None, node_public_key: None, sni: None };
        assert!(v6.into_candidate("x").is_err());
        assert_eq!(cand("198.51.100.8:443").sni, "www.example.org", "SNI по умолчанию — как у основного узла");
    }

    #[test]
    fn last_good_survives_a_round_trip() {
        let dir = std::env::temp_dir().join(format!("nr-nodes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_last_good(&dir), None);
        write_last_good(&dir, "198.51.100.2:443");
        assert_eq!(read_last_good(&dir).as_deref(), Some("198.51.100.2:443"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pick_skips_dead_nodes_and_returns_none_when_all_are_down() {
        let alive = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alive_addr = alive.local_addr().unwrap();
        // закрытый порт: привязали и сразу отпустили
        let dead_addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let mk = |a: SocketAddr| NodeCandidate {
            address: a.to_string(),
            proxy: a,
            sni: "x".into(),
            node_secret: None,
            node_public_key: None,
        };
        let t = Duration::from_millis(800);
        assert_eq!(pick(&[mk(dead_addr), mk(alive_addr)], t).await, Some(1));
        assert_eq!(pick(&[mk(alive_addr), mk(dead_addr)], t).await, Some(0));
        assert_eq!(pick(&[mk(dead_addr)], t).await, None);
        assert_eq!(pick(&[], t).await, None);
    }
}
