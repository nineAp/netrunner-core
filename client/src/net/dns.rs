//! Локальный перехват DNS: фейковые IP + блок-лист.
//!
//! Клиент сам отвечает на DNS-запросы приложений, чтобы (а) не утекал реальный
//! DNS и (б) каждое имя получало стабильный «фейковый» IP из диапазона CGNAT
//! (RFC 6598, 100.64.0.0/10), по которому потом восстанавливается хост.
//!
//! Две части:
//! - [`FakeIpStore`] — двусторонний LRU-маппинг `домен ⇄ фейковый IP`. Выдаёт
//!   новый IP по запросу и позволяет обратный поиск (IP → домен) при установке
//!   туннельного соединения.
//! - [`DnsHandler`] — обработчик запросов: режет приватные суффиксы и домены из
//!   блок-листа (StevenBlack/hosts, фоново подкачивается и кэшируется),
//!   пропускает исключённые домены мимо туннеля (ServFail → системный DNS),
//!   остальным A-запросам выдаёт фейковый IP.

use anyhow::Result;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use lru::LruCache;
use netrunner_logger::{debug, error, info};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, BufReader};

// --- Constants ---

/// Start of the RFC 6598 (CGNAT) range used for fake DNS responses.
const FAKE_IP_START: u32 = 0x6440_0001; // 100.64.0.1
/// LRU capacity for the domain→IP and IP→domain mapping tables.
const FAKE_IP_CACHE_SIZE: usize = 2000;
/// Re-download the blocklist if the cached file is older than this.
const BLOCKLIST_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600);
/// Delay before starting a background blocklist download on first run.
const BLOCKLIST_DOWNLOAD_DELAY: Duration = Duration::from_secs(10);
/// HTTP timeout for the blocklist download request.
const BLOCKLIST_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// TTL advertised in fake DNS A records (seconds).
const FAKE_DNS_TTL: u32 = 60;

/// Двусторонний LRU-маппинг доменов на фейковые IP из CGNAT-диапазона.
pub struct FakeIpStore {
    /// Прямой: домен → выданный IP.
    cache: LruCache<String, Ipv4Addr>,
    /// Обратный: IP → домен (для восстановления цели при connect).
    rev_cache: LruCache<Ipv4Addr, String>,
    /// Следующий свободный IP (монотонно растёт от `FAKE_IP_START`).
    next_ip: u32,
}

impl FakeIpStore {
    pub fn new() -> Self {
        info!("Initializing FakeIpStore starting at {}", Ipv4Addr::from(FAKE_IP_START));
        Self {
            cache: LruCache::new(NonZeroUsize::new(FAKE_IP_CACHE_SIZE).unwrap()),
            rev_cache: LruCache::new(NonZeroUsize::new(FAKE_IP_CACHE_SIZE).unwrap()),
            next_ip: FAKE_IP_START,
        }
    }

    pub fn get_or_assign(&mut self, host: &str) -> Ipv4Addr {
        if let Some(&ip) = self.cache.get(host) {
            debug!(host = %host, ip = %ip, "Cache hit: IP already assigned");
            return ip;
        }
        let ip = Ipv4Addr::from(self.next_ip);
        self.next_ip += 1;

        self.cache.put(host.to_string(), ip);
        self.rev_cache.put(ip, host.to_string());

        debug!(host = %host, ip = %ip, "Assigned new fake IP");
        ip
    }

    pub fn lookup_by_ip(&self, ip: &Ipv4Addr) -> Option<String> {
        if let Some(host) = self.rev_cache.peek(ip) {
            debug!(ip = %ip, host = %host, "Reverse lookup successful");
            Some(host.clone())
        } else {
            debug!(ip = %ip, "Reverse lookup miss");
            None
        }
    }
}

// --- DNS Handler & Blocklist Logic ---

/// Обработчик DNS-запросов: фильтрация + выдача фейковых IP.
pub struct DnsHandler {
    /// Заблокированные домены (из StevenBlack/hosts).
    block_list: HashSet<String>,
    /// Приватные суффиксы, которые всегда NXDomain (`.lan`, `.local`, …).
    forbidden_suffixes: Vec<String>,
    /// Путь к кэшу блок-листа на диске.
    cache_path: String,
    /// Домены в обход туннеля: на них отвечаем ServFail → системный DNS.
    excluded_domains: HashSet<String>,
}

impl DnsHandler {
    pub fn new(cache_dir: &str, excluded: Vec<String>) -> Self {
        Self {
            block_list: HashSet::new(),
            forbidden_suffixes: vec![".lan", ".local", ".home", ".arpa"]
                .into_iter()
                .map(String::from)
                .collect(),
            cache_path: format!("{}/hosts_cache.txt", cache_dir),
            excluded_domains: excluded.into_iter().map(|d| d.to_lowercase()).collect(),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        let path = PathBuf::from(&self.cache_path);

        if path.exists() {
            let _ = self.load_from_file().await;
        }

        let needs_update = if let Ok(meta) = fs::metadata(&path).await {
            SystemTime::now()
                .duration_since(meta.modified()?)
                .unwrap_or_default()
                > BLOCKLIST_UPDATE_INTERVAL
        } else {
            true
        };

        if needs_update {
            let p_clone = self.cache_path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(BLOCKLIST_DOWNLOAD_DELAY).await;
                if let Err(e) = Self::download_blocklist_async(p_clone).await {
                    error!("DNS: Background update failed: {}", e);
                }
            });
        }

        Ok(())
    }

    async fn download_blocklist_async(cache_path: String) -> Result<()> {
        info!("DNS: Starting background download to {}", cache_path);
        let client = reqwest::Client::builder()
            .timeout(BLOCKLIST_HTTP_TIMEOUT)
            .build()?;

        let resp = client
            .get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
            .send()
            .await?;

        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            fs::write(&cache_path, bytes).await?;
            info!("DNS: Blocklist downloaded successfully.");
        } else {
            error!("DNS: Download failed with status {}", resp.status());
        }
        Ok(())
    }

    async fn load_from_file(&mut self) -> Result<()> {
        let file = File::open(&self.cache_path).await?;
        let mut lines = BufReader::new(file).lines();
        let mut count = 0;

        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(domain) = line.split_whitespace().nth(1) {
                self.block_list.insert(domain.to_lowercase());
                count += 1;
            }
        }
        info!("DNS: Loaded {} domains from blocklist.", count);
        Ok(())
    }

    /// Обрабатывает один DNS-запрос и возвращает сериализованный ответ.
    ///
    /// Порядок решений: исключённый домен → ServFail (фолбэк на системный DNS);
    /// приватный суффикс/блок-лист → NXDomain; A-запрос → фейковый IP; прочее →
    /// пустой NoError. `None` — если запрос не разобрался.
    pub fn handle_query(&self, data: &[u8], store: &mut FakeIpStore) -> Option<Vec<u8>> {
        let req = Message::from_vec(data).ok()?;
        let query = req.queries().first()?;
        let name = query
            .name()
            .to_string()
            .trim_end_matches('.')
            .to_lowercase();

        let mut res = Message::new();
        res.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_recursion_available(true)
            .add_query(query.clone());

        if self.excluded_domains.iter().any(|ext| name.ends_with(ext)) {
            netrunner_logger::info!("Bypassing DNS for excluded domain: {}", name);
            // Отвечаем ServFail (или Refused). Это заставит ОС сделать фолбэк на реальный DNS провайдера.
            res.set_response_code(ResponseCode::ServFail);
            return res.to_vec().ok();
        }

        if self.forbidden_suffixes.iter().any(|s| name.ends_with(s))
            || self.block_list.contains(&name)
        {
            debug!(domain = %name, "DNS: Blocked");
            res.set_response_code(ResponseCode::NXDomain);
            return res.to_vec().ok();
        }

        if query.query_type() == RecordType::A {
            let fake_ip = store.get_or_assign(&name);
            res.add_answer(Record::from_rdata(
                query.name().clone(),
                FAKE_DNS_TTL,
                RData::A(fake_ip.into()),
            ));
            res.set_response_code(ResponseCode::NoError);
        } else {
            res.set_response_code(ResponseCode::NoError);
        }

        res.to_vec().ok()
    }
}
