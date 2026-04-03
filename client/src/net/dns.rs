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

// --- Fake IP Storage ---

const START_IP: u32 = 0x64400001; // 100.64.0.1

pub struct FakeIpStore {
    cache: LruCache<String, Ipv4Addr>,
    rev_cache: LruCache<Ipv4Addr, String>,
    next_ip: u32,
}

impl FakeIpStore {
    pub fn new() -> Self {
        info!("Initializing FakeIpStore starting at 100.64.0.1");
        Self {
            cache: LruCache::new(NonZeroUsize::new(2000).unwrap()),
            rev_cache: LruCache::new(NonZeroUsize::new(2000).unwrap()),
            next_ip: START_IP,
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

pub struct DnsHandler {
    block_list: HashSet<String>,
    forbidden_suffixes: Vec<String>,
    cache_path: String,
}

impl DnsHandler {
    pub fn new(cache_dir: &str) -> Self {
        Self {
            block_list: HashSet::new(),
            forbidden_suffixes: vec![".lan", ".local", ".home", ".arpa"]
                .into_iter()
                .map(String::from)
                .collect(),
            cache_path: format!("{}/hosts_cache.txt", cache_dir),
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
                > Duration::from_secs(604800) // 1 неделя
        } else {
            true
        };

        if needs_update {
            let p_clone = self.cache_path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
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
            .timeout(Duration::from_secs(30))
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

        // 1. Проверка блокировок
        if self.forbidden_suffixes.iter().any(|s| name.ends_with(s))
            || self.block_list.contains(&name)
        {
            debug!(domain = %name, "DNS: Blocked");
            res.set_response_code(ResponseCode::NXDomain);
            return res.to_vec().ok();
        }

        // 2. Генерация Fake IP для A-записей
        if query.query_type() == RecordType::A {
            let fake_ip = store.get_or_assign(&name);
            res.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(fake_ip.into()),
            ));
            res.set_response_code(ResponseCode::NoError);
        } else {
            // Для остальных типов записей (AAAA и т.д.) просто возвращаем пустой NoError или NXDomain
            res.set_response_code(ResponseCode::NoError);
        }

        res.to_vec().ok()
    }
}
