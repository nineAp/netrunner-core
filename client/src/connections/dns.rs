use crate::connections::ip_store::FakeIpStore;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use netrunner_logger::{debug, error, info, warn};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

pub struct DnsHandler {
    block_list: HashSet<String>,
    forbidden_suffixes: Vec<String>,
    cache_path: String,
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            block_list: HashSet::new(),
            forbidden_suffixes: vec![
                ".lan".to_string(),
                ".local".to_string(),
                ".home".to_string(),
                ".arpa".to_string(),
            ],
            cache_path: "hosts_cache.txt".to_string(),
        }
    }

    /// Основной метод инициализации: решает, качать или брать из кэша
    pub fn init(&mut self) -> anyhow::Result<()> {
        let url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
        let path = Path::new(&self.cache_path);

        let should_download = if path.exists() {
            let metadata = fs::metadata(path)?;
            let last_modified = metadata.modified()?;
            let elapsed = SystemTime::now().duration_since(last_modified)?.as_secs();

            elapsed > 604800
        } else {
            true
        };

        if should_download {
            info!("Blocklist is outdated or missing. Trying to download...");
            if let Err(e) = self.download_and_cache(url) {
                warn!(
                    "Failed to download blocklist ({}), trying to use cache if available",
                    e
                );
            }
        }

        if path.exists() {
            self.load_from_file()?;
        } else {
            error!("No blocklist available (neither online nor cache)!");
        }

        Ok(())
    }

    fn download_and_cache(&self, url: &str) -> anyhow::Result<()> {
        let mut response = reqwest::blocking::get(url)?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Server returned status {}",
                response.status()
            ));
        }

        let mut file = File::create(&self.cache_path)?;
        response.copy_to(&mut file)?;
        info!("Blocklist downloaded and cached locally.");
        Ok(())
    }

    fn load_from_file(&mut self) -> anyhow::Result<()> {
        let file = File::open(&self.cache_path)?;
        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Берем домен (второй столбец в StevenBlack hosts)
                self.block_list.insert(parts[1].to_lowercase());
                count += 1;
            }
        }
        info!("Loaded {} domains from cache.", count);
        Ok(())
    }

    pub fn handle_query(&self, data: &[u8], store: &mut FakeIpStore) -> Option<Vec<u8>> {
        let request = Message::from_vec(data).ok()?;
        let query = request.queries().first()?;

        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_recursion_available(true)
            .add_query(query.clone());

        let name = query
            .name()
            .to_string()
            .trim_end_matches('.')
            .to_lowercase();

        // 1. Спец. суффиксы
        if self.forbidden_suffixes.iter().any(|s| name.ends_with(s)) {
            info!(domain = %name, "DNS: Blocked (Suffix)");
            response.set_response_code(ResponseCode::NXDomain);
            return response.to_vec().ok();
        }

        // 2. Бан-лист (AdBlock)
        if self.block_list.contains(&name) {
            info!(domain = %name, "DNS: Blocked (AdList)");
            response.set_response_code(ResponseCode::NXDomain);
            return response.to_vec().ok();
        }

        // 3. Fake IP Logic
        match query.query_type() {
            RecordType::A => {
                let fake_ip = store.get_or_assign(&name);
                let record = Record::from_rdata(query.name().clone(), 60, RData::A(fake_ip.into()));
                response.set_response_code(ResponseCode::NoError);
                response.add_answer(record);
            }
            _ => {
                response.set_response_code(ResponseCode::NoError);
            }
        }

        response.to_vec().ok()
    }
}
