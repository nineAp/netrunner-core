use crate::connections::ip_store::FakeIpStore;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use netrunner_logger::{debug, error, info, warn};
use std::collections::HashSet;
use std::time::{Duration, SystemTime};
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, BufReader};
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

    pub async fn init(&mut self) -> anyhow::Result<()> {
        let path = std::path::PathBuf::from(&self.cache_path);

        if path.exists() {
            let _ = self.load_from_file().await;
        }

        let needs_update = if let Ok(meta) = fs::metadata(&path).await {
            SystemTime::now()
                .duration_since(meta.modified()?)
                .unwrap_or_default()
                > Duration::from_secs(604800)
        } else {
            true
        };

        if needs_update {
            let p_clone = self.cache_path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Self::download_blocklist(p_clone);
            });
        }

        Ok(())
    }

    fn download_blocklist(cache_path: String) {
        let runtime = crate::RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime")
        });

        runtime.block_on(async move {
            info!("DNS: Starting background download to {}", cache_path);

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build();

            let client = match client {
                Ok(c) => c,
                Err(e) => {
                    netrunner_logger::error!("DNS: Failed to create client: {}", e);
                    return;
                }
            };

            match client
                .get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(bytes) = resp.bytes().await {
                        if let Err(e) = tokio::fs::write(&cache_path, bytes).await {
                            netrunner_logger::error!("DNS: File write error: {}", e);
                        } else {
                            info!("DNS: Blocklist downloaded successfully to {}", cache_path);
                        }
                    }
                }
                Ok(resp) => {
                    netrunner_logger::error!("DNS: Download failed with status {}", resp.status())
                }
                Err(e) => {
                    netrunner_logger::error!("DNS: Request error (check internet/TLS): {}", e)
                }
            }
        });
    }

    async fn load_from_file(&mut self) -> anyhow::Result<()> {
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
        info!("DNS: Loaded {} domains from cache.", count);
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

        // Проверка блокировок
        if self.forbidden_suffixes.iter().any(|s| name.ends_with(s))
            || self.block_list.contains(&name)
        {
            info!(domain = %name, "DNS: Blocked");
            res.set_response_code(ResponseCode::NXDomain);
            return res.to_vec().ok();
        }

        if query.query_type() == RecordType::A {
            let fake_ip = store.get_or_assign(&name);
            res.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(fake_ip.into()),
            ));
            res.set_response_code(ResponseCode::NoError);
        }

        res.to_vec().ok()
    }
}
