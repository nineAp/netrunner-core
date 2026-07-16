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
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use lru::LruCache;
use netrunner_logger::{debug, error, info, warn};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::fs::{self, File};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;

/// Публичный резолвер для исключённых доменов — намеренно НЕ системный
/// (`tokio::net::lookup_host`/getaddrinfo): на активном туннеле системный
/// DNS сам смотрит на 10.0.0.2 (см. `resolvectl dns netr0`/DNAT в routing.rs),
/// то есть запрос туда просто вернулся бы в этот же обработчик по кругу.
/// Прямой UDP-запрос на публичный резолвер — единственный способ узнать
/// реальный IP, не полагаясь на системный DNS. Сам этот IP явно выведен
/// из-под захвата туннелем на уровне routing.rs (nftables/route-исключение),
/// иначе и этот прямой запрос ушёл бы в туннель.
const PUBLIC_DNS_RESOLVER: &str = "1.1.1.1:53";
const PUBLIC_DNS_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Домены в обход туннеля.
    excluded_domains: HashSet<String>,
    /// Реальные IP исключённых доменов, уже разрешённые фоновой задачей (см.
    /// `engine.rs::build` — та же задача, что ставит явные bypass-маршруты).
    /// `Arc<DashMap<..>>`, а не приватное поле: тот же экземпляр разделяется
    /// с фоновой задачей, чтобы она писала сюда результат резолва, а
    /// `handle_query` читал его синхронно, без единого `.await` в горячем
    /// пути обработки пакетов.
    resolved_excluded: Arc<DashMap<String, Ipv4Addr>>,
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
            resolved_excluded: Arc::new(DashMap::new()),
        }
    }

    /// Клон `Arc` на карту разрешённых исключённых доменов — отдаётся фоновой
    /// задаче резолва (см. `engine.rs::build`), чтобы она могла класть сюда
    /// результаты `resolve_via_public_dns` по мере готовности.
    pub fn resolved_excluded_map(&self) -> Arc<DashMap<String, Ipv4Addr>> {
        self.resolved_excluded.clone()
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
    /// Порядок решений: исключённый домен, уже разрешённый фоновой задачей →
    /// реальный A-record (см. `resolved_excluded`); исключённый, но ещё не
    /// разрешённый (узкое окно сразу после подключения) → ServFail; приватный
    /// суффикс/блок-лист → NXDomain; A-запрос → фейковый IP; прочее → пустой
    /// NoError. `None` — если запрос не разобрался.
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
            if let Some(real_ip) = self.resolved_excluded.get(&name).map(|e| *e.value()) {
                // Раньше здесь всегда стоял ServFail в расчёте на то, что ОС
                // сама повторит запрос через "настоящий" DNS — но пока
                // туннель активен, netr0 прописан ЕДИНСТВЕННЫМ резолвером на
                // ВСЕ домены (см. `resolvectl domain netr0 ~.` в routing.rs),
                // и повторить запрос буквально некуда: ServFail просто рвал
                // резолв для исключённого домена целиком (трафик на него
                // не шёл вообще, ни с killswitch, ни без). Отдаём здесь уже
                // реальный IP, разрешённый фоновой задачей через публичный
                // DNS в обход туннеля (см. `resolve_via_public_dns` /
                // `engine.rs::build`) — тот же IP, для которого уже стоит
                // явный bypass-маршрут в обход VPN.
                netrunner_logger::info!("Excluded domain {} -> real IP {} (bypass)", name, real_ip);
                res.add_answer(Record::from_rdata(
                    query.name().clone(),
                    FAKE_DNS_TTL,
                    RData::A(real_ip.into()),
                ));
                res.set_response_code(ResponseCode::NoError);
                return res.to_vec().ok();
            }

            // Ещё не разрешено (узкое окно сразу после connect, пока фоновая
            // задача не успела отработать) — тут ServFail оправдан: это
            // именно транзиентное состояние, а не постоянный тупик, и
            // следующий повтор запроса (обычно секунды спустя) уже попадёт
            // в ветку выше.
            netrunner_logger::info!(
                "Excluded domain {} not yet resolved via public DNS, ServFail (transient)",
                name
            );
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

/// Разрешает домен в реальный IPv4 напрямую через публичный резолвер
/// (`PUBLIC_DNS_RESOLVER`), в обход системного DNS — см. комментарий у
/// константы выше про то, почему `tokio::net::lookup_host`/getaddrinfo
/// здесь не годится (циклический захват тем же fake-DNS обработчиком).
///
/// Вызывается фоновой задачей в `engine.rs::build()` для каждого
/// исключённого домена; результат кладётся в `resolved_excluded_map()`,
/// откуда его синхронно читает `handle_query`.
pub async fn resolve_via_public_dns(domain: &str) -> Option<Ipv4Addr> {
    let name = match Name::from_str(domain) {
        Ok(n) => n,
        Err(e) => {
            warn!(
                "resolve_via_public_dns: invalid domain name {}: {}",
                domain, e
            );
            return None;
        }
    };

    let mut query = Query::new();
    query.set_name(name).set_query_type(RecordType::A);

    // ID транзакции не нужен криптостойким — только чтобы не совпадать
    // между параллельными запросами; берём младшие биты текущих наносекунд,
    // не таща отдельную зависимость от `rand` ради одного вызова.
    let query_id = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);

    let mut req = Message::new();
    req.set_id(query_id)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true)
        .add_query(query);

    let Ok(req_bytes) = req.to_vec() else {
        warn!(
            "resolve_via_public_dns: failed to encode query for {}",
            domain
        );
        return None;
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("resolve_via_public_dns: bind failed for {}: {}", domain, e);
            return None;
        }
    };

    if tokio::time::timeout(PUBLIC_DNS_TIMEOUT, socket.connect(PUBLIC_DNS_RESOLVER))
        .await
        .map_err(|_| "timeout")
        .and_then(|r| r.map_err(|_| "connect error"))
        .is_err()
    {
        warn!(
            "resolve_via_public_dns: failed to reach public resolver {} for {}",
            PUBLIC_DNS_RESOLVER, domain
        );
        return None;
    }

    if tokio::time::timeout(PUBLIC_DNS_TIMEOUT, socket.send(&req_bytes))
        .await
        .map_err(|_| "timeout")
        .and_then(|r| r.map_err(|_| "send error"))
        .is_err()
    {
        warn!("resolve_via_public_dns: send failed for {}", domain);
        return None;
    }

    let mut buf = [0u8; 512];
    let len = match tokio::time::timeout(PUBLIC_DNS_TIMEOUT, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => len,
        _ => {
            warn!(
                "resolve_via_public_dns: no response (timeout) for {}",
                domain
            );
            return None;
        }
    };

    let resp = match Message::from_vec(&buf[..len]) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                "resolve_via_public_dns: malformed response for {}: {}",
                domain, e
            );
            return None;
        }
    };

    let ip = resp
        .answers()
        .iter()
        .find_map(|record| match record.data().ip_addr() {
            Some(std::net::IpAddr::V4(ip)) => Some(ip),
            _ => None,
        });

    if ip.is_none() {
        warn!(
            "resolve_via_public_dns: no A record in response for {}",
            domain
        );
    }
    ip
}
