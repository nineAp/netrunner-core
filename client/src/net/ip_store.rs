use lru::LruCache;
use netrunner_logger::{debug, info};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

pub struct FakeIpStore {
    cache: LruCache<String, Ipv4Addr>,
    rev_cache: LruCache<Ipv4Addr, String>,
    next_ip: u32,
}

const START_IP: u32 = 0x64400001;

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
