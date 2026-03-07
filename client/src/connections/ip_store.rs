use lru::LruCache;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

pub struct FakeIpStore {
    cache: LruCache<String, Ipv4Addr>,
    pub rev_cache: LruCache<Ipv4Addr, String>,
    next_ip: u32,
}

const START_IP: u32 = 0x64400001; // 100.64.0.1 (IP for Service Networks/Shared Address Space)

impl FakeIpStore {
    pub fn new() -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(2000).unwrap()),
            rev_cache: LruCache::new(NonZeroUsize::new(2000).unwrap()),
            next_ip: START_IP,
        }
    }

    pub fn get_or_assign(&mut self, host: &str) -> Ipv4Addr {
        if let Some(&ip) = self.cache.get(host) {
            return ip;
        }
        let ip = Ipv4Addr::from(self.next_ip);
        self.next_ip += 1;
        self.cache.put(host.to_string(), ip);
        self.rev_cache.put(ip, host.to_string());
        ip
    }

    pub fn lookup_by_ip(&self, ip: &Ipv4Addr) -> Option<String> {
        self.rev_cache.peek(ip).cloned()
    }
}
