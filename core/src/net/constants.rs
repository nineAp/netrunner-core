use std::time::Duration;

pub const MAX_SOCKETS: usize = 256;
pub const MAX_TUNNEL_LEGS: u32 = 4;
pub const MUXER_POOL_SIZE: usize = 3;

pub const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
pub const GLOBAL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

// 🔥 ФИКС: Ускоряем обнаружение мертвой сети при переключении Wi-Fi -> LTE
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(3); // Было 7
pub const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(20); // Было 10
pub const LEG_RECONNECT_DELAY: Duration = Duration::from_secs(2); // Было 3
pub const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub const DNS_PORT: u16 = 53;
pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;
pub const NETBIOS_PORTS: [u16; 2] = [137, 138];

pub const AUTH_TIME_STEP: u64 = 60;
pub const AUTH_WINDOW_SIZE: u64 = 2;

pub const LEG_STAGGER_DELAY: Duration = Duration::from_millis(1000); // Чуть ускорили старт
pub const TOPOLOGY_PRINT_INTERVAL: Duration = Duration::from_secs(10);

pub const STEALTH_FALLBACK_HOST: &str = "ubuntu.com:443";
pub const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub const TLS_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
pub const SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
