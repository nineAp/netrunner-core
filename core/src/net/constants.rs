use std::time::Duration;

// --- Лимиты системы ---
pub const MAX_SOCKETS: usize = 2048; // Лимит сокетов в SocketSet (Anti-DDoS)
pub const MAX_TUNNEL_LEGS: u32 = 10; // Максимальное кол-во физических соединений (Legs)
pub const MUXER_POOL_SIZE: usize = 2; // Из скольких лучших Leg-ов выбирать для балансировки

// --- Таймауты ---
pub const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20); // Время на установку SYN/ACK
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60); // Смерть UDP сессии без данных
pub const GLOBAL_IDLE_TIMEOUT: Duration = Duration::from_secs(120); // Очистка Tracker-ом
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5); // Частота пинга Leg-ов
pub const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
pub const LEG_RECONNECT_DELAY: Duration = Duration::from_secs(5); // Пауза перед реконнектом Leg
pub const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // Таймаут задач-бриджей

// --- Сетевые порты ---
pub const DNS_PORT: u16 = 53;
pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;
pub const NETBIOS_PORTS: [u16; 2] = [137, 138];

// --- Критические оверхеды (для MTU/MSS) ---
pub const IPV4_TCP_OVERHEAD: usize = 40; // IPv4(20) + TCP(20)
pub const NRXP_OVERHEAD: usize = 254; // Запас под заголовки твоего протокола и TLS

// --- Настройки безопасности ---
pub const AUTH_TIME_STEP: u64 = 60; // Шаг генерации токена (секунды)
pub const AUTH_WINDOW_SIZE: u64 = 2; // Допуск шагов времени (current +/- 2)

// --- Настройки Multipath (Legs) ---
pub const LEG_STAGGER_DELAY: Duration = Duration::from_millis(250);
pub const TOPOLOGY_PRINT_INTERVAL: Duration = Duration::from_secs(15);

// --- Настройки Stealth Fallback (Маскировка) ---
pub const STEALTH_FALLBACK_HOST: &str = "ubuntu.com:443";
pub const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

// --- Таймауты Handshake ---
pub const TLS_HELLO_TIMEOUT: Duration = Duration::from_secs(1);
pub const SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
