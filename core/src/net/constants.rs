//! Все «магические числа» сетевого ядра в одном месте.
//!
//! Сгруппированы по назначению (пулы, тайм-ауты, аутентификация, порты, stealth,
//! кодек, тюнинг сокетов). Многие значения — результат борьбы с конкретными
//! проблемами (bufferbloat, «эффект домино» при падении ноги, рассинхрон часов);
//! у таких констант в `///`-комментарии объяснено, **почему** именно это число, а
//! не просто что оно значит. Меняя их, читайте обоснование рядом.

use std::time::Duration;

// ── Connection pool ──────────────────────────────────────────────────────────
/// Максимум одновременных smoltcp-сокетов (виртуальных соединений) на клиенте.
pub const MAX_SOCKETS: usize = 256;
/// Сколько параллельных TCP-ног держит туннель (для throughput и отказоустойчивости).
pub const MAX_TUNNEL_LEGS: u32 = 4;
/// Размер пула мультиплексоров.
pub const MUXER_POOL_SIZE: usize = 3;
/// Weight applied to observed congestion when scoring tunnel legs.
pub const MUXER_CONGESTION_WEIGHT: f64 = 2000.0;
/// Initial RTT estimate used before any real measurement arrives.
pub const INITIAL_RTT_MS: u32 = 250;

// ── Timeouts ─────────────────────────────────────────────────────────────────
/// Тайм-аут TCP-хендшейка к целевому хосту (серверная сторона).
pub const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Простой UDP-сессии, после которого она считается завершённой.
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// Глобальный простой соединения до его закрытия.
pub const GLOBAL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Период health-check'ов ног туннеля (heartbeat/проверка живости).
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(3);
/// Сколько ждать ответа на health-check, прежде чем счесть ногу мёртвой.
pub const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(20);
/// Пауза перед переподключением упавшей ноги.
pub const LEG_RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Простой моста (стрима) до его закрытия.
pub const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time to wait for a local app socket to accept downloaded data.
/// If the app's receive buffer stays full longer than this, the connection
/// is closed to unblock the tunnel leg for other streams.
pub const BRIDGE_STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// While *every* tunnel leg is momentarily down (all reconnecting), an upload
/// stream holds its current chunk and retries instead of closing — turning a
/// leg outage into a short pause rather than a mass stream reset. This bounds
/// how long a stream will wait before it finally gives up and closes.
pub const STREAM_PAUSE_BUDGET: Duration = Duration::from_secs(30);
/// Poll interval while a paused upload stream waits for a leg to come back.
pub const STREAM_PAUSE_RETRY: Duration = Duration::from_millis(250);
/// Grace window dispatch_to_local waits when a stream's receive channel is full
/// before closing that ONE stream. The hot path now uses try_send (no await), so
/// this applies only to a genuinely backed-up consumer; kept short so a slow or
/// dead stream (e.g. a finished speedtest socket the app stopped reading) can
/// never head-of-line-block the shared per-leg reader and freeze every other
/// download on that leg (was 10 s — caused multi-second download stalls).
pub const DISPATCH_TO_LOCAL_TIMEOUT: Duration = Duration::from_millis(300);
pub const TLS_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
pub const SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
pub const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for resolving a proxy address via DNS.
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// Delay between leg reconnect attempts (base); actual delay adds random jitter.
pub const RECONNECT_BACKOFF_BASE: Duration = Duration::from_millis(2000);
/// Upper bound of the random jitter added to `RECONNECT_BACKOFF_BASE`.
pub const RECONNECT_BACKOFF_JITTER_MS: u64 = 1000;
/// After this many consecutive internal reconnect failures the engine gives up
/// and returns Err to the outer establish_leg loop, which re-runs DNS resolution
/// and resets all counters.  10 × ~18 s ≈ 3 minutes max stuck-silent time.
pub const MAX_INTERNAL_RECONNECT_ATTEMPTS: u32 = 10;
/// Cap for exponential reconnect backoff inside the engine (milliseconds).
pub const MAX_RECONNECT_BACKOFF_MS: u64 = 30_000;
/// How long to wait before removing an idle session after all legs drop.
pub const SESSION_CLEANUP_DELAY: Duration = Duration::from_secs(120);
/// How often the network-change watcher checks the local IP address.
pub const NETWORK_WATCHER_INTERVAL: Duration = Duration::from_secs(1);

// ── Logging ───────────────────────────────────────────────────────────────────
pub const LEG_STAGGER_DELAY: Duration = Duration::from_millis(1000);
pub const TOPOLOGY_PRINT_INTERVAL: Duration = Duration::from_secs(10);
/// How often the client engine logs traffic statistics.
pub const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);

// ── Authentication ───────────────────────────────────────────────────────────
/// Длительность одного шага time-based auth-тега в секундах (TOTP-«окно»).
/// Тег меняется раз в 60 с — см. [`SessionAuth`](crate::nrxp).
pub const AUTH_TIME_STEP: u64 = 60;
/// Допуск на рассинхрон часов при проверке тега: ±2 шага (~±2 минуты).
/// Сужает окно replay, оставляя запас под дрейф NTP и сетевые задержки.
pub const AUTH_WINDOW_SIZE: u64 = 2;

// ── Well-known ports ─────────────────────────────────────────────────────────
// Известные порты для эвристик классификации трафика (heavy/light, спец-обработка).
pub const DNS_PORT: u16 = 53;
pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;
pub const HTTP_ALT_PORT: u16 = 8080;
pub const SSH_PORT: u16 = 22;
pub const RDP_PORT: u16 = 3389;
pub const VNC_PORT: u16 = 5900;
pub const RTMP_PORT: u16 = 1935;
pub const NTP_PORT: u16 = 123;
pub const NETBIOS_PORTS: [u16; 2] = [137, 138];

// ── TLS / stealth ────────────────────────────────────────────────────────────
/// Hostname used as the SNI in the stealth TLS ClientHello.
pub const STEALTH_FALLBACK_SNI: &str = "ubuntu.com";
pub const STEALTH_FALLBACK_HOST: &str = "ubuntu.com:443";

// ── Tunnel frame codec ───────────────────────────────────────────────────────
/// OOM guard: drop the leg if the read buffer grows past this.
pub const TUNNEL_MAX_BUFFER_SIZE: usize = 1024 * 1024;
/// Bytes reserved in the read buffer before each `read_buf` call.
pub const TUNNEL_READ_RESERVE: usize = 16 * 1024;
/// Maximum bytes written per stream in a single interleaved write pass.
pub const TUNNEL_INTERLEAVE_CHUNK: usize = 16 * 1024;
/// Max bytes a stream bridge reads per pass before producing a data message.
/// Bounds the size of a single MuxMessage so the per-leg queue is byte-bounded
/// (CHANNEL_PACKETS × this), keeping post-speedtest bufferbloat small. One NRXP
/// frame is 16 KB, so reading in 16 KB units also aligns with the wire framing.
pub const BRIDGE_READ_CHUNK: usize = 16 * 1024;

// ── Tunnel leg TCP socket tuning ─────────────────────────────────────────────
/// OS-level TCP send buffer for each tunnel leg.  The default (4–8 MB on
/// Linux/Android) can hold seconds of data at typical mobile speeds, causing
/// severe jitter.  128 KB limits extra queuing to ~40 ms at 25 Mbit/s per leg
/// while still providing enough headroom for TCP slow-start.  (Halved from
/// 256 KB to cut post-speedtest bufferbloat — see CHANNEL_PACKETS.)
pub const TUNNEL_SOCKET_SNDBUF: u32 = 128 * 1024;
/// OS-level TCP receive buffer for each tunnel leg.  Larger than the send
/// buffer so the receiver can absorb bursts without dropping packets, but
/// bounded to keep stale in-flight download data (for already-closed streams)
/// small so the tunnel recovers in ~1 s after a heavy download.
pub const TUNNEL_SOCKET_RCVBUF: u32 = 256 * 1024;

// ── Smoltcp socket defaults ──────────────────────────────────────────────────
/// Packet slots for the ICMP socket's RX and TX packet buffers.
pub const ICMP_META_SLOTS: usize = 4;
/// Byte capacity of the ICMP socket's RX and TX data buffers.
pub const ICMP_BUFFER_SIZE: usize = 512;
/// Log a bufferbloat warning when the application-layer queue exceeds this.
pub const BUFFERBLOAT_WARN_THRESHOLD: usize = 1024 * 1024;
