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

// ── Datagram (UDP) leg ───────────────────────────────────────────────────────
/// Зарезервированный `leg_id` физической UDP-ноги в диагностике/логах —
/// никогда не пересекается с TCP-ногами (`0..MAX_TUNNEL_LEGS`), потому что
/// она не часть `Muxer::legs` вообще (см. докстринг поля `datagram_leg`).
pub const DATAGRAM_LEG_ID: u32 = u32::MAX;
/// Сколько ждать ЛЮБОЙ успешно расшифрованной датаграммы в ответ на первую
/// отправленную, прежде чем считать попытку установки UDP-ноги неудавшейся
/// и остаться на TCP. Одна попытка на сессию (см. `docs/UDP_LEG_RESEARCH.md`
/// §1) — без агрессивных ретраев, потому что блокировка UDP в сети обычно
/// постоянна на весь сеанс, а не транзиентна.
pub const DATAGRAM_LEG_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Потолок полезной нагрузки (байт прикладной UdpData) для одной датаграммы
/// физической UDP-ноги. Кадр крупнее уходит по TCP-ноге как `UdpData`, а не
/// фрагментируется (правило §1.3 исследования, bug #5).
///
/// Считаем консервативно от целевого внешнего размера UDP-пейлоада ~1250 байт
/// (с запасом под самый агрессивный DPI и типичный туннельный MTU 1400+):
/// ```text
///   1250  внешний UDP-пейлоад
///  -  21  худшая обвязка движка (raw: 16 leg_token + 1 epoch + 4 counter;
///         quic ~13, rtp 12+1 — все меньше)
///  -  25  заголовок кадра NRXP (FRAME_HEADER_SIZE)
///  -  16  AEAD-тег
///  = 1188  → округляем вниз до 1150 ради запаса на будущую обвязку
/// ```
/// UdpData не паддится (`padding_len == 0` в `nrxp::datagram`), поэтому иных
/// слагаемых нет. С IP+UDP-заголовками (28 v4 / 48 v6) внешний пакет остаётся
/// заметно ниже 1500 даже на IPv6.
pub const MAX_DATAGRAM_LEG_PAYLOAD: usize = 1150;

/// Сервер: первый `UdpData` нового потока может обогнать по быстрой UDP-ноге
/// свой же `UdpConnect`, который едет по TCP и регистрирует поток (bug #4).
/// Такие ранние датаграммы буферизуются вместо отбрасывания и сливаются в поток
/// при его регистрации. Границы буфера жёсткие — это защита от DoS
/// (аутентифицированный клиент иначе слал бы `UdpData` на случайные stream_id,
/// раздувая память): не больше [`MAX_PENDING_UDP_STREAMS`] ожидающих потоков,
/// не больше [`PENDING_UDP_STREAM_MAX_BYTES`] на поток, и не дольше
/// [`PENDING_UDP_TTL`] (после — подметает `spawn_backlog_reaper`).
pub const MAX_PENDING_UDP_STREAMS: usize = 256;
pub const PENDING_UDP_STREAM_MAX_BYTES: usize = 16 * 1024;
pub const PENDING_UDP_TTL: Duration = Duration::from_secs(2);

/// Keepalive физической UDP-ноги на ПРОСТОЕ: интервал берётся случайно из
/// `[MIN, MAX]` на каждую пробу, а не фиксированные 3 с. Жёсткий период
/// PING/PONG раз в 3 с — сам по себе признак туннеля (bug #14); настоящий QUIC
/// шлёт keepalive реже и вразброс. Таймер сбрасывается любым реальным кадром,
/// поэтому под нагрузкой PING почти не уходит — freshness держат данные.
/// Верхняя граница с запасом ниже `LEG_PONG_FRESHNESS` (45 с) и типичного
/// UDP-NAT-таймаута (~30 с), чтобы нога не «протухала» и mapping не закрывался.
pub const DATAGRAM_KEEPALIVE_MIN: Duration = Duration::from_secs(15);
pub const DATAGRAM_KEEPALIVE_MAX: Duration = Duration::from_secs(25);

// ── Timeouts ─────────────────────────────────────────────────────────────────
/// Тайм-аут TCP-хендшейка к целевому хосту (серверная сторона).
pub const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Простой UDP-сессии, после которого она считается завершённой.
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// Глобальный простой соединения до его закрытия.
pub const GLOBAL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Базовый период heartbeat'а ноги (writer туннеля). Реальная задержка — это
/// значение с джиттером ±30 % и множителем 1…8 по длительности простоя, см.
/// `TunnelEngine::next_heartbeat_delay`.
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(3);
/// Насколько недавним должен быть PONG, чтобы `Muxer::perform_health_check`
/// счёл ногу заведомо живой и **не слал ей отдельный PING**.
///
/// Heartbeat writer'а и health-check делают ровно одно и то же (PING → PONG →
/// замер RTT), но исторически работали независимо: на пустом туннеле это
/// давало на каждую ногу и heartbeat'ы, и пробы health-check'а — основной
/// объём холостого трафика. Окно взято с запасом над самым медленным
/// heartbeat'ом (3 с × 8 × 1,3 ≈ 31 с), чтобы на простое проба не срабатывала
/// вообще.
///
/// **Цена:** на полностью idle-ноге обнаружение обрыва растягивается до
/// `LEG_PONG_FRESHNESS + HEALTH_CHECK_TIMEOUT` (~65 с) вместо ~30 с. Это
/// сознательно: пока по ноге нет трафика, её смерть ничего не стоит, а первая
/// же попытка записи упрётся в ошибку сокета и уведёт поток на соседнюю ногу
/// немедленно, не дожидаясь health-check'а.
pub const LEG_PONG_FRESHNESS: Duration = Duration::from_secs(45);
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
/// Memory budget for one stream's local-delivery backlog (see
/// `Muxer::dispatch_to_local`). When a stream's receive channel is momentarily
/// full, frames queue here instead of blocking the shared per-leg reader — so a
/// slow-but-alive consumer (disk write hiccup, TUN backpressure, scheduler
/// jitter) gets as long as it needs to drain, while a genuinely dead stream
/// (e.g. a finished speedtest socket the app stopped reading) is caught by
/// exceeding this bound rather than by guessing a latency. Bytes, not
/// milliseconds, because "how slow is too slow" has no universal answer but
/// "how much unread data are we willing to hold for one stalled stream" does.
pub const STREAM_BACKLOG_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Same budget, but for server-side streams (tunnel → real internet target,
/// i.e. the user's upload direction — see `bridge.rs` module docs for the
/// upload/download naming). Bigger than the client default: a remote target
/// is inherently slower and more variable than the local TUN device, so
/// uploads need more slack before a stalled target is judged dead.
pub const SERVER_STREAM_BACKLOG_MAX_BYTES: usize = 16 * 1024 * 1024;
/// How often the background backlog reaper (`Muxer::spawn_backlog_reaper`) scans
/// streams for genuinely stuck consumers. Runs off the hot path entirely — the
/// dispatch call itself never evicts anything — so this only bounds how far a
/// dead stream's backlog can overshoot its byte budget between ticks.
pub const BACKLOG_REAPER_INTERVAL: Duration = Duration::from_millis(500);
/// Grace window: a stream over its backlog byte budget is evicted only once it
/// has ALSO made no delivery progress for this long. Separates "backlog is
/// big because the producer is fast and still draining" from "backlog is big
/// because the consumer stopped entirely" — a raw byte cap alone can't tell
/// those apart, and evicting the former destabilizes healthy fast downloads.
pub const BACKLOG_STUCK_GRACE: Duration = Duration::from_secs(5);
/// How long a `Muxer` with zero legs and zero streams is kept alive before its
/// backlog reaper self-terminates. Without this, every session's reaper task
/// (and the Arc'd registries it keeps alive) would leak forever on a server
/// that has served many short-lived client sessions.
pub const BACKLOG_REAPER_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

// ── End-to-end credit flow control (Muxer::init_credit/grant_credit/consume_credit) ──
/// Initial credit window granted to a stream's sender: how many bytes it may
/// push into the tunnel before it must wait for the receiver to grant more via
/// a `Credit` frame. Bounds how much can ever be "in flight" for one stream —
/// unlike the local byte-budget backlog (a last-resort backstop), this stops
/// the sender from ever producing the excess in the first place, so a slow
/// receiver never has to buffer-then-give-up.
pub const STREAM_CREDIT_INITIAL: u32 = 2 * 1024 * 1024;
/// The receiver batches freed bytes and sends one `Credit` frame per this many
/// bytes reclaimed, instead of one per delivered frame — same idea as TCP
/// delayed window updates, avoids flooding tiny control frames. Deliberately
/// finer than a quarter of the (possibly RTT-scaled, see
/// `adaptive_credit_window`) sender window: the receiver has no way to know
/// the sender's actual multiplier, and smaller/more frequent grants keep the
/// window topped up with less slack regardless of how big it ended up being.
pub const STREAM_CREDIT_RETURN_THRESHOLD: u32 = STREAM_CREDIT_INITIAL / 8;
/// How long `consume_credit` waits on each poll before re-checking the balance
/// (bounds the delay from a `notify` race, not a hard deadline by itself).
pub const CREDIT_WAIT_POLL: Duration = Duration::from_secs(2);
/// If the peer hasn't granted any credit at all for this long, treat it as not
/// speaking the credit protocol (or badly behind) and fall back to unrestricted
/// sending rather than stalling the stream forever — the byte-budget backlog
/// and its reaper remain the ultimate backstop either way.
pub const CREDIT_FALLBACK_AFTER: Duration = Duration::from_secs(10);
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
/// Нога, умершая быстрее этого после успешного реконнекта, считается
/// «флапающей»: следующий реконнект идёт с экспоненциальной паузой (см.
/// `TunnelEngine::run`). Типичный случай — сервер отверг токен сразу после
/// хендшейка.
pub const LEG_FLAP_WINDOW: Duration = Duration::from_secs(5);
/// Cap for exponential reconnect backoff inside the engine (milliseconds).
///
/// Was 30 s: after a network dropout the legs could still be sleeping through a
/// 16-30 s backoff once the network was back, i.e. "internet stands" for up to half
/// a minute after it returned. 10 s keeps the thundering-herd protection (the jitter
/// in the engine grows with the step) but bounds that tail.
pub const MAX_RECONNECT_BACKOFF_MS: u64 = 10_000;
/// How long to wait before removing an idle session after all legs drop.
pub const SESSION_CLEANUP_DELAY: Duration = Duration::from_secs(120);
/// How often the network-change watcher checks the local IP address.
pub const NETWORK_WATCHER_INTERVAL: Duration = Duration::from_secs(1);

/// Сколько туннель может простоять вообще без единой живой ноги, прежде чем
/// клиентский движок признает сессию мёртвой и завершится.
///
/// Без этого порога приложение врало: `CONN_CONNECTED` выставляется один раз
/// при сборке движка и сбрасывается только когда `Engine::run` вернулся, а
/// вернуться он мог лишь по `Muxer::is_fatal` — то есть исключительно когда
/// сервер отверг токен. Все четыре ноги мертвы, отправлять некуда, а
/// интерфейс показывает «подключено»; на Android это ещё и утечка, потому что
/// закрытый TUN отдаёт трафик обратно системе.
///
/// Значение — компромисс. Меньше — и обычный реконнект (пауза 2 с плюс
/// хендшейк) начнёт ронять живые сессии на каждом чихе сети. Больше — и
/// пользователь дольше сидит с мёртвым туннелем, не зная об этом. Тридцать
/// секунд заведомо переживают штатное переподключение и смену сети, но не
/// оставляют «подключено» на минуты.
pub const TUNNEL_DEAD_AFTER: Duration = Duration::from_secs(30);
/// После смены сети туннель без единой ноги не считается мёртвым так долго: новая
/// сеть (LTE/Wi-Fi) бывает готова не сразу, а пока `remove_all_legs` снял все ноги,
/// 30 с без ног — норма, а не смерть. Android на `CONN_FAILED` гасит VPN-интерфейс, и
/// пользователь видел «туннель падает при смене сети». Отсчёт `TUNNEL_DEAD_AFTER`
/// идёт заново после окончания этого окна.
pub const NETWORK_CHANGE_DEAD_GRACE: Duration = Duration::from_secs(90);
/// Сколько адрес может отсутствовать (Wi-Fi выключили, LTE ещё не поднялся), чтобы
/// его возвращение считалось сменой сети даже при том же IP: сокеты за это время
/// почти наверняка умерли.
pub const NETWORK_GAP_IS_CHANGE: Duration = Duration::from_secs(3);

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
/// Домен-декой по умолчанию: и SNI клиентского `ClientHello`, и цель
/// server-side stealth-fallback (см. [`ServerHandler`](crate::net::ServerHandler)).
/// Оба реальных сервера сейчас настраиваются на лету (CLI-флаг `--decoy-host`
/// у сервера, [`EngineConfig::with_decoy_sni`](../../../../client/src/net/engine.rs)
/// у клиента) — это значение только запасной дефолт, если ничего не задано явно.
///
/// Раньше здесь был захардкожен `ubuntu.com`: он у Fastly отдаёт `403` без
/// точного совпадения SNI/Host — ровно тот случай, когда браузер заходит прямо
/// по IP (SNI для IP-литералов не шлётся вовсе, RFC 6066). `www.debian.org` —
/// одиночный Apache-ориджин без CDN-роутинга, отдаёт `200` независимо от SNI/Host.
pub const DEFAULT_DECOY_HOST: &str = "www.debian.org";

// ── Tunnel frame codec ───────────────────────────────────────────────────────
/// OOM guard: drop the leg if the read buffer grows past this.
pub const TUNNEL_MAX_BUFFER_SIZE: usize = 1024 * 1024;
/// Bytes reserved in the read buffer before each `read_buf` call.
pub const TUNNEL_READ_RESERVE: usize = 16 * 1024;
/// Maximum bytes written per stream in a single interleaved write pass.
/// Base value; adaptive_batch_chunk multiplies this by (1 + RTT_ms / 250) up to 4×.
/// At 300+ ms RTT, expect ~64 KB per pass (4× base), batching more frames per syscall.
///
/// Deliberately **exactly one frame payload**, not a round 16 KiB. `handle_outbound`
/// slices a message into `MAX_FRAME_PAYLOAD` frames, so a chunk that is not a
/// multiple of it leaves a tiny remainder frame on every single pass — with
/// 16384 against a 16360 payload cap that was a 24-byte frame after every full
/// one, i.e. a steady "big record, tiny record" alternation visible from the
/// outside as a pattern of its own. Every adaptive multiple of this value stays
/// an exact multiple of the frame payload.
pub const TUNNEL_INTERLEAVE_CHUNK: usize = crate::nrxp::MAX_FRAME_PAYLOAD;
/// Max bytes a stream bridge reads per pass before producing a data message.
/// At high RTT (>300 ms), bigger chunks reduce context switches and improve
/// coalescing in the writer. ~64 KB: still fits in wire frames (several NRXP
/// frames per message) while batching better.
/// Per-leg queue size = CHANNEL_PACKETS × this ≈ 64 × 64 KB = 4 MB baseline.
///
/// Expressed as a whole number of frame payloads for the same reason as
/// [`TUNNEL_INTERLEAVE_CHUNK`]: a full read then slices into exactly four
/// maximum-size frames with no systematic remainder.
pub const BRIDGE_READ_CHUNK: usize = 4 * crate::nrxp::MAX_FRAME_PAYLOAD;

// ── Tunnel leg TCP socket tuning ─────────────────────────────────────────────
// The OS send/receive buffers of a leg are NOT fixed: `connection::buftune`
// keeps them near 2x the measured bandwidth-delay product (floor 256 KB, cap
// [`BUF_CAP`]). The old fixed 1 MB / 256 KB capped a leg at `rcvbuf / RTT`
// (~65 Mbit/s at 31 ms) while letting uploads queue seconds of data.
/// Threshold above which Linux withholds socket write-readiness until the
/// amount of not-yet-sent data falls again.  Keeping this close to two NRXP
/// records limits how far a bulk stream can run ahead of the fair writer before
/// a newly-arrived interactive stream gets its turn.
///
/// This is a local socket policy only: it neither changes TCP options on the
/// wire nor the NRXP/TLS record format.  Linux and Android apply it; other
/// targets simply ignore it.
pub const TUNNEL_TCP_NOTSENT_LOWAT: u32 = (2 * crate::nrxp::MAX_FRAME_PAYLOAD) as u32;

// ── Smoltcp socket defaults ──────────────────────────────────────────────────
/// Packet slots for the ICMP socket's RX and TX packet buffers.
pub const ICMP_META_SLOTS: usize = 4;
/// Byte capacity of the ICMP socket's RX and TX data buffers.
pub const ICMP_BUFFER_SIZE: usize = 512;
/// Log a bufferbloat warning when the application-layer queue exceeds this.
pub const BUFFERBLOAT_WARN_THRESHOLD: usize = 1024 * 1024;
