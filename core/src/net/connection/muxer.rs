//! Мультиплексор: распределение логических потоков по физическим ногам туннеля.
//!
//! Сердце сетевого ядра и единственный по-настоящему конкурентный компонент.
//! [`Muxer`] держит реестр ног (TCP-соединений) и потоков (`stream_id`) и решает,
//! по какой ноге отправить каждый кадр. Спроектирован под высокую нагрузку:
//!
//! - **Lock-free горячий путь.** Реестры — это [`DashMap`] (шардированный), а
//!   снапшот ног для выбора — [`ArcSwap`] (чтение = атомарный bump `Arc`, без
//!   read-guard). См. поле `active_legs_cache`.
//! - **Sticky-привязка + ребаланс.** Поток «прилипает» к ноге
//!   (`stream_bindings`), но при её падении мгновенно переезжает на лучшую из
//!   оставшихся (`select_leg`). Среди равных по качеству ног — round-robin, чтобы
//!   всплеск новых потоков не сел на одну «лучшую» ногу (thundering herd).
//! - **Anti-domino failover.** Падение ноги НЕ закрывает поток: дохлая нога
//!   эвиктится, кадр переотправляется на соседнюю; `Err` только когда живых ног
//!   нет вовсе — и тогда мост делает паузу с буфером, а не сброс (см.
//!   `send_to_network` и `run_tcp_bridge`).
//! - **Анти-bufferbloat доставка.** Входящие кадры доставляются неблокирующим
//!   `try_send` (`dispatch_to_local`); если канал потока временно полон, кадр
//!   уходит в его персональный байтовый бэклог вместо ожидания — общий reader
//!   ноги никогда не блокируется на медленном потребителе (head-of-line) и
//!   никогда сам не мутирует реестр потоков. Бэклог дренит отдельная
//!   persistent-задача на поток; закрытие "зависшего" потока — исключительно
//!   работа фонового `spawn_backlog_reaper` (байтовый бюджет
//!   [`STREAM_BACKLOG_MAX_BYTES`]/[`crate::net::SERVER_STREAM_BACKLOG_MAX_BYTES`]
//!   **и** отсутствие прогресса дольше RTT-адаптивного grace-окна —
//!   [`adaptive_write_timeout`] от [`crate::net::BACKLOG_STUCK_GRACE`], та же
//!   логика, что и у медленной-но-живой ноги, — фиксированные 5с раньше
//!   ошибочно убивали, например, upload в реальную цель под высоким RTT) —
//!   решение никогда не принимается изнутри горячего пути доставки, см.
//!   докстринг `StreamBacklog`.
//! - **Credit flow control (сейчас не подключён).** В `Muxer` остаётся API
//!   (`init_credit`/`grant_credit`/`consume_credit`) и кадр `FrameType::Credit`
//!   для сквозного окна получатель→отправитель — идея была не дать отправителю
//!   производить данные быстрее приёмника, вместо того чтобы копить и потом
//!   эвиктить. На практике привязка паузы к сетевому round-trip (ожидание
//!   `Credit`-кадра) оказалась хуже уже работавшего локального backpressure
//!   `data_tx.send().await` (тот реагирует мгновенно, без RTT): давала
//!   burst-then-stall на скачивании и подрывала джиттер/пинг на общей ноге.
//!   Отключено в `run_tcp_bridge` (там просто читают без гейта), байтовый
//!   бэклог + reaper выше остаются единственной защитой.
//!
//! ## Адаптация под RTT
//!
//! [`GLOBAL_MIN_RTT`] обновляется по heartbeat'ам (EWMA). От него зависят
//! [`adaptive_write_timeout`] (не убивать медленную, но живую ногу) и
//! [`adaptive_batch_chunk`] (под высоким RTT слать кадры большими пачками,
//! экономя syscalls).

use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{info, instrument, trace, warn, AppError, ERR_INFRA_TIMEOUT};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{error::TrySendError, Sender};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::net::diagnostics::{self, DiagnosticsEvent, LegMetrics, TunnelMetrics, DIAG_COUNTERS};
use crate::net::INITIAL_RTT_MS;
use crate::net::{
    BACKLOG_REAPER_IDLE_TIMEOUT, BACKLOG_REAPER_INTERVAL, BACKLOG_STUCK_GRACE, BRIDGE_READ_CHUNK,
    DATAGRAM_LEG_ID, MAX_DATAGRAM_LEG_PAYLOAD, MAX_PENDING_UDP_STREAMS, MAX_TUNNEL_LEGS,
    PENDING_UDP_STREAM_MAX_BYTES, PENDING_UDP_TTL, STREAM_BACKLOG_MAX_BYTES,
};
use crate::nrxp::FrameType;

/// Атомарная статистика одной ноги: переданные/принятые байты и сглаженный RTT.
#[derive(Default, Debug)]
pub struct LegStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rtt_ms: AtomicU32,
    /// Payload bytes accepted by the per-leg data channel but not yet written
    /// by its socket writer.  Unlike `Sender::capacity`, this remains accurate
    /// when messages have different sizes and while the fair writer holds them
    /// in its local per-stream queues.
    pub queued_data_bytes: AtomicU64,
    /// Monotonic timestamp at which the currently non-empty data queue became
    /// non-empty.  Zero means no application data is waiting.
    pub queued_since_ms: AtomicU64,
    /// Linux TCP_INFO snapshot.  These stay zero on unsupported platforms.
    pub tcp_notsent_bytes: AtomicU64,
    pub tcp_unacked_bytes: AtomicU64,
    pub tcp_delivery_rate: AtomicU64,
    pub tcp_total_retrans: AtomicU32,
    /// Last time `tcp_total_retrans` increased.  Used as a short-lived penalty
    /// when assigning new streams; historical losses do not poison a leg forever.
    pub last_retrans_ms: AtomicU64,
    /// Момент последнего PONG по ноге, в миллисекундах от [`process_uptime_ms`].
    ///
    /// Нужен, чтобы [`Muxer::perform_health_check`] не слал PING ноге, которая
    /// только что и так ответила: heartbeat writer'а и health-check —
    /// две независимые механики, делающие ровно одно и то же (PING → PONG →
    /// замер RTT), и на живой ноге вторая была чистым дублированием трафика.
    /// `0` означает «PONG ещё не приходил».
    pub last_pong_ms: AtomicU64,
}

/// Монотонные миллисекунды от старта процесса.
///
/// `Instant` нельзя положить в атомик, а для проверки свежести PONG'а нужен
/// именно неблокирующий доступ из горячего пути — отсюда общая точка отсчёта.
fn process_uptime_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Атомарная статистика одного потока: переданные/принятые байты.
#[derive(Default, Debug)]
pub struct StreamStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

/// Байтовый бэклог одного потока на приём.
///
/// Когда канал потока временно полон, кадры копятся здесь вместо того, чтобы
/// блокировать общий ридер ноги (`dispatch_to_local` никогда не ждёт и никогда
/// не мутирует реестр потоков — только кладёт кадр сюда). Решение "поток
/// по-настоящему завис, закрыть" принимает ИСКЛЮЧИТЕЛЬНО фоновый
/// `Muxer::spawn_backlog_reaper`, а не сам вызов доставки: так вызов, держащий
/// `Ref` в `Muxer::streams`, никогда не пытается сам же удалить свой ключ из
/// той же шарды DashMap (что раньше приводило к самоблокировке потока ОС —
/// DashMap не поддерживает реентерабельные локи).
///
/// Условие эвикции у ридера — не просто байтовый бюджет (`cap_bytes`), а бюджет
/// **и** отсутствие прогресса дольше [`BACKLOG_STUCK_GRACE`]: так отличаем
/// «бэклог большой, потому что источник быстрый и продолжает сливаться» от
/// «бэклог большой, потому что потребитель встал намертво».
struct StreamBacklog {
    queue: Mutex<VecDeque<Bytes>>,
    bytes: AtomicUsize,
    cap_bytes: usize,
    notify: Notify,
    /// Метка времени (мс, `current_timestamp_ms`) последней успешной доставки
    /// этому потоку — неважно, быстрым путём или через дренер бэклога.
    last_progress_ms: AtomicU64,
    /// Peer closed the stream after sending everything: once the backlog has been
    /// handed to the consumer, the stream is finished gracefully (consumer sees EOF
    /// instead of being cancelled with data still queued) — see `Muxer::finish_stream`.
    closing: AtomicBool,
}

impl StreamBacklog {
    fn new(cap_bytes: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            bytes: AtomicUsize::new(0),
            cap_bytes,
            notify: Notify::new(),
            last_progress_ms: AtomicU64::new(diagnostics::current_timestamp_ms()),
            closing: AtomicBool::new(false),
        }
    }

    /// Кладёт кадр в бэклог. Никогда не отказывает и не трогает `Muxer::streams` —
    /// решение "хватит ждать" не отсюда, см. докстринг типа.
    fn push(&self, data: Bytes, size: u64) {
        self.bytes.fetch_add(size as usize, Ordering::AcqRel);
        self.queue.lock().unwrap().push_back(data);
        self.notify.notify_one();
    }

    /// Отмечает успешную доставку: сбрасывает счётчик "с каких пор нет прогресса".
    fn mark_progress(&self) {
        self.last_progress_ms
            .store(diagnostics::current_timestamp_ms(), Ordering::Relaxed);
    }
}

/// Ранние `UdpData` потока, чей `UdpConnect` (по TCP) ещё не зарегистрировал его
/// (bug #4). Держится недолго и под жёсткими границами — см.
/// [`crate::net::PENDING_UDP_TTL`] и соседние константы.
struct PendingUdp {
    queue: VecDeque<Bytes>,
    bytes: usize,
    /// Момент создания записи — по нему `spawn_backlog_reaper` подметает
    /// протухшие (поток так и не открылся).
    since_ms: u64,
}

/// Кредитное окно одного потока на СТОРОНЕ ОТПРАВИТЕЛЯ (см. [`crate::net::credit`]).
///
/// Создаётся при регистрации потока с лимитом «без ограничений»: пока приёмник не
/// прислал ни одного `Credit`-кадра (старый пир, не знающий про кредиты), поток
/// ведёт себя как раньше. Первый грант включает ограничение; дальше лимит только
/// растёт. Счётчик отправленного байта ведётся с самого начала потока, поэтому
/// абсолютный лимит приёмника сравнивается с честным `sent`, без дрейфа.
struct CreditState {
    /// Абсолютный лимит отправки (байт Data с начала потока); `u64::MAX` — грантов
    /// ещё не было.
    limit: AtomicU64,
    /// Сколько байт Data уже отправлено в этом потоке.
    sent: AtomicU64,
    notify: Notify,
    /// Метка времени (мс) последнего РЕАЛЬНОГО гранта — для аварийного отката
    /// (`CREDIT_STALL_FALLBACK`).
    last_grant_ms: AtomicU64,
    /// Поток снят: ждущего отправителя нужно отпустить, чтобы он не завис.
    closed: AtomicBool,
}

impl CreditState {
    fn new() -> Self {
        Self {
            limit: AtomicU64::new(u64::MAX),
            sent: AtomicU64::new(0),
            notify: Notify::new(),
            last_grant_ms: AtomicU64::new(diagnostics::current_timestamp_ms()),
            closed: AtomicBool::new(false),
        }
    }

    /// Окно исчерпано: лимит задан и отправлено не меньше него.
    fn exhausted(&self) -> bool {
        let limit = self.limit.load(Ordering::Acquire);
        limit != u64::MAX && self.sent.load(Ordering::Acquire) >= limit
    }
}

/// Регистрационная запись потока в реестре `Muxer::streams`.
struct StreamSlot {
    tx: Sender<Bytes>,
    stats: Arc<StreamStats>,
    token: CancellationToken,
    backlog: Arc<StreamBacklog>,
}

/// Одна нога туннеля = одно физическое TCP+TLS-соединение.
///
/// Два раздельных канала к writer-задаче ноги: `control_tx` (Close/Heartbeat,
/// приоритетные) и `data_tx` (данные, с backpressure). `Clone` дёшев — внутри
/// `Arc`/`Sender`, поэтому ногу можно копировать из кэша без затрат.
#[derive(Clone)]
struct MuxLeg {
    id: u32,
    control_tx: Sender<MuxMessage>,
    data_tx: Sender<MuxMessage>,
    stats: Arc<LegStats>,
    /// Maximum plaintext payload that fits in a single native datagram.
    /// Zero for reliable stream legs.
    max_datagram_payload: usize,
}

impl MuxLeg {
    /// Observable queue pressure in the application channel, fair-writer queue
    /// and Linux TCP write queue.  The public/diagnostic form is clamped to 1.0.
    fn congestion_factor(&self) -> f64 {
        let max = self.data_tx.max_capacity();
        let current_capacity = self.data_tx.capacity();
        let filled = max.saturating_sub(current_capacity);
        let channel_pressure = if max == 0 {
            0.0
        } else {
            filled as f64 / max as f64
        };

        let byte_capacity = max.saturating_mul(BRIDGE_READ_CHUNK).max(1) as f64;
        let queued = self.stats.queued_data_bytes.load(Ordering::Relaxed) as f64;
        let byte_pressure = queued / byte_capacity;

        let notsent = self.stats.tcp_notsent_bytes.load(Ordering::Relaxed) as f64;
        let kernel_pressure = notsent / (crate::net::TUNNEL_TCP_NOTSENT_LOWAT.max(1) as f64);

        channel_pressure
            .max(byte_pressure)
            .max(kernel_pressure)
            .clamp(0.0, 1.0)
    }

    /// Wider score used only for new-flow placement.  It deliberately exceeds
    /// 1.0 for a queue that has waited multiple RTTs or for a leg that has just
    /// retransmitted, so a superficially-low RTT cannot hide a stalled path.
    fn selection_load_factor(&self) -> f64 {
        let base = self.congestion_factor();
        let now = process_uptime_ms();
        let queued_since = self.stats.queued_since_ms.load(Ordering::Relaxed);
        let rtt = self.stats.rtt_ms.load(Ordering::Relaxed).max(1) as f64;
        let queue_delay = if queued_since == 0 {
            0.0
        } else {
            now.saturating_sub(queued_since) as f64 / rtt
        };

        let delivery_rate = self.stats.tcp_delivery_rate.load(Ordering::Relaxed);
        let queued = self
            .stats
            .queued_data_bytes
            .load(Ordering::Relaxed)
            .saturating_add(self.stats.tcp_notsent_bytes.load(Ordering::Relaxed));
        let drain_delay = if delivery_rate == 0 {
            0.0
        } else {
            (queued as f64 * 1000.0 / delivery_rate as f64) / rtt
        };

        let last_retrans = self.stats.last_retrans_ms.load(Ordering::Relaxed);
        let retrans_penalty = if last_retrans > 0
            && now.saturating_sub(last_retrans) <= (rtt as u64).saturating_mul(4).max(1_000)
        {
            1.0
        } else {
            0.0
        };

        base.max(queue_delay).max(drain_delay).min(3.0) + retrans_penalty
    }
}

#[derive(Clone, Copy, Debug)]
struct UdpFlowletState {
    leg_id: u32,
    last_send_ms: u64,
}

/// Генератор `stream_id`, разводящий клиента и сервер по чётности.
///
/// Клиент выдаёт нечётные id (1,3,5…), сервер — чётные (2,4,6…). Так две стороны
/// независимо открывают потоки, не споря за номера. Шаг — `+2`, атомарно.
struct IdGenerator {
    counter: AtomicU32,
}

impl IdGenerator {
    pub fn new(is_client: bool) -> Self {
        Self {
            counter: AtomicU32::new(if is_client { 1 } else { 2 }),
        }
    }
    pub fn next(&self) -> u32 {
        self.counter.fetch_add(2, Ordering::Relaxed)
    }
}

/// Единица передачи через muxer: что отправить (`data`), какого типа и в какой
/// поток. Передаётся по каналам ноги к её writer-задаче.
#[derive(Clone)]
pub struct MuxMessage {
    pub(crate) stream_id: u32,
    pub(crate) frame_type: FrameType,
    pub(crate) data: Bytes,
}

/// Portable subset of Linux TCP_INFO consumed by leg scoring.  The engine
/// fills it where the platform exposes the fields; other targets simply leave
/// the corresponding atomics at zero.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpSocketStats {
    pub notsent_bytes: u64,
    pub unacked_bytes: u64,
    pub delivery_rate: u64,
    pub total_retrans: u32,
}

pub static GLOBAL_MIN_RTT: AtomicU32 = AtomicU32::new(INITIAL_RTT_MS);

/// True at most once per `interval_ms` for the given timestamp cell (CAS, so
/// concurrent callers agree on a single winner per interval).
fn throttle_due(last: &AtomicU64, now_ms: u64, interval_ms: u64) -> bool {
    let prev = last.load(Ordering::Relaxed);
    (prev == 0 || now_ms.saturating_sub(prev) >= interval_ms)
        && last
            .compare_exchange(prev, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// True at most once per second: gates the log line and diagnostics event for
/// dropped control frames (see the call site for why).
fn control_full_report_due() -> bool {
    static LAST_MS: AtomicU64 = AtomicU64::new(0);
    throttle_due(&LAST_MS, process_uptime_ms().max(1), 1000)
}

/// Write timeout that scales with a given RTT sample — the shared scaling
/// rule behind [`adaptive_write_timeout`] and [`Muxer::adaptive_leg_write_timeout`].
/// Allowing ~8 RTT of drain time (capped at 60 s) keeps a slow-but-alive path
/// from being evicted under high latency, while still reaping genuinely stuck
/// sockets.
fn scale_write_timeout(rtt_ms: u32, floor: Duration) -> Duration {
    let scaled = Duration::from_millis((rtt_ms as u64).saturating_mul(8));
    scaled.clamp(floor, Duration::from_secs(60))
}

/// Write timeout that scales with the process-wide minimum observed RTT
/// ([`GLOBAL_MIN_RTT`]) — appropriate for a local-socket write that isn't tied
/// to any one physical leg (bridge writes to the real destination). For a
/// tunnel leg's own write, prefer [`Muxer::adaptive_leg_write_timeout`]: this
/// function's RTT input is the *best* leg in the whole process, which can be
/// far below the RTT of the specific — possibly much slower — leg actually
/// doing the write, defeating the point documented below.
///
/// On a healthy path (RTT ~50 ms) this stays at `floor`. When the path degrades
/// to multi-second RTT (the > 2500 ms peaks seen in production), a flat 20 s
/// timeout fires on a leg that is merely *slow*, not dead — and a killed leg
/// triggers the leg-drop → stream-close cascade ("domino effect").
pub fn adaptive_write_timeout(floor: Duration) -> Duration {
    scale_write_timeout(GLOBAL_MIN_RTT.load(Ordering::Relaxed), floor)
}

/// Interleave/batch chunk size that grows with RTT.
///
/// At low RTT keep the `base` (snappy, fair interleaving); under high RTT — where
/// the bandwidth-delay product is large — write bigger batches per pass so more
/// 16 KB frames coalesce into a single contiguous socket write (see
/// `handle_outbound`), cutting the number of `write()` syscalls under exactly the
/// conditions that were producing `tunnel_write_stuck`.
///
/// 1× at ≤250 ms, +1× per extra 250 ms of RTT, capped at 4×.
pub fn adaptive_batch_chunk(base: usize) -> usize {
    let rtt_ms = GLOBAL_MIN_RTT.load(Ordering::Relaxed) as usize;
    let factor = (1 + rtt_ms / 250).clamp(1, 4);
    base.saturating_mul(factor)
}

/// Credit window that grows with RTT, same idea as [`adaptive_batch_chunk`].
///
/// A stream's credit window should hold roughly one bandwidth-delay product
/// in flight so the sender never has to stall waiting for a grant under
/// normal operation. A flat window sized for a healthy path (tens of ms RTT)
/// would be far too small once RTT climbs into the hundreds/low thousands of
/// ms (mobile network, as seen in production — `GLOBAL_MIN_RTT` peaks well
/// past 1 s): the fallback in `consume_credit` prevents that from ever
/// stalling a stream outright, but scaling the window up front means it
/// mostly doesn't need to. Wider cap than `adaptive_batch_chunk` (up to 8×,
/// matching `SERVER_STREAM_BACKLOG_MAX_BYTES` at the top end) since BDP grows
/// with RTT much faster than a comfortable interleave chunk does.
pub fn adaptive_credit_window(base: u32) -> u32 {
    let rtt_ms = GLOBAL_MIN_RTT.load(Ordering::Relaxed);
    let factor = (1 + rtt_ms / 250).clamp(1, 8);
    base.saturating_mul(factor)
}

/// Мультиплексор туннеля. Дёшево клонируется (всё внутри `Arc`) и шарится между
/// всеми задачами ног и потоков.
#[derive(Clone)]
pub struct Muxer {
    /// Источник истины по ногам (id → нога). Шардированная карта, lock-free.
    legs: Arc<DashMap<u32, MuxLeg>>,
    // 🔥 ОПТИМИЗАЦИЯ: полностью lock-free кэш горячего пути.
    // ArcSwap: чтение (load_full) — атомарный bump Arc без блокировок; запись
    // (store) реже и тоже неблокирующая. Заменил RwLock<Arc<Vec>> — у которого
    // чтение брало read-guard.
    active_legs_cache: Arc<ArcSwap<Vec<MuxLeg>>>,

    /// Реестр потоков: id → регистрационная запись (канал, статистика, токен,
    /// бэклог). Токен мгновенно убивает связанные с потоком задачи при `remove_stream`.
    streams: Arc<DashMap<u32, StreamSlot>>,
    /// Tokens of streams that the peer closed gracefully (`finish_stream`): the slot
    /// is gone so the consumer sees EOF, but its owner still needs a way to cancel
    /// the stream's tasks — `remove_stream` does that through this map.
    closing_tokens: Arc<DashMap<u32, CancellationToken>>,
    /// Кредитные окна потоков, для которых ЭТА сторона — отправитель (см.
    /// [`CreditState`]). Отдельная карта от `streams`: та — про приём, эта —
    /// про то, сколько ещё можно отправить, не дожидаясь `Credit`-кадра.
    credits: Arc<DashMap<u32, Arc<CreditState>>>,
    /// Sticky-привязка потока к ноге (`stream_id` → `leg_id`).
    stream_bindings: Arc<DashMap<u32, u32>>,
    /// UDP has no in-order delivery contract, so it uses short flowlets instead
    /// of a lifetime sticky binding.  A quiet gap or a congested leg permits the
    /// next datagram to move without changing the NRXP frame format.
    udp_flowlets: Arc<DashMap<u32, UdpFlowletState>>,
    /// Время отправки PING по каждой ноге — для измерения RTT по PONG.
    pending_pings: Arc<DashMap<u32, Instant>>,
    /// Генератор `stream_id` (чётность по роли).
    id_gen: Arc<IdGenerator>,
    /// Идентификатор сессии (для логов/топологии).
    session_id: Arc<String>,
    /// Rotating cursor for round-robin leg selection among similar-quality legs,
    /// so a burst of new streams spreads across legs instead of all binding to
    /// the single current-best one (thundering herd).
    rr_counter: Arc<AtomicU32>,
    /// Байты ног, которые уже отцеплены (реконнект/эвикт) — без этого
    /// `total_bytes()` был бы не монотонным: у новой ноги счётчик стартует с
    /// нуля, и частые переподключения занижали бы расход трафика для лимитов
    /// (см. `total_bytes`/`fold_removed_leg`).
    cumulative_tx: Arc<AtomicU64>,
    cumulative_rx: Arc<AtomicU64>,
    /// Идентификатор юзера-владельца сессии для отчёта о расходе трафика
    /// прокси-серверу (`None` — авторизация выключена или это клиентская
    /// сторона муксера, отчёты о трафике шлёт только сервер).
    quota_user_id: Arc<ArcSwap<Option<String>>>,
    /// Сколько байт (tx+rx) уже было отчитано бэкенду по этой сессии —
    /// следующий тик репортит только дельту сверх этого значения.
    quota_reported_bytes: Arc<AtomicU64>,
    /// Клиент: сервер безоговорочно отверг токен (`ERR_AUTH_FAILED` —
    /// см. `ClientHandler::connect`'s per-leg loop) — это не сетевой сбой,
    /// повторные попытки с тем же токеном обречены (например, аккаунт удалён
    /// на бэкенде). Once set, ноги перестают реконнектиться, а верхний
    /// движок клиента (`Engine::run`) видит [`Muxer::is_fatal`] и завершает
    /// сессию сам — без этого приложение молча висело в статусе "connected"
    /// с мёртвым туннелем, пока пользователь вручную не выключит VPN.
    fatal: Arc<AtomicBool>,
    /// Токен текущей «эпохи» сети. Отменяется при [`remove_all_legs`](Self::remove_all_legs)
    /// и тут же заменяется свежим.
    ///
    /// Нужен, потому что убрать ногу из карты — не то же самое, что её убить:
    /// задача `TunnelEngine::run` продолжает висеть на своём сокете. При смене
    /// сети (Wi-Fi ↔ LTE) TCP не получает RST, пакеты просто перестают
    /// доходить, и сокет живёт до таймаута ОС — это минуты, в течение которых
    /// муксер пуст и отправлять некуда. Токен каждой ноги — потомок этого,
    /// поэтому отмена мгновенно рвёт reader/writer и отправляет ногу на
    /// переподключение по новому маршруту.
    network_epoch: Arc<ArcSwap<CancellationToken>>,
    /// Единственная физическая UDP-нога сессии — НЕ часть `legs`.
    ///
    /// В отличие от TCP (несколько ног ради throughput/отказоустойчивости,
    /// см. [`MAX_TUNNEL_LEGS`]), UDP-нога — один опциональный быстрый путь
    /// (см. `docs/UDP_LEG_RESEARCH.md` §1), а не то, что можно
    /// мультиплицировать так же. Она сознательно вне `legs`/`active_legs_cache`:
    /// `select_leg`/`pick_leg` (TCP-семантичные потоки — `Data`/`Connect`) не
    /// должны её увидеть ни при каких обстоятельствах — общей гарантии
    /// доставки/порядка, на которую полагается TCP-мост, у датаграммной ноги
    /// нет. Единственная точка входа к ней — [`select_udp_leg`](Self::select_udp_leg),
    /// и только для `FrameType::UdpData`.
    datagram_leg: Arc<ArcSwapOption<MuxLeg>>,
    /// Сервер: ранние `UdpData`, обогнавшие свой `UdpConnect` (bug #4). Ключ —
    /// `stream_id`; сливается в поток при его регистрации (`register_stream*`) и
    /// подметается по TTL фоновым `spawn_backlog_reaper`. На клиенте карта
    /// просто пустует (клиент регистрирует потоки сам, до отправки данных).
    pending_udp: Arc<DashMap<u32, PendingUdp>>,
    /// Клиентский гейт «одна UDP-попытка за раз»: заявка первой TCP-ноги, чей
    /// хендшейк завершился. Реконнект ОТДЕЛЬНОЙ TCP-ноги его не трогает — иначе
    /// UDP-нога рвалась бы при каждом реконнекте, хотя её физическое состояние с
    /// этим не связано (см. `ClientHandler::establish_leg`).
    ///
    /// В отличие от прежнего `OnceLock`, заявка СБРАСЫВАЕТСЯ при смене сети
    /// ([`remove_all_legs`](Self::remove_all_legs) зовёт
    /// [`reset_datagram_leg_claim`](Self::reset_datagram_leg_claim)): старая
    /// попытка уже мертва вместе с эпохой, и ровно одна переподключившаяся нога
    /// поднимает НОВУЮ попытку со свежим корнем (→ свежие ключи) — без этого
    /// UDP-нога была одноразовой и умирала на первом же переключении сети
    /// (bug #2). На сервере это поле не используется (демультиплексирование там
    /// ведёт `SessionManager`).
    datagram_leg_token: Arc<Mutex<Option<[u8; 16]>>>,
    /// Когда в последний раз сбрасывали все ноги из-за смены сети (мс от старта
    /// процесса, 0 — ни разу). См. [`ms_since_network_change`](Self::ms_since_network_change).
    last_network_change_ms: Arc<AtomicU64>,
}

impl Muxer {
    pub fn new(is_client: bool, session_id: String) -> Self {
        let muxer = Self {
            legs: Arc::new(DashMap::new()),
            active_legs_cache: Arc::new(ArcSwap::from_pointee(Vec::new())),
            streams: Arc::new(DashMap::new()),
            closing_tokens: Arc::new(DashMap::new()),
            credits: Arc::new(DashMap::new()),
            stream_bindings: Arc::new(DashMap::new()),
            udp_flowlets: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            pending_pings: Arc::new(DashMap::new()),
            session_id: Arc::new(session_id),
            rr_counter: Arc::new(AtomicU32::new(0)),
            cumulative_tx: Arc::new(AtomicU64::new(0)),
            cumulative_rx: Arc::new(AtomicU64::new(0)),
            quota_user_id: Arc::new(ArcSwap::from_pointee(None)),
            quota_reported_bytes: Arc::new(AtomicU64::new(0)),
            fatal: Arc::new(AtomicBool::new(false)),
            network_epoch: Arc::new(ArcSwap::from_pointee(CancellationToken::new())),
            datagram_leg: Arc::new(ArcSwapOption::from(None)),
            pending_udp: Arc::new(DashMap::new()),
            datagram_leg_token: Arc::new(Mutex::new(None)),
            last_network_change_ms: Arc::new(AtomicU64::new(0)),
        };
        muxer.spawn_backlog_reaper();
        muxer
    }

    /// Помечает сессию как безвозвратно проваленную (сервер отверг токен) —
    /// см. поле [`fatal`](Self::fatal).
    pub fn mark_fatal(&self) {
        self.fatal.store(true, Ordering::Relaxed);
    }

    /// `true`, если сессию нужно завершать, а не реконнектить (см. [`mark_fatal`](Self::mark_fatal)).
    pub fn is_fatal(&self) -> bool {
        self.fatal.load(Ordering::Relaxed)
    }

    /// Сессия закончена (остановлена юзером, отменена новой сессией или
    /// провалена): ноги должны перестать переподключаться и закрыть сокеты.
    ///
    /// Задачи ног запускаются `tokio::spawn` в `ClientHandler::connect` и
    /// живут отдельно от движка клиента. Без этого вызова они переживали
    /// остановку сессии и переподключались к ноде, пока жив процесс
    /// приложения; а когда токен протухал — долбили ноду отказами без пауз
    /// (прод, 2026-09-30: один Android-клиент ~10 попыток/с на две ноды).
    pub fn shutdown(&self) {
        self.mark_fatal();
        self.remove_all_legs();
    }

    /// Number of currently registered logical streams. Mesh peer sessions use
    /// this to retire idle pooled connections without interrupting live flows.
    pub fn active_streams_count(&self) -> usize {
        self.streams.len()
    }

    /// Close every logical stream after its physical peer session has ended.
    /// Removing the slots drops their senders, waking stream owners instead of
    /// leaving them waiting on a connection that can no longer deliver data.
    pub fn remove_all_streams(&self) {
        let stream_ids: Vec<_> = self.streams.iter().map(|entry| *entry.key()).collect();
        for stream_id in stream_ids {
            self.remove_stream(stream_id);
        }
    }

    /// Сколько миллисекунд прошло с последней смены сети; `None`, если её не было.
    pub fn ms_since_network_change(&self) -> Option<u64> {
        match self.last_network_change_ms.load(Ordering::Relaxed) {
            0 => None,
            at => Some(process_uptime_ms().saturating_sub(at)),
        }
    }

    /// Токен текущей эпохи сети — от него нога порождает свой дочерний
    /// (см. [`network_epoch`](Self::network_epoch)).
    pub fn network_epoch_token(&self) -> CancellationToken {
        CancellationToken::clone(&self.network_epoch.load())
    }

    /// Складывает байты ноги, которая уходит из `legs` (эвикт/реконнект), в
    /// сессионный кумулятивный счётчик — вызывать сразу после `DashMap::remove`.
    fn fold_removed_leg(&self, leg: &MuxLeg) {
        self.cumulative_tx.fetch_add(
            leg.stats.tx_bytes.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.cumulative_rx.fetch_add(
            leg.stats.rx_bytes.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    /// Суммарный трафик сессии (все ноги, включая уже отцепленные) — источник
    /// истины для отчётов о расходе прокси-серверу бэкенду.
    pub fn total_bytes(&self) -> (u64, u64) {
        let mut tx = self.cumulative_tx.load(Ordering::Relaxed);
        let mut rx = self.cumulative_rx.load(Ordering::Relaxed);
        for leg in self.active_legs_cache.load_full().iter() {
            tx += leg.stats.tx_bytes.load(Ordering::Relaxed);
            rx += leg.stats.rx_bytes.load(Ordering::Relaxed);
        }
        (tx, rx)
    }

    /// Привязывает сессию к юзеру бэкенда — вызывается один раз при успешной
    /// проверке auth-токена первой ноги сессии (см. `ServerHandler::run`).
    pub fn set_quota_user(&self, user_id: String) {
        self.quota_user_id.store(Arc::new(Some(user_id)));
    }

    pub fn quota_user_id(&self) -> Option<String> {
        self.quota_user_id.load_full().as_ref().clone()
    }

    /// Дельта трафика с прошлого репорта и (не блокирующий) сдвиг базовой
    /// точки — вызывающий обязан либо реально отправить дельту бэкенду, либо
    /// не звать этот метод (в отличие от `store`, здесь нет отмены на ошибку:
    /// невозможность связаться с бэкендом не должна накапливать неограниченно
    /// растущую "недоотчитанную" дельту).
    pub fn take_usage_delta(&self) -> u64 {
        let (tx, rx) = self.total_bytes();
        let total = tx + rx;
        let last = self.quota_reported_bytes.swap(total, Ordering::Relaxed);
        total.saturating_sub(last)
    }

    /// Откатывает базовую точку назад на `delta` — вызывать, если репорт
    /// бэкенду не удался, чтобы не потерять дельту навсегда.
    pub fn rollback_usage_delta(&self, delta: u64) {
        self.quota_reported_bytes.fetch_sub(
            delta.min(self.quota_reported_bytes.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }

    /// Фоновый "ридер" бэклогов: единственное место, которое реально закрывает
    /// поток за зависший бэклог (см. докстринг [`StreamBacklog`]). Никогда не
    /// вызывается изнутри `dispatch_to_local` — работает по расписанию, вне
    /// любых `Ref`-гвардов `Muxer::streams`, поэтому структурно не может
    /// повторить самоблокировку DashMap.
    ///
    /// Держит собственный клон `Muxer` (дёшево — всё внутри `Arc`), поэтому
    /// самостоятельно завершается, если сессия опустела (нет ног и потоков)
    /// дольше [`BACKLOG_REAPER_IDLE_TIMEOUT`] — иначе на сервере, обслужившем
    /// много клиентов, эти задачи копились бы вечно.
    fn spawn_backlog_reaper(&self) {
        let muxer = self.clone();
        tokio::spawn(async move {
            let mut idle_since: Option<Instant> = None;
            loop {
                tokio::time::sleep(BACKLOG_REAPER_INTERVAL).await;

                // Подметаем протухшие ранние UDP-буферы всегда, даже на простое:
                // поток мог так и не открыться, и запись висела бы до следующей
                // активности (bug #4 — буфер обязан быть строго ограничен во
                // времени).
                muxer.sweep_expired_pending_udp();

                if muxer.active_legs_count() == 0 && muxer.streams.is_empty() {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= BACKLOG_REAPER_IDLE_TIMEOUT {
                        trace!("Backlog reaper: muxer idle, stopping");
                        return;
                    }
                    continue;
                }
                idle_since = None;

                let now = diagnostics::current_timestamp_ms();
                // Same reasoning as adaptive_write_timeout: a stuck-but-alive
                // consumer under high/variable RTT (e.g. the server writing a
                // client's uploaded bytes into a slow real target) needs more
                // than a flat grace window before it's judged dead — a fixed 5 s
                // was fine for the low-RTT case this was tuned against, but
                // evicted legitimately-slow-but-recovering streams once RTT (or
                // its variance) climbed, exactly where this reaper replaced the
                // old adaptive_write_timeout-only protection on that path.
                let grace = adaptive_write_timeout(BACKLOG_STUCK_GRACE);
                let grace_ms = grace.as_millis() as u64;
                let stuck: Vec<u32> = muxer
                    .streams
                    .iter()
                    .filter_map(|kv| {
                        let backlog = &kv.value().backlog;
                        let over_budget = backlog.bytes.load(Ordering::Relaxed) > backlog.cap_bytes;
                        let stale = now
                            .saturating_sub(backlog.last_progress_ms.load(Ordering::Relaxed))
                            >= grace_ms;
                        (over_budget && stale).then_some(*kv.key())
                    })
                    .collect();

                // Evict AFTER the .iter() above is fully dropped (collected into
                // an owned Vec) — removing a key while iterating the same
                // DashMap would hold a shard Ref and a write-lock request on it
                // at once, exactly the self-deadlock this design avoids.
                for stream_id in stuck {
                    DIAG_COUNTERS
                        .mux_dispatch_full_closed
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        stream_id,
                        "Backlog reaper: over budget with no progress for {:?} — closing stream",
                        grace
                    );
                    muxer.remove_stream(stream_id);
                }
            }
        });
    }

    /// Пересобирает lock-free снапшот ног из источника истины (`legs`) и
    /// атомарно публикует его в `active_legs_cache`. Вызывается при любом
    /// изменении набора ног (add/remove).
    fn update_legs_cache(&self) {
        let new_cache: Vec<MuxLeg> = self.legs.iter().map(|kv| kv.value().clone()).collect();
        self.active_legs_cache.store(Arc::new(new_cache));
    }

    /// Регистрирует новую ногу (после установки TCP+TLS). Если лимит
    /// [`MAX_TUNNEL_LEGS`] достигнут и это не обновление существующей — игнор.
    pub fn add_leg(
        &self,
        leg_id: u32,
        control_tx: Sender<MuxMessage>,
        data_tx: Sender<MuxMessage>,
    ) {
        if self.legs.len() >= MAX_TUNNEL_LEGS as usize && !self.legs.contains_key(&leg_id) {
            warn!(leg_id, "MUXER: Max legs reached");
            return;
        }

        self.legs.insert(
            leg_id,
            MuxLeg {
                id: leg_id,
                control_tx,
                data_tx,
                stats: Arc::new(LegStats::default()),
                max_datagram_payload: 0,
            },
        );
        self.update_legs_cache(); // Обновляем Lock-Free кэш
        info!(
            leg_id,
            "MUXER: Physical TCP+TLS leg registered (Total: {})",
            self.legs.len()
        );
    }

    /// Drop every stream→leg binding that points at `leg_id`. Stale bindings to a
    /// removed leg force `select_leg` to re-balance each affected stream onto a
    /// healthy leg on its next send, instead of repeatedly probing the dead one.
    fn clear_bindings_for_leg(&self, leg_id: u32) {
        self.stream_bindings
            .retain(|_, bound_leg| *bound_leg != leg_id);
        self.udp_flowlets
            .retain(|_, flowlet| flowlet.leg_id != leg_id);
    }

    /// Безопасно эвиктит ногу, но только если её текущий `control_tx` совпадает с
    /// `tx` (защита от удаления ноги, уже переподключённой под тем же id). Сначала
    /// снимает привязки, потом обновляет кэш — чтобы конкурентный `select_leg` не
    /// привязался к эвиктируемой ноге.
    pub fn remove_leg(&self, leg_id: u32, tx: &Sender<MuxMessage>) {
        let should_remove = self
            .legs
            .get(&leg_id)
            .is_some_and(|leg| leg.control_tx.same_channel(tx));
        if should_remove {
            if let Some((_, leg)) = self.legs.remove(&leg_id) {
                self.fold_removed_leg(&leg);
            }
            // Unbind streams BEFORE refreshing the cache so a concurrent
            // select_leg never re-binds a stream to the leg we are evicting.
            self.clear_bindings_for_leg(leg_id);
            self.update_legs_cache();
            info!(
                leg_id,
                "MUXER: TCP leg removed safely, streams will re-balance"
            );
        }
    }

    /// Безусловно удаляет ногу (без сверки канала) — при выходе её движка.
    pub fn force_remove_leg(&self, leg_id: u32) {
        if let Some((_, leg)) = self.legs.remove(&leg_id) {
            self.fold_removed_leg(&leg);
            self.clear_bindings_for_leg(leg_id);
            self.update_legs_cache();
            info!(leg_id, "MUXER: TCP leg force-removed on engine exit");
        }
    }

    /// Сбрасывает все ноги и привязки (полная остановка туннеля).
    pub fn remove_all_legs(&self) {
        self.last_network_change_ms
            .store(process_uptime_ms().max(1), Ordering::Relaxed);
        for entry in self.legs.iter() {
            self.fold_removed_leg(entry.value());
        }
        self.legs.clear();
        self.stream_bindings.clear();
        self.udp_flowlets.clear();
        self.update_legs_cache();
        // Физическая UDP-нога тоже привязана к старой эпохе и сейчас умрёт —
        // снимаем её из выбора немедленно, не дожидаясь, пока её собственный
        // читатель заметит отмену токена.
        self.clear_datagram_leg();
        // Снимаем заявку на UDP-попытку: старая попытка мертва вместе с эпохой,
        // и следующая переподключившаяся нога поднимет новую (bug #2).
        self.reset_datagram_leg_claim();

        // И действительно убить задачи ног, а не только вычистить карту:
        // старый сокет после смены сети не отдаёт ошибку, он просто молчит.
        // Сначала ставим новую эпоху, потом отменяем старую — нога, которая
        // проснётся от отмены и сразу пойдёт переподключаться, должна взять
        // уже свежий токен, а не тот, который отменяется прямо сейчас.
        let previous = self.network_epoch.swap(Arc::new(CancellationToken::new()));
        previous.cancel();
    }

    /// Пытается зарезервировать право поднимать UDP-ногу этой сессии за
    /// вызывающей TCP-ногой. `true` — вызывающий выиграл гонку (заявки ещё не
    /// было) и обязан сам поднять UDP-попытку; `false` — заявку уже кто-то
    /// держит (поднимает/поднял/провалил в рамках ТЕКУЩЕЙ эпохи сети). Заявка
    /// снимается [`reset_datagram_leg_claim`](Self::reset_datagram_leg_claim)
    /// при смене сети, позволяя следующей попытке (см. докстринг поля).
    pub fn try_claim_datagram_leg_token(&self, token: [u8; 16]) -> bool {
        let mut guard = self.datagram_leg_token.lock().unwrap();
        if guard.is_some() {
            false
        } else {
            *guard = Some(token);
            true
        }
    }

    /// Снимает заявку — вызывается из [`remove_all_legs`](Self::remove_all_legs)
    /// при смене сети, чтобы ровно одна переподключившаяся нога подняла НОВУЮ
    /// UDP-попытку со свежим корнем (bug #2).
    pub fn reset_datagram_leg_claim(&self) {
        *self.datagram_leg_token.lock().unwrap() = None;
    }

    /// Текущее значение заявки, если она есть.
    pub fn datagram_leg_token(&self) -> Option<[u8; 16]> {
        *self.datagram_leg_token.lock().unwrap()
    }

    /// Регистрирует физически установленную UDP-ногу. Вызывается один раз
    /// по завершении её собственного хендшейка (см. точку вызова на
    /// клиенте/сервере) — до этого момента `select_udp_leg` использует
    /// исключительно TCP-переносимый фолбэк.
    pub fn set_datagram_leg(&self, control_tx: Sender<MuxMessage>, data_tx: Sender<MuxMessage>) {
        self.set_datagram_leg_with_max_payload(control_tx, data_tx, MAX_DATAGRAM_LEG_PAYLOAD);
    }

    /// Register a native datagram leg with a transport-specific MTU ceiling.
    /// The ceiling applies to the NRXP frame payload before framing/encryption.
    pub fn set_datagram_leg_with_max_payload(
        &self,
        control_tx: Sender<MuxMessage>,
        data_tx: Sender<MuxMessage>,
        max_payload: usize,
    ) {
        self.datagram_leg.store(Some(Arc::new(MuxLeg {
            id: DATAGRAM_LEG_ID,
            control_tx,
            data_tx,
            stats: Arc::new(LegStats::default()),
            max_datagram_payload: max_payload.min(MAX_DATAGRAM_LEG_PAYLOAD),
        })));
        info!("MUXER: Physical UDP leg registered");
    }

    /// Снимает UDP-ногу (эвикт по мёртвому health-check'у или физическая
    /// смерть движка) — `select_udp_leg` немедленно откатывается на
    /// TCP-переносимый фолбэк для следующей же датаграммы, ничего больше
    /// делать не нужно (в отличие от TCP-ног, здесь нет привязок потоков,
    /// которые нужно было бы расчищать: `udp_flowlets` адресует TCP-ноги по
    /// их `leg_id`, датаграммная нога никогда там не встречается).
    pub fn clear_datagram_leg(&self) {
        if self.datagram_leg.swap(None).is_some() {
            info!("MUXER: Physical UDP leg cleared, falling back to TCP-carried UdpData");
        }
    }

    /// Статистика текущей UDP-ноги — нужна её собственному health-check'у
    /// (см. точку вызова), чтобы отмечать PING/PONG тем же способом, что и
    /// TCP-ноги (`LegStats::last_pong_ms`/`rtt_ms`), не изобретая параллельный
    /// формат метрик только ради одной ноги.
    pub fn datagram_leg_stats(&self) -> Option<Arc<LegStats>> {
        self.datagram_leg.load_full().map(|leg| leg.stats.clone())
    }

    /// Отмечает UDP-ногу живой прямо сейчас — вызывается её собственным
    /// читателем (`net::connection::dgram_engine`) на КАЖДУЮ успешно
    /// расшифрованную датаграмму, не только на явный PONG (см. докстринг
    /// `dgram_engine` за тем, почему этого достаточно). Инкапсулирует
    /// `process_uptime_ms()` — он приватен этому файлу, чтобы единственным
    /// источником "текущего времени для свежести ноги" всегда оставался этот
    /// модуль, а не что-то, независимо считающее время снаружи.
    pub fn mark_datagram_leg_alive(&self) {
        if let Some(stats) = self.datagram_leg_stats() {
            stats
                .last_pong_ms
                .store(process_uptime_ms().max(1), Ordering::Relaxed);
        }
    }

    /// Жива ли UDP-нога прямо сейчас: недавний PONG в пределах того же окна
    /// свежести, что и у TCP-ног (`LEG_PONG_FRESHNESS`) — единый критерий
    /// "жива", не два разных под два транспорта.
    fn datagram_leg_is_fresh(&self, leg: &MuxLeg) -> bool {
        let last_pong = leg.stats.last_pong_ms.load(Ordering::Relaxed);
        last_pong != 0
            && process_uptime_ms().saturating_sub(last_pong)
                < crate::net::LEG_PONG_FRESHNESS.as_millis() as u64
    }

    /// Число активных ног.
    pub fn active_legs_count(&self) -> usize {
        self.legs.len()
    }

    /// Picks a new leg using latency plus application/kernel queue state.
    /// `exclude` is best-effort: if it would remove the only live leg, that leg
    /// remains eligible.
    fn pick_leg(&self, exclude: Option<u32>) -> Option<MuxLeg> {
        let legs = self.active_legs_cache.load_full();
        if legs.is_empty() {
            return None;
        }

        let mut eligible: Vec<&MuxLeg> =
            legs.iter().filter(|leg| exclude != Some(leg.id)).collect();
        if eligible.is_empty() {
            eligible = legs.iter().collect();
        }

        // RTT remains the base, but queue residence, bytes already accepted by
        // the writer, Linux `notsent` bytes and a recent retransmission can now
        // quarantine an apparently-fast leg before its mpsc channel fills.
        let score = |leg: &MuxLeg| -> f64 {
            let rtt = (leg.stats.rtt_ms.load(Ordering::Relaxed) as f64).max(1.0);
            rtt * (1.0 + leg.selection_load_factor())
        };

        let best = eligible
            .iter()
            .map(|leg| score(leg))
            .fold(f64::MAX, f64::min);

        // Candidate set = every leg within 2× of the best score. Drastically
        // worse (slow / bufferbloated) legs are excluded; near-equal legs are all
        // eligible. We then ROUND-ROBIN across the candidates so a burst of new
        // streams (speedtest / multi-connection upload opening many sockets at
        // once, before congestion registers) spreads across legs instead of all
        // binding to the single current-best leg — which previously left one leg
        // saturated and the others idle (low aggregate upload + stop-start stalls).
        let candidates: Vec<&MuxLeg> = eligible
            .into_iter()
            .filter(|leg| score(leg) <= best * 2.0)
            .collect();

        if candidates.is_empty() {
            None
        } else {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len();
            Some(candidates[idx].clone())
        }
    }

    /// Выбирает lifetime-sticky ногу для TCP/control потока.
    fn select_leg(&self, stream_id: u32) -> Option<MuxLeg> {
        // Hot path: preserving one outer leg also preserves TCP stream ordering
        // without adding sequence numbers to NRXP.
        if let Some(leg_id_ref) = self.stream_bindings.get(&stream_id) {
            let leg_id = *leg_id_ref;
            if let Some(leg) = self.legs.get(&leg_id) {
                return Some(leg.clone());
            }
        }

        let leg = self.pick_leg(None)?;
        self.stream_bindings.insert(stream_id, leg.id);
        Some(leg)
    }

    /// Chooses a leg for one UDP datagram: prefers the physical UDP-native
    /// leg while it's alive (см. [`datagram_leg_is_fresh`](Self::datagram_leg_is_fresh)
    /// — приоритетная лестница из `docs/UDP_LEG_RESEARCH.md` §1), иначе
    /// откатывается на TCP-переносимый фолбэк
    /// ([`select_udp_leg_over_tcp`](Self::select_udp_leg_over_tcp), прежняя
    /// реализация этого метода целиком).
    fn select_udp_leg(&self, stream_id: u32, payload_len: usize) -> Option<MuxLeg> {
        if let Some(native) = self.datagram_leg.load_full() {
            // Кадр, не влезающий в потолок физической датаграммы, НЕ отдаём на
            // native-ногу: её писатель отправил бы его одной UDP-датаграммой,
            // которая при DF упёрлась бы в PMTU (EMSGSIZE/чёрная дыра), а без DF
            // фрагментировалась бы (сам по себе признак для DPI). Такой кадр
            // уходит по TCP-переносимому фолбэку — правило §1.3 (bug #5).
            if payload_len <= native.max_datagram_payload && self.datagram_leg_is_fresh(&native) {
                return Some((*native).clone());
            }
        }
        self.select_udp_leg_over_tcp(stream_id)
    }

    /// During a short burst the flowlet stays on one leg to limit
    /// reordering; after a quiet gap, or immediately when that leg builds a
    /// standing queue, the next datagram may move.
    fn select_udp_leg_over_tcp(&self, stream_id: u32) -> Option<MuxLeg> {
        let now = process_uptime_ms().max(1);
        let gap_ms = (GLOBAL_MIN_RTT.load(Ordering::Relaxed) as u64 / 2).clamp(10, 100);
        let previous = self.udp_flowlets.get(&stream_id).map(|state| *state);

        if let Some(previous) = previous {
            if let Some(leg) = self.legs.get(&previous.leg_id) {
                let within_flowlet = now.saturating_sub(previous.last_send_ms) < gap_ms;
                if within_flowlet && leg.selection_load_factor() < 1.0 {
                    let selected = leg.clone();
                    drop(leg);
                    self.udp_flowlets.insert(
                        stream_id,
                        UdpFlowletState {
                            leg_id: selected.id,
                            last_send_ms: now,
                        },
                    );
                    return Some(selected);
                }
            }
        }

        let exclude = previous.and_then(|old| {
            self.legs
                .get(&old.leg_id)
                .and_then(|leg| (leg.selection_load_factor() >= 1.0).then_some(old.leg_id))
        });
        let selected = self.pick_leg(exclude)?;
        self.udp_flowlets.insert(
            stream_id,
            UdpFlowletState {
                leg_id: selected.id,
                last_send_ms: now,
            },
        );
        Some(selected)
    }

    /// Запоминает момент отправки PING по ноге (для замера RTT по PONG).
    pub fn record_ping_sent(&self, leg_id: u32) {
        self.pending_pings.insert(leg_id, Instant::now());
    }

    /// Обрабатывает PONG: считает RTT и обновляет сглаженную оценку (EWMA, α=0.25),
    /// затем пересчитывает глобальный минимум [`GLOBAL_MIN_RTT`] по всем ногам.
    pub async fn record_pong(&self, leg_id: u32) {
        // Отмечаем свежесть ноги ДО разбора RTT: PONG мог прийти на heartbeat
        // writer'а, для которого `pending_pings` не заполняется, и такой ответ
        // всё равно доказывает, что нога жива (см. `perform_health_check`).
        if let Some(leg) = self.legs.get(&leg_id) {
            leg.stats
                .last_pong_ms
                .store(process_uptime_ms().max(1), Ordering::Relaxed);
        }

        if let Some((_, start_time)) = self.pending_pings.remove(&leg_id) {
            let measured = start_time.elapsed().as_millis() as u32;
            if let Some(leg) = self.legs.get(&leg_id) {
                let current = leg.stats.rtt_ms.load(Ordering::Relaxed);
                // EWMA with α=0.25: new = (3·old + measured) / 4.
                // A single noisy heartbeat (e.g. 300 ms on a 50 ms baseline)
                // only moves the stored RTT to ~112 ms instead of jumping
                // straight to 300 ms, preventing unnecessary leg re-selection.
                let rtt = if current == crate::net::INITIAL_RTT_MS {
                    measured // first real measurement: accept immediately
                } else {
                    (current.saturating_mul(3).saturating_add(measured)) / 4
                };
                leg.stats.rtt_ms.store(rtt, Ordering::Relaxed);
                let min_rtt = self
                    .legs
                    .iter()
                    .map(|kv| kv.value().stats.rtt_ms.load(Ordering::Relaxed))
                    .filter(|&r| r > 0)
                    .min()
                    .unwrap_or(250);
                GLOBAL_MIN_RTT.store(min_rtt, Ordering::Relaxed);
            }
        }
    }

    /// Records that payload has crossed the bounded mpsc channel boundary but
    /// has not yet completed a socket write.  This count intentionally includes
    /// bytes moved into the writer's local fair queues.
    fn record_leg_data_queued(&self, leg: &MuxLeg, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let previous = leg
            .stats
            .queued_data_bytes
            .fetch_add(bytes, Ordering::AcqRel);
        if previous == 0 {
            leg.stats
                .queued_since_ms
                .store(process_uptime_ms().max(1), Ordering::Release);
        }
    }

    fn record_data_tx(&self, leg: &MuxLeg, stream_id: u32, bytes: u64) {
        leg.stats.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        if let Some(stream_ref) = self.streams.get(&stream_id) {
            stream_ref
                .value()
                .stats
                .tx_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Called by the writer after a fair-scheduled chunk has completed its
    /// `write_all`.  Saturating CAS avoids underflow if a dying leg races cleanup.
    pub(crate) fn record_leg_data_drained(&self, leg_id: u32, bytes: u64) {
        let Some(leg) = self.legs.get(&leg_id) else {
            return;
        };
        let stats = &leg.stats;
        let mut current = stats.queued_data_bytes.load(Ordering::Acquire);
        let new_value = loop {
            let updated = current.saturating_sub(bytes);
            match stats.queued_data_bytes.compare_exchange_weak(
                current,
                updated,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break updated,
                Err(actual) => current = actual,
            }
        };
        if new_value == 0 {
            stats.queued_since_ms.store(0, Ordering::Release);
        }
    }

    /// Publishes a sampled TCP_INFO subset without putting a syscall on the
    /// stream-selection hot path.
    pub(crate) fn record_tcp_socket_stats(&self, leg_id: u32, sample: TcpSocketStats) {
        let Some(leg) = self.legs.get(&leg_id) else {
            return;
        };
        let stats = &leg.stats;
        stats
            .tcp_notsent_bytes
            .store(sample.notsent_bytes, Ordering::Relaxed);
        stats
            .tcp_unacked_bytes
            .store(sample.unacked_bytes, Ordering::Relaxed);
        stats
            .tcp_delivery_rate
            .store(sample.delivery_rate, Ordering::Relaxed);
        let previous = stats
            .tcp_total_retrans
            .swap(sample.total_retrans, Ordering::Relaxed);
        if sample.total_retrans > previous {
            stats
                .last_retrans_ms
                .store(process_uptime_ms().max(1), Ordering::Relaxed);
        }
    }

    /// Отправляет кадр в сеть, выбирая ногу и применяя стратегию по типу кадра.
    ///
    /// - **Данные** (`Data`/`UdpData`): `send().await` (backpressure) с
    ///   anti-domino failover в цикле — при мёртвой ноге эвикт + переотправка на
    ///   другую; `Err` лишь когда живых ног нет.
    /// - **Критичные** (`Close`/`Heartbeat`): надёжно через `send().await`
    ///   (потеря Close течёт ресурсы, потеря PONG валит health-check).
    /// - **Прочий контроль**: `try_send`; при переполнении кадр дропается с
    ///   сигналом `ControlChannelFull`, не блокируя.
    #[instrument(skip(self, message), fields(session_id = %self.session_id, stream_id = message.stream_id, frame = ?message.frame_type))]
    pub async fn send_to_network(&self, message: MuxMessage) -> Result<(), AppError> {
        let is_data = matches!(message.frame_type, FrameType::Data | FrameType::UdpData);

        // End-to-end flow control: if the receiver of this stream grants credit, don't
        // outrun it. Datagrams are exempt (UDP is best-effort and drops when late).
        if message.frame_type == FrameType::Data {
            self.credit_gate(message.stream_id).await;
        }

        if is_data {
            // 🔥 ANTI-DOMINO FAILOVER.
            // A single leg dropping must NOT close the stream. We evict the dead
            // leg, unbind the stream, and retry on the next-best leg. Only when
            // *every* leg is gone do we return Err — and the bridge treats that
            // as "pause & buffer", not "close" (see run_tcp_bridge). The loop is
            // bounded: remove_leg drops the leg from the cache, so select_leg can
            // never hand back the same dead leg, and it terminates at None.
            loop {
                let leg = match if message.frame_type == FrameType::UdpData {
                    self.select_udp_leg(message.stream_id, message.data.len())
                } else {
                    self.select_leg(message.stream_id)
                } {
                    Some(l) => l,
                    None => {
                        return Err(AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Нет связи",
                            "No active legs",
                        ));
                    }
                };

                let stream_id = message.stream_id;
                let size = message.data.len() as u64;

                // A full native datagram queue must never backpressure a UDP
                // flow. Drop this datagram and keep draining the source; Quinn's
                // own bounded queue retains newer traffic by evicting stale
                // unsent datagrams. Reliable Data and UDP carried over TCP keep
                // the existing await/backpressure path below.
                if message.frame_type == FrameType::UdpData && leg.id == DATAGRAM_LEG_ID {
                    match leg.data_tx.clone().try_reserve_owned() {
                        Ok(permit) => {
                            permit.send(message);
                            self.record_data_tx(&leg, stream_id, size);
                            return Ok(());
                        }
                        Err(TrySendError::Full(_)) => {
                            metrics::counter!("netrunner_udp_native_queue_drops_total")
                                .increment(1);
                            return Ok(());
                        }
                        Err(TrySendError::Closed(_)) => {
                            DIAG_COUNTERS.upload_fails.fetch_add(1, Ordering::Relaxed);
                            diagnostics::send_diag_event(DiagnosticsEvent::UploadFailed {
                                stream_id,
                                reason: "datagram data channel closed — failing over".into(),
                            });
                            self.clear_datagram_leg();
                            continue;
                        }
                    }
                }

                // Reserve first so queue accounting becomes visible before the
                // receiver can dequeue the message.  The bounded channel still
                // supplies the original local, sub-RTT backpressure.
                match leg.data_tx.clone().reserve_owned().await {
                    Ok(permit) => {
                        self.record_leg_data_queued(&leg, size);
                        let is_tcp_data = message.frame_type == FrameType::Data;
                        permit.send(message);
                        self.record_data_tx(&leg, stream_id, size);
                        if is_tcp_data {
                            self.debit_credit(stream_id, size as usize);
                        }
                        return Ok(());
                    }
                    Err(_) => {
                        // `reserve` failed before taking ownership, so `message`
                        // is still available for retry on another live leg.
                        DIAG_COUNTERS.upload_fails.fetch_add(1, Ordering::Relaxed);
                        diagnostics::send_diag_event(DiagnosticsEvent::UploadFailed {
                            stream_id,
                            reason: "data channel closed (leg dropped) — failing over".into(),
                        });
                        if leg.id == DATAGRAM_LEG_ID {
                            // Физическая UDP-нога НЕ живёт в `legs`, поэтому
                            // `remove_leg(DATAGRAM_LEG_ID)` — no-op: раньше при
                            // мёртвом писателе UDP-ноги, пока она ещё «свежая»,
                            // `select_udp_leg` бесконечно отдавал её снова, а
                            // reserve снова падал — холостой цикл на ~1.3 млн
                            // итераций/с (bug #6). Снимаем именно датаграммную
                            // ногу — следующий `select_udp_leg` откатится на TCP.
                            self.clear_datagram_leg();
                        } else {
                            // Evict the dead leg (also unbinds its streams) so the
                            // next select_leg re-balances onto a healthy leg.
                            self.remove_leg(leg.id, &leg.control_tx);
                        }
                        // loop → pick another leg, or return Err if none remain.
                    }
                }
            }
        } else {
            let leg = match self.select_leg(message.stream_id) {
                Some(l) => l,
                None => {
                    return Err(AppError::new(
                        ERR_INFRA_TIMEOUT,
                        "Нет связи",
                        "No active legs",
                    ));
                }
            };

            let stream_id = message.stream_id;
            let size = message.data.len() as u64;
            // Close and Heartbeat frames MUST be delivered reliably (.send().await).
            // Close: dropping it leaks stream resources.
            // Heartbeat (PONG): dropping it via try_send causes the health-check
            // probe to time out after HEALTH_CHECK_TIMEOUT and evict a live leg.
            // Credit too: a dropped grant would leave the sender blocked until the next one.
            let is_critical = matches!(
                message.frame_type,
                FrameType::Close | FrameType::Heartbeat | FrameType::Credit
            );

            if is_critical {
                match leg.control_tx.send(message).await {
                    Ok(_) => {
                        leg.stats.tx_bytes.fetch_add(size, Ordering::Relaxed);
                        if let Some(stream_ref) = self.streams.get(&stream_id) {
                            stream_ref
                                .value()
                                .stats
                                .tx_bytes
                                .fetch_add(size, Ordering::Relaxed);
                        }
                        Ok(())
                    }
                    Err(_) => {
                        self.remove_leg(leg.id, &leg.control_tx);
                        Err(AppError::new(ERR_INFRA_TIMEOUT, "Обрыв", "Leg closed"))
                    }
                }
            } else {
                match leg.control_tx.try_send(message) {
                    Ok(_) => {
                        leg.stats.tx_bytes.fetch_add(size, Ordering::Relaxed);
                        if let Some(stream_ref) = self.streams.get(&stream_id) {
                            stream_ref
                                .value()
                                .stats
                                .tx_bytes
                                .fetch_add(size, Ordering::Relaxed);
                        }
                        Ok(())
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(ref dropped)) => {
                        let drops = DIAG_COUNTERS
                            .control_full_drops
                            .fetch_add(1, Ordering::Relaxed)
                            + 1;
                        // A full control queue drops frames at thousands per second
                        // right after an outage. One WARN and one diagnostics event per
                        // drop turned that into a log flood plus a diagnostics backlog
                        // the client engine then spent seconds draining in its main
                        // loop (the engine stalls while the TUN stays up). Report at
                        // most once a second; the counter keeps the exact total.
                        if control_full_report_due() {
                            netrunner_logger::warn!(
                                stream_id,
                                frame = ?dropped.frame_type,
                                total_drops = drops,
                                "Control queue FULL! Dropping non-critical control frames (reported once per second)."
                            );
                            diagnostics::send_diag_event(DiagnosticsEvent::ControlChannelFull {
                                stream_id,
                                frame_type: format!("{:?}", dropped.frame_type),
                            });
                        }
                        Ok(())
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        self.remove_leg(leg.id, &leg.control_tx);
                        Err(AppError::new(ERR_INFRA_TIMEOUT, "Обрыв", "Leg closed"))
                    }
                }
            }
        }
    }

    /// Удобная обёртка для отправки данных потока (выбирает `Data`/`UdpData`).
    pub async fn send_data_safe(
        &self,
        stream_id: u32,
        data: Bytes,
        is_udp: bool,
    ) -> Result<(), AppError> {
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type: if is_udp {
                FrameType::UdpData
            } else {
                FrameType::Data
            },
            data,
        })
        .await
    }

    /// Идентификатор сессии этого мультиплексора (для логов/топологии и для
    /// именования пер-сессионных файлов диагностики на сервере).
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Отправляет на сервер одну строку клиентской диагностики `Diag`-кадром.
    ///
    /// Холодный путь: едет по контрольному каналу с best-effort семантикой (как и
    /// прочий не-критичный контроль — при переполнении канала кадр дропается, не
    /// блокируя). Возвращает `false`, только если живых ног нет вовсе — тогда
    /// вызывающая сторона может оставить снапшот в очереди и повторить позже.
    pub async fn send_diag_report(&self, payload: Bytes) -> bool {
        self.send_to_network(MuxMessage {
            stream_id: 0,
            frame_type: FrameType::Diag,
            data: payload,
        })
        .await
        .is_ok()
    }

    /// Sends a control frame on a SPECIFIC leg. Heartbeat replies use it: a PONG that
    /// comes back on a different leg than the PING proves nothing about the pinged leg
    /// and makes its RTT sample garbage (the time since that other leg's last ping).
    /// Falls back to the normal routing if the leg is gone or its writer is closed.
    pub(crate) async fn send_control_on_leg(
        &self,
        leg_id: u32,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), AppError> {
        let leg = self.legs.get(&leg_id).map(|l| l.value().clone());
        if let Some(leg) = leg {
            let size = data.len() as u64;
            let msg = MuxMessage {
                stream_id,
                frame_type: f_type,
                data: data.clone(),
            };
            if leg.control_tx.send(msg).await.is_ok() {
                leg.stats.tx_bytes.fetch_add(size, Ordering::Relaxed);
                return Ok(());
            }
        }
        self.send_control(stream_id, f_type, data).await
    }

    /// Списывает отправленные `size` байт Data с кредитного окна потока.
    fn debit_credit(&self, stream_id: u32, size: usize) {
        if let Some(state) = self.credits.get(&stream_id) {
            state.sent.fetch_add(size as u64, Ordering::AcqRel);
        }
    }

    /// Whether the leg has answered a heartbeat/PING at least once and is still fresh.
    #[cfg(test)]
    pub(crate) fn leg_has_pong(&self, leg_id: u32) -> bool {
        self.legs.get(&leg_id).is_some_and(|leg| {
            let last_pong = leg.stats.last_pong_ms.load(Ordering::Relaxed);
            last_pong != 0
                && process_uptime_ms().saturating_sub(last_pong)
                    < crate::net::LEG_PONG_FRESHNESS.as_millis() as u64
        })
    }

    /// Удобная обёртка для отправки управляющего кадра заданного типа.
    pub(crate) async fn send_control(
        &self,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), AppError> {
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type: f_type,
            data,
        })
        .await
    }

    /// Регистрирует поток с бэклогом по умолчанию ([`STREAM_BACKLOG_MAX_BYTES`])
    /// и возвращает его [`CancellationToken`]. Канал `tx` используется для
    /// доставки входящих данных потоку (`dispatch_to_local`).
    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) -> CancellationToken {
        self.register_stream_with_backlog_cap(stream_id, tx, STREAM_BACKLOG_MAX_BYTES)
    }

    /// Регистрирует поток с явным байтовым бюджетом бэклога. Используется
    /// сервером для потоков к реальной цели ([`SERVER_STREAM_BACKLOG_MAX_BYTES`]),
    /// где нужен запас больше дефолтного — см. модульный докстринг.
    pub fn register_stream_with_backlog_cap(
        &self,
        stream_id: u32,
        tx: Sender<Bytes>,
        backlog_cap_bytes: usize,
    ) -> CancellationToken {
        let token = CancellationToken::new();
        let stats = Arc::new(StreamStats::default());
        let backlog = Arc::new(StreamBacklog::new(backlog_cap_bytes));

        Self::spawn_backlog_drainer(
            stream_id,
            tx.clone(),
            backlog.clone(),
            stats.clone(),
            token.clone(),
            self.clone(),
        );

        self.credits
            .insert(stream_id, Arc::new(CreditState::new()));
        self.streams.insert(
            stream_id,
            StreamSlot {
                tx,
                stats,
                token: token.clone(),
                backlog,
            },
        );
        // Слить ранние UDP-датаграммы, пришедшие ДО этой регистрации (bug #4).
        // Строго после вставки в `streams`: иначе `dispatch_to_local` внутри
        // flush не нашёл бы поток. Гонку с `buffer_early_udp` (тот тоже
        // перепроверяет регистрацию после вставки в буфер) закрывает то, что
        // обе стороны финализируют через атомарный `pending_udp.remove`.
        self.flush_pending_udp(stream_id);
        token
    }

    /// Persistent-задача одного потока: спит на [`Notify`], по пробуждению сливает
    /// весь накопленный бэклог в реальный канал потребителя блокирующим `send`
    /// (сколько угодно времени — здесь нет тайм-аута). Ровно одна такая задача на
    /// поток за всё время его жизни, поэтому порядок доставки внутри потока не
    /// нарушается, в отличие от спавна задачи на каждый кадр.
    fn spawn_backlog_drainer(
        stream_id: u32,
        tx: Sender<Bytes>,
        backlog: Arc<StreamBacklog>,
        stats: Arc<StreamStats>,
        token: CancellationToken,
        muxer: Muxer,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return,
                    _ = backlog.notify.notified() => {}
                }
                loop {
                    let item = backlog.queue.lock().unwrap().pop_front();
                    let Some(item) = item else { break };
                    let len = item.len() as u64;
                    if tx.send(item).await.is_err() {
                        // Consumer dropped its receiver — remove_stream elsewhere
                        // will clean up the entry; nothing more to drain into.
                        trace!(
                            stream_id,
                            "backlog drainer: consumer channel closed, stopping"
                        );
                        return;
                    }
                    backlog.bytes.fetch_sub(len as usize, Ordering::AcqRel);
                    backlog.mark_progress();
                    stats.rx_bytes.fetch_add(len, Ordering::Relaxed);
                    DIAG_COUNTERS
                        .mux_dispatch_ok
                        .fetch_add(1, Ordering::Relaxed);
                }

                // The peer closed this stream and everything it sent has now been
                // handed to the consumer: end the stream the graceful way. Dropping
                // the registry slot (and, on return, our own `tx`) closes the
                // consumer's channel AFTER the frames already buffered in it, so the
                // consumer reads the whole tail and then sees EOF. Cancelling the
                // token here instead (what `remove_stream` does) would abort it with
                // those frames still queued — the truncated-response bug.
                if backlog.closing.load(Ordering::Acquire)
                    && backlog.bytes.load(Ordering::Acquire) == 0
                {
                    if let Some((_, slot)) = muxer
                        .streams
                        .remove_if(&stream_id, |_, s| Arc::ptr_eq(&s.backlog, &backlog))
                    {
                        let linger = slot.token.clone();
                        muxer.closing_tokens.insert(stream_id, linger.clone());
                        drop(slot);
                        // The stream is over for both directions: free its credit window
                        // (releasing any sender still waiting on it), leg binding and the
                        // rest of its state. Only the consumer's tasks stay alive until
                        // they see EOF.
                        muxer.release_stream_state(stream_id);
                        // A consumer that ignores EOF must not live forever; the
                        // owner's `remove_stream` normally cancels the token first.
                        let closing_tokens = muxer.closing_tokens.clone();
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(
                                crate::net::STREAM_EOF_LINGER,
                                linger.cancelled(),
                            )
                            .await;
                            linger.cancel();
                            closing_tokens.remove(&stream_id);
                        });
                    }
                    return;
                }
            }
        });
    }

    /// Drops the receiving side of a stream (registry slot, backlog drainer, tasks tied
    /// to its token) but KEEPS its leg binding. Used when a bridge ends: the `Close`
    /// frame that follows must go out on the SAME leg as the stream's data, otherwise
    /// it can overtake data still queued on that leg and the peer drops the tail.
    /// The owner finishes the cleanup with [`remove_stream`](Self::remove_stream)
    /// after sending the `Close`.
    pub fn release_stream_inbound(&self, stream_id: u32) {
        // 🔥 Мгновенно убиваем "зомби-задачи", привязанные к стриму!
        if let Some((_, slot)) = self.streams.remove(&stream_id) {
            slot.token.cancel();
        }
        // Stream the peer already closed gracefully (`finish_stream`): the slot is
        // gone, but its tasks are still cancelled through the saved token.
        if let Some((_, token)) = self.closing_tokens.remove(&stream_id) {
            token.cancel();
        }
    }

    /// The peer closed `stream_id`. Unlike [`remove_stream`](Self::remove_stream) this
    /// does NOT throw away what is still on its way to the consumer: the stream ends
    /// once everything already received has been delivered, and the consumer then
    /// sees its channel close (EOF) instead of being cancelled mid-delivery.
    ///
    /// `Close` travels behind the stream's own `Data` on the wire, so by the time
    /// it is handled every byte the peer sent is either in the consumer's channel
    /// or in the stream backlog — both are preserved.
    pub fn finish_stream(&self, stream_id: u32) {
        let Some(backlog) = self
            .streams
            .get(&stream_id)
            .map(|entry| entry.value().backlog.clone())
        else {
            return;
        };
        backlog.closing.store(true, Ordering::Release);
        backlog.notify.notify_one();
    }

    /// Удаляет поток, отменяя его токен (мгновенно гасит связанные задачи, включая
    /// бэклог-дренер) и снимая привязку к ноге.
    pub fn remove_stream(&self, stream_id: u32) {
        self.release_stream_inbound(stream_id);
        self.release_stream_state(stream_id);
    }

    /// Everything about a stream except its receiving half: credit window, leg
    /// binding, UDP flowlet and early-datagram buffer.
    fn release_stream_state(&self, stream_id: u32) {
        self.drop_credit(stream_id);
        self.stream_bindings.remove(&stream_id);
        self.udp_flowlets.remove(&stream_id);
        // Поток закрыт — держать под ним ранний UDP-буфер незачем.
        self.pending_udp.remove(&stream_id);
    }

    // ORDERING CONTRACT: preserved by construction — each stream has exactly one
    // persistent backlog-drainer task (spawned once, at register_stream), so this
    // function never spawns per-frame and never reorders within a stream.
    //
    // HEAD-OF-LINE GUARD: this function never awaits. The hot path is a
    // non-blocking try_send; when the channel is momentarily full, the frame is
    // queued in the stream's own backlog and the call returns immediately — the
    // shared per-leg reader can move on to the next frame/stream right away.
    //
    // NO Ref HELD ACROSS A MUTATING CALL: the DashMap `Ref` from `streams.get`
    // is dropped the instant we've cloned the owned handles we need (`tx`,
    // `stats`, `backlog` — all cheap Arc/Sender clones). This function never
    // calls anything that mutates `self.streams` for this same key — eviction
    // is entirely the background reaper's job (see `spawn_backlog_reaper`) —
    // so there is no risk of a shard read-lock (still held by an outer `Ref`)
    // deadlocking against that shard's write-lock (DashMap locks are not
    // reentrant). An earlier version held the `Ref` across a nested
    // `remove_stream` call here and could self-deadlock the calling task.
    /// Доставка входящей UDP-датаграммы. Отличается от [`dispatch_to_local`]
    /// (её путь для TCP `Data`) ровно одним: если поток ещё не зарегистрирован,
    /// кадр не отбрасывается, а коротко буферизуется — первый `UdpData` нового
    /// потока часто обгоняет свой `UdpConnect`, едущий по TCP (bug #4). TCP
    /// `Data` так буферизовать нельзя (там порядок и надёжность гарантируются
    /// иначе), поэтому это отдельный вход, а не флаг внутри `dispatch_to_local`.
    pub fn dispatch_to_local_udp(&self, stream_id: u32, data: Bytes) {
        if self.streams.contains_key(&stream_id) {
            self.dispatch_to_local(stream_id, data);
        } else {
            self.buffer_early_udp(stream_id, data);
        }
    }

    /// Кладёт раннюю UDP-датаграмму в буфер ожидания под жёсткими границами (см.
    /// [`PendingUdp`]). После вставки перепроверяет регистрацию потока: если он
    /// успел появиться между нашей проверкой и вставкой, сливаем немедленно —
    /// так гонка «зарегистрировали ровно сейчас» не оставляет кадр висеть до
    /// TTL/подметания.
    fn buffer_early_udp(&self, stream_id: u32, data: Bytes) {
        let size = data.len();
        // Слишком большой одиночный кадр в буфер ожидания не помещается вовсе.
        if size > PENDING_UDP_STREAM_MAX_BYTES {
            DIAG_COUNTERS
                .mux_dispatch_no_stream
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        // ВАЖНО: не звать `pending_udp.len()`/`.insert()` под guard'ом `get_mut`
        // из той же DashMap — это шардовый лок, он не реентерабельный, и len()
        // (обход всех шардов) на нём самоблокируется. Поэтому guard из ветки
        // Some дропается до выхода из `if let`, а len()/insert() живут в else,
        // где guard'а уже нет.
        if let Some(mut p) = self.pending_udp.get_mut(&stream_id) {
            if p.bytes + size > PENDING_UDP_STREAM_MAX_BYTES {
                // Переполнение буфера потока — дропаем именно этот кадр,
                // сохраняя уже накопленный префикс (у UDP нет гарантии доставки,
                // потеря отдельной датаграммы допустима).
                DIAG_COUNTERS
                    .mux_dispatch_no_stream
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            p.bytes += size;
            p.queue.push_back(data);
        } else {
            // guard'а нет (get_mut вернул None) — len()/insert() безопасны.
            if self.pending_udp.len() >= MAX_PENDING_UDP_STREAMS {
                // Слишком много ожидающих потоков — не заводим новый (анти-DoS:
                // иначе `UdpData` на случайные id раздувал бы память). Кадр
                // отбрасываем.
                DIAG_COUNTERS
                    .mux_dispatch_no_stream
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let mut queue = VecDeque::with_capacity(1);
            queue.push_back(data);
            self.pending_udp.insert(
                stream_id,
                PendingUdp {
                    queue,
                    bytes: size,
                    since_ms: process_uptime_ms().max(1),
                },
            );
        }

        // Закрываем гонку с регистрацией потока (см. докстринг). Guard из
        // веток выше здесь уже дропнут — `flush_pending_udp` может снова
        // локать `pending_udp` без реентерабельности.
        if self.streams.contains_key(&stream_id) {
            self.flush_pending_udp(stream_id);
        }
    }

    /// Сливает ранее буферизованные ранние UDP-датаграммы в уже
    /// зарегистрированный поток, по порядку прихода, и снимает запись буфера.
    /// Идемпотентна: нет записи — ничего не делает.
    fn flush_pending_udp(&self, stream_id: u32) {
        if let Some((_, pending)) = self.pending_udp.remove(&stream_id) {
            for data in pending.queue {
                self.dispatch_to_local(stream_id, data);
            }
        }
    }

    /// Подметает протухшие записи буфера ожидания (поток так и не открылся за
    /// [`PENDING_UDP_TTL`]) — вызывается фоновым `spawn_backlog_reaper`.
    fn sweep_expired_pending_udp(&self) {
        let now = process_uptime_ms();
        let ttl_ms = PENDING_UDP_TTL.as_millis() as u64;
        self.pending_udp
            .retain(|_, p| now.saturating_sub(p.since_ms) < ttl_ms);
    }

    pub fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        let size = data.len() as u64;

        let Some((tx, stats, backlog)) = self.streams.get(&stream_id).map(|entry| {
            let slot = entry.value();
            (slot.tx.clone(), slot.stats.clone(), slot.backlog.clone())
        }) else {
            // No stream registered for this id (already closed / never opened).
            DIAG_COUNTERS
                .mux_dispatch_no_stream
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let backlog_empty = backlog.bytes.load(Ordering::Acquire) == 0;

        // Fast path: nothing queued ahead of this frame, try to hand it straight
        // to the consumer without ever touching the backlog.
        if backlog_empty {
            match tx.try_send(data) {
                Ok(()) => {
                    stats.rx_bytes.fetch_add(size, Ordering::Relaxed);
                    backlog.mark_progress();
                    DIAG_COUNTERS
                        .mux_dispatch_ok
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Closed(_)) => {
                    DIAG_COUNTERS
                        .mux_dispatch_recv_closed
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Full(data)) => {
                    backlog.push(data, size);
                }
            }
        } else {
            backlog.push(data, size);
        }
    }

    /// Снимает кредитное окно потока и отпускает ждущего в [`credit_gate`] отправителя.
    pub fn drop_credit(&self, stream_id: u32) {
        if let Some((_, state)) = self.credits.remove(&stream_id) {
            state.closed.store(true, Ordering::Release);
            state.notify.notify_waiters();
            state.notify.notify_one();
        }
    }

    /// Обрабатывает входящий `Credit`-кадр: `offset` — абсолютный лимит отправки в
    /// байтах Data с начала потока (по модулю 2³²). Идемпотентно: дубликат или
    /// запоздавший кадр лимит не откатывают. No-op для неизвестного потока (кадр
    /// пришёл после его снятия).
    pub fn grant_credit(&self, stream_id: u32, offset: u32) {
        let Some(state) = self.credits.get(&stream_id).map(|e| e.value().clone()) else {
            return;
        };
        loop {
            let current = state.limit.load(Ordering::Acquire);
            let next = if current == u64::MAX {
                // Первый грант: лимит абсолютный от начала потока, продолжать нечего.
                Some(offset as u64)
            } else {
                crate::net::credit::extend_limit(current, offset)
            };
            let Some(next) = next else { return };
            if state
                .limit
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        state
            .last_grant_ms
            .store(diagnostics::current_timestamp_ms(), Ordering::Relaxed);
        state.notify.notify_one();
    }

    /// Шлюз отправки Data: ждёт, пока у потока есть кредит. Списание делает
    /// [`debit_credit`](Self::debit_credit) уже после того, как кадр принят каналом
    /// ноги — повтор отправки после failover не должен списывать дважды.
    ///
    /// Стоит в единственном месте, через которое проходят все Data на ногу
    /// ([`send_to_network`](Self::send_to_network)), поэтому работает для любого
    /// отправителя — моста сервера, мост-реле меша, клиентской выгрузки — без
    /// изменений в каждом. Ожидание блокирует именно отправителя этого потока: его
    /// источник перестаёт читаться, и TCP-backpressure доходит до цели/приложения,
    /// а соседние потоки на той же ноге не страдают.
    ///
    /// Без грантов (старый пир) возвращается сразу. Списание «в долг» (одним чанком
    /// сверх окна) допустимо: окно мягкое, перелёт не больше одного чанка.
    async fn credit_gate(&self, stream_id: u32) {
        let Some(state) = self.credits.get(&stream_id).map(|e| e.value().clone()) else {
            return;
        };
        loop {
            if !state.exhausted() || state.closed.load(Ordering::Acquire) {
                return;
            }
            let since_grant = diagnostics::current_timestamp_ms()
                .saturating_sub(state.last_grant_ms.load(Ordering::Relaxed));
            if since_grant >= crate::net::CREDIT_STALL_FALLBACK.as_millis() as u64 {
                warn!(
                    stream_id,
                    "credit gate: no grant for {:?} — sending unrestricted",
                    crate::net::CREDIT_STALL_FALLBACK
                );
                return;
            }
            let _ =
                tokio::time::timeout(crate::net::CREDIT_WAIT_POLL, state.notify.notified()).await;
        }
    }

    /// Учитывает принятые ногой байты в её статистике.
    pub fn record_leg_rx(&self, leg_id: u32, bytes: u64) {
        if let Some(leg) = self.legs.get(&leg_id) {
            leg.stats.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// This leg's own smoothed RTT (EWMA over PONGs, see `record_pong`), if
    /// it's still registered. `None` before its first PONG, or once it has
    /// been evicted — callers fall back to [`GLOBAL_MIN_RTT`] in that case.
    pub fn leg_rtt_ms(&self, leg_id: u32) -> Option<u32> {
        self.legs
            .get(&leg_id)
            .map(|leg| leg.stats.rtt_ms.load(Ordering::Relaxed))
    }

    /// Write timeout for a write on THIS specific leg, scaled by its own RTT
    /// rather than the process-wide [`GLOBAL_MIN_RTT`].
    ///
    /// `adaptive_write_timeout(floor)` scales off the *fastest* leg in the
    /// whole process — fine for a local-socket write with no single leg to
    /// attribute it to, wrong for a leg's own write: a session with one fast
    /// leg (RTT ~700 ms) and three legs limping at 10-20 s RTT to a degraded
    /// path computed every leg's timeout from that 700 ms figure, so the
    /// slow-but-alive legs kept tripping the same flat-timeout kill this
    /// function exists to avoid (see `adaptive_write_timeout`'s doc and the
    /// leg-death RCA). Falls back to the global figure only when this leg
    /// hasn't reported an RTT yet (first write, before any PONG).
    pub fn adaptive_leg_write_timeout(&self, leg_id: u32, floor: Duration) -> Duration {
        let rtt_ms = self
            .leg_rtt_ms(leg_id)
            .filter(|&rtt| rtt > 0)
            .unwrap_or_else(|| GLOBAL_MIN_RTT.load(Ordering::Relaxed));
        scale_write_timeout(rtt_ms, floor)
    }

    /// Следующий свободный `stream_id` (с учётом чётности роли).
    pub fn next_stream_id(&self) -> u32 {
        self.id_gen.next()
    }

    /// Прогоняет health-check по всем ногам: PING с уникальным probe-потоком и
    /// ожидание PONG в пределах [`HEALTH_CHECK_TIMEOUT`](crate::net::HEALTH_CHECK_TIMEOUT).
    ///
    /// Тонкости (см. inline): закрытый канал → немедленный эвикт; временно
    /// полный → пропуск цикла (нога жива, просто занята); перед эвиктом по
    /// тайм-ауту сверяется, что нога не переподключилась под тем же id.
    pub async fn perform_health_check(&self) {
        let leg_ids: Vec<u32> = self.legs.iter().map(|kv| *kv.key()).collect();

        for leg_id in leg_ids {
            let tx = {
                let Some(leg) = self.legs.get(&leg_id) else {
                    continue;
                };

                // Нога, которая ответила PONG'ом недавно, уже доказала, что
                // жива — слать ей ещё один PING незачем. Heartbeat writer'а и
                // этот health-check исторически работали независимо и на живой
                // ноге дублировали друг друга: на пустом туннеле это давало
                // четыре записи на ногу за цикл вместо одной, то есть основной
                // объём холостого трафика.
                let last_pong = leg.stats.last_pong_ms.load(Ordering::Relaxed);
                if last_pong != 0
                    && process_uptime_ms().saturating_sub(last_pong)
                        < crate::net::LEG_PONG_FRESHNESS.as_millis() as u64
                {
                    trace!(leg_id, "Health check skipped: fresh PONG already seen");
                    continue;
                }

                leg.control_tx.clone()
            };

            let probe_stream_id = self.id_gen.next();
            let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel(10);
            let _token = self.register_stream(probe_stream_id, probe_tx);
            self.record_ping_sent(leg_id);

            let msg = MuxMessage {
                stream_id: probe_stream_id,
                frame_type: FrameType::Heartbeat,
                data: Bytes::from("PING"),
            };
            match tx.try_send(msg) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // Writer is already dead — evict immediately without waiting 20s.
                    warn!(
                        leg_id,
                        "Health check: control channel closed, evicting dead leg"
                    );
                    self.remove_leg(leg_id, &tx);
                    self.remove_stream(probe_stream_id);
                    continue;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Control channel is temporarily full: the writer is alive and
                    // busy processing other frames. Skip this probe cycle — evicting
                    // a healthy leg because its queue is momentarily saturated would
                    // cause a spurious reconnect.
                    self.remove_stream(probe_stream_id);
                    continue;
                }
            }

            match tokio::time::timeout(crate::net::HEALTH_CHECK_TIMEOUT, probe_rx.recv()).await {
                Ok(Some(_)) => trace!(leg_id, "✅ TCP Leg Health Check OK"),
                _ => {
                    // Before evicting, verify the muxer still holds the same control_tx
                    // we probed with.  After an internal reconnect, add_leg replaces the
                    // entry with new channels, and the old probe belongs to a dead leg
                    // that the engine has already recycled — evicting the new leg here
                    // would be wrong.
                    let still_same = self
                        .legs
                        .get(&leg_id)
                        .is_some_and(|l| l.control_tx.same_channel(&tx));
                    if still_same {
                        warn!(leg_id, "❌ TCP Leg Health Check FAIL/Timeout - Evicting");
                        self.remove_leg(leg_id, &tx);
                    } else {
                        netrunner_logger::debug!(
                            leg_id,
                            "Health check probe timed out but leg already reconnected — skipping eviction"
                        );
                    }
                }
            }
            self.remove_stream(probe_stream_id);
        }
    }

    fn format_size(bytes: u64) -> String {
        /* ... (оставлено без изменений) ... */
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Печатает в лог дерево топологии туннеля: ноги (трафик/RTT), виртуальные
    /// потоки и кумулятивные счётчики здоровья пайплайна. Чисто диагностика.
    pub fn print_topology_tree(&self) {
        let mut out = String::new();
        out.push_str(&format!(
            "🌐 Netrunner Tunnel Topology [Session: {}]\n",
            self.session_id
        ));

        let (total_tx, total_rx) = self.total_bytes();
        let mut legs_info = Vec::new();

        let cached_legs = self.active_legs_cache.load_full();
        for leg in cached_legs.iter() {
            let tx = leg.stats.tx_bytes.load(Ordering::Relaxed);
            let rx = leg.stats.rx_bytes.load(Ordering::Relaxed);
            let rtt = leg.stats.rtt_ms.load(Ordering::Relaxed);

            let rtt_str = if rtt == 0 {
                "N/A".to_string()
            } else {
                format!("{}ms", rtt)
            };
            legs_info.push(format!(
                "   ├─ Leg {} (TCP+TLS) ─ ⇡ {:<9} | ⇣ {:<9} [RTT: {}]",
                leg.id,
                Self::format_size(tx),
                Self::format_size(rx),
                rtt_str
            ));
        }

        out.push_str(&format!(
            "├─ 📊 Global Traffic: ⇡ {} | ⇣ {}\n├─ 🦵 Physical Connections (Active: {})\n",
            Self::format_size(total_tx),
            Self::format_size(total_rx),
            legs_info.len()
        ));
        for (i, info) in legs_info.iter().enumerate() {
            out.push_str(&format!(
                "{}\n",
                if i == legs_info.len() - 1 {
                    info.replace("├─", "└─")
                } else {
                    info.clone()
                }
            ));
        }

        // Клонируем данные стримов, чтобы не блокировать DashMap при форматировании текста
        let streams_snapshot: Vec<(u32, u64, u64)> = self
            .streams
            .iter()
            .map(|kv| {
                (
                    *kv.key(),
                    kv.value().stats.tx_bytes.load(Ordering::Relaxed),
                    kv.value().stats.rx_bytes.load(Ordering::Relaxed),
                )
            })
            .collect();

        out.push_str(&format!(
            "└─ 🔀 Virtual Streams (TCP/UDP multiplexed: {})\n",
            streams_snapshot.len()
        ));
        for (count, (id, tx, rx)) in streams_snapshot.into_iter().enumerate() {
            let prefix = if count == self.streams.len() - 1 {
                "   └─"
            } else {
                "   ├─"
            };
            out.push_str(&format!(
                "{} Stream {:<4} ─ ⇡ {:<9} | ⇣ {}\n",
                prefix,
                id,
                Self::format_size(tx),
                Self::format_size(rx)
            ));
        }

        // ── Pipeline health counters (cumulative) ────────────────────────────
        let c = &DIAG_COUNTERS;
        out.push_str(&format!(
            "├─ 📥 Mux dispatch: ok={} no_stream={} full_closed={} recv_closed={}\n",
            c.mux_dispatch_ok.load(Ordering::Relaxed),
            c.mux_dispatch_no_stream.load(Ordering::Relaxed),
            c.mux_dispatch_full_closed.load(Ordering::Relaxed),
            c.mux_dispatch_recv_closed.load(Ordering::Relaxed),
        ));
        out.push_str(&format!(
            "└─ 📤 Upload/legs: upload_fails={} ctrl_full_drops={} write_stalls={} leg_disconnects={}",
            c.upload_fails.load(Ordering::Relaxed),
            c.control_full_drops.load(Ordering::Relaxed),
            c.tunnel_write_stalls.load(Ordering::Relaxed),
            c.leg_disconnects.load(Ordering::Relaxed),
        ));

        info!("\n{}", out);
    }

    /// Collect a point-in-time snapshot of tunnel metrics for diagnostics.
    /// Lock-free: reads only atomics and the ArcSwap-backed legs cache.
    pub fn snapshot_tunnel_metrics(&self) -> TunnelMetrics {
        let global_min_rtt = crate::net::GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        let cached_legs = self.active_legs_cache.load_full();

        let active_legs: Vec<LegMetrics> = cached_legs
            .iter()
            .map(|leg| {
                let cap = leg.data_tx.max_capacity();
                let free = leg.data_tx.capacity();
                LegMetrics {
                    leg_id: leg.id,
                    rtt_ms: leg.stats.rtt_ms.load(Ordering::Relaxed),
                    tx_mb: leg.stats.tx_bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0,
                    rx_mb: leg.stats.rx_bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0,
                    congestion_factor: leg.congestion_factor(),
                    data_channel_free: free,
                    data_channel_capacity: cap,
                    session_id: self.session_id.to_string(),
                }
            })
            .collect();

        TunnelMetrics {
            global_min_rtt_ms: global_min_rtt,
            active_legs,
            total_streams: self.streams.len(),
            session_count: 1,
        }
    }
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;

    fn muxer_with_two_legs() -> Muxer {
        let muxer = Muxer::new(true, "scheduling-test".into());
        for leg_id in 0..2 {
            let (control_tx, _control_rx) = tokio::sync::mpsc::channel(8);
            let (data_tx, _data_rx) = tokio::sync::mpsc::channel(8);
            muxer.add_leg(leg_id, control_tx, data_tx);
            muxer
                .legs
                .get(&leg_id)
                .unwrap()
                .stats
                .rtt_ms
                .store(50, Ordering::Relaxed);
        }
        muxer.update_legs_cache();
        muxer
    }

    /// bug #4: ранний `UdpData`, пришедший ДО регистрации потока, обязан быть
    /// буферизован и слит по порядку в момент регистрации (которую делает
    /// `UdpConnect`, едущий по TCP), а не отброшен.
    #[tokio::test]
    async fn early_udp_data_is_buffered_then_flushed_in_order_on_registration() {
        let muxer = Muxer::new(false, "pending-test".into());

        muxer.dispatch_to_local_udp(7, Bytes::from_static(b"early-1"));
        muxer.dispatch_to_local_udp(7, Bytes::from_static(b"early-2"));
        assert_eq!(
            muxer.pending_udp.len(),
            1,
            "early UdpData for an unregistered stream must be buffered, not dropped"
        );

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let _tok = muxer.register_stream(7, tx);

        assert!(
            muxer.pending_udp.get(&7).is_none(),
            "registration must drain and remove the pending buffer"
        );
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"early-1"));
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"early-2"));
    }

    /// Уже зарегистрированный поток идёт быстрым путём, без буфера ожидания.
    #[tokio::test]
    async fn udp_for_a_registered_stream_bypasses_the_pending_buffer() {
        let muxer = Muxer::new(false, "pending-fast".into());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let _tok = muxer.register_stream(3, tx);

        muxer.dispatch_to_local_udp(3, Bytes::from_static(b"live"));
        assert!(muxer.pending_udp.is_empty());
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"live"));
    }

    /// Анти-DoS: буфер ожидания ограничен и по числу потоков, и по байтам на
    /// поток — переполнение отбрасывает лишнее, не раздувая память.
    #[tokio::test]
    async fn pending_udp_buffer_enforces_its_caps() {
        let muxer = Muxer::new(false, "pending-caps".into());

        // Заполняем ровно до лимита числа ожидающих потоков.
        for id in 0..MAX_PENDING_UDP_STREAMS as u32 {
            muxer.dispatch_to_local_udp(id, Bytes::from_static(b"x"));
        }
        assert_eq!(muxer.pending_udp.len(), MAX_PENDING_UDP_STREAMS);
        // Ещё один НОВЫЙ поток сверх лимита не заводится.
        muxer.dispatch_to_local_udp(999_999, Bytes::from_static(b"x"));
        assert_eq!(muxer.pending_udp.len(), MAX_PENDING_UDP_STREAMS);
        assert!(muxer.pending_udp.get(&999_999).is_none());

        // Байтовый потолок одного потока: одиночный кадр больше потолка не
        // помещается вовсе.
        let muxer2 = Muxer::new(false, "pending-bytes".into());
        let huge = Bytes::from(vec![0u8; PENDING_UDP_STREAM_MAX_BYTES + 1]);
        muxer2.dispatch_to_local_udp(1, huge);
        assert!(
            muxer2.pending_udp.is_empty(),
            "oversized early datagram must be dropped"
        );
    }

    /// TTL: свежая запись НЕ подметается, протухшая — подметается.
    #[tokio::test]
    async fn pending_udp_is_swept_after_ttl_but_fresh_entries_survive() {
        let muxer = Muxer::new(false, "pending-sweep".into());

        // Свежая запись переживает подметание.
        muxer.pending_udp.insert(
            10,
            PendingUdp {
                queue: std::collections::VecDeque::from(vec![Bytes::from_static(b"fresh")]),
                bytes: 5,
                since_ms: process_uptime_ms().max(1),
            },
        );
        muxer.sweep_expired_pending_udp();
        assert_eq!(
            muxer.pending_udp.len(),
            1,
            "fresh entry must survive a sweep"
        );

        // Протухшая (старше TTL) — уходит.
        let stale_since = process_uptime_ms().max(1);
        muxer.pending_udp.insert(
            11,
            PendingUdp {
                queue: std::collections::VecDeque::from(vec![Bytes::from_static(b"stale")]),
                bytes: 5,
                since_ms: stale_since,
            },
        );
        tokio::time::sleep(PENDING_UDP_TTL + std::time::Duration::from_millis(150)).await;
        muxer.sweep_expired_pending_udp();
        assert!(
            muxer.pending_udp.get(&11).is_none(),
            "entry older than PENDING_UDP_TTL must be swept"
        );
    }

    #[tokio::test]
    async fn healthy_udp_burst_stays_in_one_flowlet() {
        let muxer = muxer_with_two_legs();
        let first = muxer.select_udp_leg(11, 100).unwrap().id;
        let second = muxer.select_udp_leg(11, 100).unwrap().id;

        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn congested_udp_flowlet_moves_to_another_leg() {
        let muxer = muxer_with_two_legs();
        let first = muxer.select_udp_leg(13, 100).unwrap().id;
        let leg = muxer.legs.get(&first).unwrap();
        leg.stats.queued_data_bytes.store(
            (leg.data_tx.max_capacity() * BRIDGE_READ_CHUNK) as u64,
            Ordering::Relaxed,
        );
        drop(leg);

        let second = muxer.select_udp_leg(13, 100).unwrap().id;
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn select_udp_leg_prefers_a_fresh_native_datagram_leg_over_tcp() {
        let muxer = muxer_with_two_legs();
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(8);
        let (data_tx, _data_rx) = tokio::sync::mpsc::channel(8);
        muxer.set_datagram_leg(control_tx, data_tx);
        muxer
            .datagram_leg_stats()
            .unwrap()
            .last_pong_ms
            // Не `process_uptime_ms()`: в первую же миллисекунду свежего
            // тестового процесса он сам может вернуть 0, что неотличимо от
            // "PONG ещё не приходил" (см. докстринг `last_pong_ms`/
            // `datagram_leg_is_fresh`) — гарантированно ненулевое значение
            // тестирует именно "недавно" вне этой гонки.
            .store(1, Ordering::Relaxed);

        let selected = muxer.select_udp_leg(99, 100).unwrap();
        assert_eq!(selected.id, DATAGRAM_LEG_ID);
    }

    #[tokio::test]
    async fn full_native_datagram_queue_drops_udp_without_blocking_the_flow() {
        let muxer = Muxer::new(false, "native-udp-full".into());
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(1);
        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel(1);
        muxer.set_datagram_leg(control_tx, data_tx);
        muxer.mark_datagram_leg_alive();

        muxer
            .send_data_safe(7, Bytes::from_static(b"first"), true)
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            muxer.send_data_safe(7, Bytes::from_static(b"second"), true),
        )
        .await
        .expect("a full UDP queue must not stall the flow")
        .unwrap();

        assert_eq!(
            data_rx.recv().await.unwrap().data,
            Bytes::from_static(b"first")
        );
        assert!(
            data_rx.try_recv().is_err(),
            "overflow datagram should be dropped"
        );
    }

    #[tokio::test]
    async fn select_udp_leg_falls_back_to_tcp_when_native_leg_is_stale() {
        let muxer = muxer_with_two_legs();
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(8);
        let (data_tx, _data_rx) = tokio::sync::mpsc::channel(8);
        muxer.set_datagram_leg(control_tx, data_tx);
        // Никогда не отмечался живым (last_pong_ms остаётся 0) — тот же
        // критерий "не жива", что и у TCP-ног в perform_health_check.

        let selected = muxer.select_udp_leg(99, 100).unwrap();
        assert_ne!(
            selected.id, DATAGRAM_LEG_ID,
            "a native leg with no fresh PONG must not be selected"
        );
    }

    #[tokio::test]
    async fn network_change_is_timestamped_by_remove_all_legs() {
        let muxer = Muxer::new(true, "t".into());
        assert_eq!(muxer.ms_since_network_change(), None);
        muxer.remove_all_legs();
        assert!(muxer.ms_since_network_change().is_some_and(|ms| ms < 1_000));
    }

    #[test]
    fn throttle_reports_once_per_interval() {
        let last = AtomicU64::new(0);
        assert!(throttle_due(&last, 5_000, 1000), "first call reports");
        assert!(!throttle_due(&last, 5_001, 1000));
        assert!(!throttle_due(&last, 5_999, 1000));
        assert!(throttle_due(&last, 6_000, 1000), "interval elapsed");
        assert!(!throttle_due(&last, 6_500, 1000));
    }

    #[tokio::test]
    async fn select_udp_leg_falls_back_to_tcp_after_native_leg_is_cleared() {
        let muxer = muxer_with_two_legs();
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(8);
        let (data_tx, _data_rx) = tokio::sync::mpsc::channel(8);
        muxer.set_datagram_leg(control_tx, data_tx);
        muxer
            .datagram_leg_stats()
            .unwrap()
            .last_pong_ms
            // Не `process_uptime_ms()`: в первую же миллисекунду свежего
            // тестового процесса он сам может вернуть 0, что неотличимо от
            // "PONG ещё не приходил" (см. докстринг `last_pong_ms`/
            // `datagram_leg_is_fresh`) — гарантированно ненулевое значение
            // тестирует именно "недавно" вне этой гонки.
            .store(1, Ordering::Relaxed);
        assert_eq!(muxer.select_udp_leg(99, 100).unwrap().id, DATAGRAM_LEG_ID);

        muxer.clear_datagram_leg();
        let selected = muxer.select_udp_leg(99, 100).unwrap();
        assert_ne!(selected.id, DATAGRAM_LEG_ID);
    }

    /// Кадр крупнее потолка датаграммы обязан обойти свежую native-ногу и уйти
    /// на TCP-фолбэк (bug #5), а кадр в пределах потолка — остаться на native.
    #[tokio::test]
    async fn select_udp_leg_routes_oversized_payload_over_tcp() {
        let muxer = muxer_with_two_legs();
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(8);
        let (data_tx, _data_rx) = tokio::sync::mpsc::channel(8);
        muxer.set_datagram_leg(control_tx, data_tx);
        muxer
            .datagram_leg_stats()
            .unwrap()
            .last_pong_ms
            .store(1, Ordering::Relaxed);

        // В пределах потолка — native.
        assert_eq!(
            muxer
                .select_udp_leg(7, MAX_DATAGRAM_LEG_PAYLOAD)
                .unwrap()
                .id,
            DATAGRAM_LEG_ID
        );
        // На байт больше — TCP-фолбэк, несмотря на свежую native-ногу.
        assert_ne!(
            muxer
                .select_udp_leg(7, MAX_DATAGRAM_LEG_PAYLOAD + 1)
                .unwrap()
                .id,
            DATAGRAM_LEG_ID,
            "кадр больше потолка не должен уходить на физическую UDP-ногу"
        );
    }

    /// Регрессия на bug #6: если писатель native-ноги умер (его приёмники
    /// сброшены), но нога ещё числится «свежей», `send_to_network(UdpData)`
    /// раньше крутился вхолодную — `remove_leg(DATAGRAM_LEG_ID)` был no-op, и
    /// `select_udp_leg` бесконечно отдавал ту же мёртвую ногу. Теперь первый же
    /// отказ снимает датаграммную ногу через `clear_datagram_leg`.
    #[tokio::test]
    async fn dead_datagram_writer_clears_the_leg_instead_of_spinning() {
        let muxer = Muxer::new(true, "spin-test".into());
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(8);
        let (data_tx, data_rx) = tokio::sync::mpsc::channel(8);
        muxer.set_datagram_leg(control_tx, data_tx);
        muxer
            .datagram_leg_stats()
            .unwrap()
            .last_pong_ms
            .store(1, Ordering::Relaxed); // «свежая»
                                          // Писатель мёртв: роняем приёмники, канал закрыт.
        drop(control_rx);
        drop(data_rx);
        assert!(muxer.datagram_leg_stats().is_some());

        // Нет TCP-ног вовсе → после снятия native-ноги остаётся только Err,
        // а НЕ бесконечный цикл. Тест завершается — значит спина нет.
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            muxer.send_to_network(MuxMessage {
                stream_id: 7,
                frame_type: FrameType::UdpData,
                data: Bytes::from_static(b"x"),
            }),
        )
        .await
        .expect("send_to_network must not spin forever on a dead datagram leg");
        assert!(res.is_err(), "no legs left → Err, not success");
        assert!(
            muxer.datagram_leg_stats().is_none(),
            "мёртвая датаграммная нога должна быть снята"
        );
    }

    #[tokio::test]
    async fn try_claim_datagram_leg_token_is_first_writer_wins() {
        let muxer = Muxer::new(true, "claim-test".into());
        assert!(muxer.try_claim_datagram_leg_token([1u8; 16]));
        // Вторая попытка — даже с ДРУГИМ токеном — обязана проиграть в пределах
        // одной эпохи сети (а не в пользу "последнего/лучшего" значения).
        assert!(!muxer.try_claim_datagram_leg_token([2u8; 16]));
        assert_eq!(muxer.datagram_leg_token(), Some([1u8; 16]));
    }

    /// bug #2: заявку можно СБРОСИТЬ (это делает смена сети), и тогда следующая
    /// нога поднимает новую попытку.
    #[tokio::test]
    async fn resetting_the_claim_allows_a_fresh_attempt() {
        let muxer = Muxer::new(true, "reclaim-test".into());
        assert!(muxer.try_claim_datagram_leg_token([1u8; 16]));
        assert!(!muxer.try_claim_datagram_leg_token([2u8; 16]));

        muxer.reset_datagram_leg_claim();
        assert!(
            muxer.try_claim_datagram_leg_token([3u8; 16]),
            "after reset a new attempt must be claimable"
        );
        assert_eq!(muxer.datagram_leg_token(), Some([3u8; 16]));
    }

    /// Смена сети (`remove_all_legs`) обязана освободить заявку — иначе
    /// UDP-нога была бы одноразовой (bug #2).
    #[tokio::test]
    async fn network_change_frees_the_datagram_claim() {
        let muxer = Muxer::new(true, "nc-test".into());
        assert!(muxer.try_claim_datagram_leg_token([1u8; 16]));
        muxer.remove_all_legs();
        assert!(
            muxer.try_claim_datagram_leg_token([2u8; 16]),
            "network change must free the datagram-leg claim for a re-attempt"
        );
    }

    #[tokio::test]
    async fn byte_accounting_includes_writer_local_queue() {
        let muxer = muxer_with_two_legs();
        let leg = muxer.legs.get(&0).unwrap().clone();

        muxer.record_leg_data_queued(&leg, 10_000);
        assert_eq!(leg.stats.queued_data_bytes.load(Ordering::Relaxed), 10_000);
        assert_ne!(leg.stats.queued_since_ms.load(Ordering::Relaxed), 0);

        muxer.record_leg_data_drained(0, 4_000);
        assert_eq!(leg.stats.queued_data_bytes.load(Ordering::Relaxed), 6_000);
        muxer.record_leg_data_drained(0, 6_000);
        assert_eq!(leg.stats.queued_data_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(leg.stats.queued_since_ms.load(Ordering::Relaxed), 0);
    }

    /// Смена сети обязана именно УБИВАТЬ ноги, а не только вычищать карту.
    ///
    /// Проверяется и порядок: нога, которую разбудила отмена, тут же идёт
    /// переподключаться и берёт токен заново — он должен быть уже новым,
    /// иначе она мгновенно отменится сама об себя и уйдёт в цикл.
    #[tokio::test]
    async fn remove_all_legs_cancels_the_epoch_and_hands_out_a_fresh_one() {
        let muxer = Muxer::new(true, "test-session".into());

        let before = muxer.network_epoch_token();
        let leg_token = before.child_token();
        assert!(!leg_token.is_cancelled());

        muxer.remove_all_legs();

        assert!(
            leg_token.is_cancelled(),
            "токен ноги обязан отмениться вместе с эпохой"
        );
        let after = muxer.network_epoch_token();
        assert!(
            !after.is_cancelled(),
            "новая эпоха не должна быть отменённой — иначе следующая нога умрёт на старте"
        );
    }
}
