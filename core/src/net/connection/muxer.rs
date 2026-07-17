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

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{info, instrument, trace, warn, AppError, ERR_INFRA_TIMEOUT};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{error::TrySendError, Sender};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::net::diagnostics::{self, DiagnosticsEvent, LegMetrics, TunnelMetrics, DIAG_COUNTERS};
use crate::net::INITIAL_RTT_MS;
use crate::net::{
    BACKLOG_REAPER_IDLE_TIMEOUT, BACKLOG_REAPER_INTERVAL, BACKLOG_STUCK_GRACE, MAX_TUNNEL_LEGS,
    STREAM_BACKLOG_MAX_BYTES,
};
use crate::nrxp::FrameType;

/// Атомарная статистика одной ноги: переданные/принятые байты и сглаженный RTT.
#[derive(Default, Debug)]
pub struct LegStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rtt_ms: AtomicU32,
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
}

impl StreamBacklog {
    fn new(cap_bytes: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            bytes: AtomicUsize::new(0),
            cap_bytes,
            notify: Notify::new(),
            last_progress_ms: AtomicU64::new(diagnostics::current_timestamp_ms()),
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

/// Кредитное окно одного потока на СТОРОНЕ ОТПРАВИТЕЛЯ: сколько байт ещё можно
/// протолкнуть в туннель, прежде чем ждать `Credit`-кадр от приёмника.
///
/// Существует отдельно от `StreamBacklog` (тот — на стороне приёмника, отвечает
/// за "что делать, если консьюмер не успевает"). Кредит — упреждающая мера:
/// если он работает как задумано, `StreamBacklog` почти никогда не разрастается,
/// потому что отправитель сам не производит данные быстрее, чем приёмник может
/// их принять. `available` — `i64`, а не `usize`, чтобы `fetch_sub` мог уводить
/// его в отрицательные значения без паники при гонках (`consume_credit` всё
/// равно трактует `<= 0` как "кредита нет").
struct CreditState {
    available: std::sync::atomic::AtomicI64,
    notify: Notify,
    /// Метка времени (мс) последнего РЕАЛЬНОГО пополнения — либо `init_credit`,
    /// либо `grant_credit` от входящего `Credit`-кадра. `consume_credit`
    /// откатывается на неограниченную отправку, только если с последнего
    /// такого пополнения прошло больше [`crate::net::CREDIT_FALLBACK_AFTER`] —
    /// НЕ если истёк дедлайн текущего вызова (это была ошибка: дедлайн
    /// пересчитывался с нуля на каждый вызов `consume_credit`, поэтому после
    /// исчерпания стартового окна на высокой скорости отправитель получал
    /// жалкие `BRIDGE_READ_CHUNK` раз в `CREDIT_FALLBACK_AFTER` — то есть
    /// credit-контроль топил скачивание СИЛЬНЕЕ, чем если бы его не было
    /// вовсе, вместо того чтобы просто подождать очередной грант).
    last_grant_ms: AtomicU64,
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
}

impl MuxLeg {
    /// Степень загруженности `data`-канала: 0.0 — пусто, 1.0 — канал полностью
    /// забит. Используется в скоринге ног при выборе (`select_leg`).
    fn congestion_factor(&self) -> f64 {
        let max = self.data_tx.max_capacity();
        let current_capacity = self.data_tx.capacity();
        let filled = max.saturating_sub(current_capacity);
        (filled as f64) / (max as f64)
    }
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

pub static GLOBAL_MIN_RTT: AtomicU32 = AtomicU32::new(INITIAL_RTT_MS);

/// Write timeout that scales with the observed network RTT.
///
/// On a healthy path (RTT ~50 ms) this stays at `floor`. When the path degrades
/// to multi-second RTT (the > 2500 ms peaks seen in production), a flat 20 s
/// timeout fires on a leg that is merely *slow*, not dead — and a killed leg
/// triggers the leg-drop → stream-close cascade ("domino effect"). Allowing
/// ~8 RTT of drain time (capped at 60 s) keeps slow-but-alive legs from being
/// evicted under high latency, while still reaping genuinely stuck sockets.
pub fn adaptive_write_timeout(floor: Duration) -> Duration {
    let rtt_ms = GLOBAL_MIN_RTT.load(Ordering::Relaxed) as u64;
    let scaled = Duration::from_millis(rtt_ms.saturating_mul(8));
    scaled.clamp(floor, Duration::from_secs(60))
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
    /// Кредитные окна потоков, для которых ЭТА сторона — отправитель (см.
    /// [`CreditState`]). Отдельная карта от `streams`: та — про приём, эта —
    /// про то, сколько ещё можно отправить, не дожидаясь `Credit`-кадра.
    credits: Arc<DashMap<u32, Arc<CreditState>>>,
    /// Sticky-привязка потока к ноге (`stream_id` → `leg_id`).
    stream_bindings: Arc<DashMap<u32, u32>>,
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
}

impl Muxer {
    pub fn new(is_client: bool, session_id: String) -> Self {
        let muxer = Self {
            legs: Arc::new(DashMap::new()),
            active_legs_cache: Arc::new(ArcSwap::from_pointee(Vec::new())),
            streams: Arc::new(DashMap::new()),
            credits: Arc::new(DashMap::new()),
            stream_bindings: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            pending_pings: Arc::new(DashMap::new()),
            session_id: Arc::new(session_id),
            rr_counter: Arc::new(AtomicU32::new(0)),
            cumulative_tx: Arc::new(AtomicU64::new(0)),
            cumulative_rx: Arc::new(AtomicU64::new(0)),
            quota_user_id: Arc::new(ArcSwap::from_pointee(None)),
            quota_reported_bytes: Arc::new(AtomicU64::new(0)),
        };
        muxer.spawn_backlog_reaper();
        muxer
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
        for entry in self.legs.iter() {
            self.fold_removed_leg(entry.value());
        }
        self.legs.clear();
        self.stream_bindings.clear();
        self.update_legs_cache();
    }

    /// Число активных ног.
    pub fn active_legs_count(&self) -> usize {
        self.legs.len()
    }

    /// Выбирает ногу для отправки кадра потока `stream_id`.
    ///
    /// Двухуровнево: (1) горячий путь — привязанный поток резолвит ногу по id
    /// прямо из `legs` (без скана и клонирования кэша); (2) новый/осиротевший
    /// поток скорится по всем ногам (RTT доминирует, congestion лишь модулирует),
    /// из ног в пределах 2× от лучшего скора выбирается round-robin, и привязка
    /// фиксируется. Подробности скоринга — в inline-комментариях ниже.
    fn select_leg(&self, stream_id: u32) -> Option<MuxLeg> {
        // 1. FAST PATH (hot, per data frame): a bound stream resolves its leg by
        //    id straight from the legs map — no full-cache Arc clone and no vector
        //    scan. Reading `legs` (source of truth, not the cached snapshot) also
        //    transparently picks up a leg that reconnected under the same id.
        if let Some(leg_id_ref) = self.stream_bindings.get(&stream_id) {
            let leg_id = *leg_id_ref;
            if let Some(leg) = self.legs.get(&leg_id) {
                return Some(leg.clone());
            }
            // Bound leg disappeared — fall through and re-pick a fresh one below.
        }

        // 2. New (or re-homed) stream: load the leg set and choose.
        let legs = self.active_legs_cache.load_full();
        if legs.is_empty() {
            return None;
        }

        // 3. O(N) поиск лучшей леги без сортировки всего вектора.
        // Consider all available legs so the 4th leg is not permanently starved.
        // MUXER_POOL_SIZE is kept for topology printing but no longer limits
        // leg selection: sticky bindings already prevent hot-leg thrashing.
        // RTT-DOMINANT score: a leg's latency sets the scale, congestion only
        // modulates within legs of similar RTT. A drastically slower leg is never
        // preferred over a fast one, even when the fast leg is congested. (The old
        // additive `rtt + congestion*2000` could score a busy 160 ms leg WORSE
        // than an idle 1300 ms one, routing new streams onto the laggy leg.)
        let score = |leg: &MuxLeg| -> f64 {
            let rtt = (leg.stats.rtt_ms.load(Ordering::Relaxed) as f64).max(1.0);
            rtt * (1.0 + leg.congestion_factor())
        };

        let best = legs.iter().map(&score).fold(f64::MAX, f64::min);

        // Candidate set = every leg within 2× of the best score. Drastically
        // worse (slow / bufferbloated) legs are excluded; near-equal legs are all
        // eligible. We then ROUND-ROBIN across the candidates so a burst of new
        // streams (speedtest / multi-connection upload opening many sockets at
        // once, before congestion registers) spreads across legs instead of all
        // binding to the single current-best leg — which previously left one leg
        // saturated and the others idle (low aggregate upload + stop-start stalls).
        let candidates: Vec<&MuxLeg> = legs.iter().filter(|&l| score(l) <= best * 2.0).collect();

        let selected_leg = if candidates.is_empty() {
            None
        } else {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len();
            Some(candidates[idx].clone())
        };

        if let Some(leg) = selected_leg {
            self.stream_bindings.insert(stream_id, leg.id);
            return Some(leg);
        }

        None
    }

    /// Запоминает момент отправки PING по ноге (для замера RTT по PONG).
    pub fn record_ping_sent(&self, leg_id: u32) {
        self.pending_pings.insert(leg_id, Instant::now());
    }

    /// Обрабатывает PONG: считает RTT и обновляет сглаженную оценку (EWMA, α=0.25),
    /// затем пересчитывает глобальный минимум [`GLOBAL_MIN_RTT`] по всем ногам.
    pub async fn record_pong(&self, leg_id: u32) {
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
    pub async fn send_to_network(&self, mut message: MuxMessage) -> Result<(), AppError> {
        let is_data = matches!(message.frame_type, FrameType::Data | FrameType::UdpData);

        if is_data {
            // 🔥 ANTI-DOMINO FAILOVER.
            // A single leg dropping must NOT close the stream. We evict the dead
            // leg, unbind the stream, and retry on the next-best leg. Only when
            // *every* leg is gone do we return Err — and the bridge treats that
            // as "pause & buffer", not "close" (see run_tcp_bridge). The loop is
            // bounded: remove_leg drops the leg from the cache, so select_leg can
            // never hand back the same dead leg, and it terminates at None.
            loop {
                let leg = match self.select_leg(message.stream_id) {
                    Some(l) => l,
                    None => {
                        return Err(AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Нет связи",
                            "No active legs",
                        ))
                    }
                };

                let stream_id = message.stream_id;
                let size = message.data.len() as u64;

                // 💡 ДАННЫЕ: Используем .send().await для создания Backpressure
                match leg.data_tx.send(message).await {
                    Ok(_) => {
                        leg.stats.tx_bytes.fetch_add(size, Ordering::Relaxed);
                        if let Some(stream_ref) = self.streams.get(&stream_id) {
                            stream_ref
                                .value()
                                .stats
                                .tx_bytes
                                .fetch_add(size, Ordering::Relaxed);
                        }
                        return Ok(());
                    }
                    Err(send_err) => {
                        // Recover the payload from the failed send so the retry
                        // on another leg does not lose the chunk.
                        message = send_err.0;
                        DIAG_COUNTERS.upload_fails.fetch_add(1, Ordering::Relaxed);
                        diagnostics::send_diag_event(DiagnosticsEvent::UploadFailed {
                            stream_id,
                            reason: "data channel closed (leg dropped) — failing over".into(),
                        });
                        // Evict the dead leg (also unbinds its streams) so the
                        // next select_leg re-balances onto a healthy leg.
                        self.remove_leg(leg.id, &leg.control_tx);
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
                    ))
                }
            };

            let stream_id = message.stream_id;
            let size = message.data.len() as u64;
            // Close and Heartbeat frames MUST be delivered reliably (.send().await).
            // Close: dropping it leaks stream resources.
            // Heartbeat (PONG): dropping it via try_send causes the health-check
            // probe to time out after HEALTH_CHECK_TIMEOUT and evict a live leg.
            let is_critical = matches!(message.frame_type, FrameType::Close | FrameType::Heartbeat);

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
                        netrunner_logger::warn!(
                            stream_id,
                            "Control queue FULL! Dropping non-critical control frame."
                        );
                        DIAG_COUNTERS
                            .control_full_drops
                            .fetch_add(1, Ordering::Relaxed);
                        diagnostics::send_diag_event(DiagnosticsEvent::ControlChannelFull {
                            stream_id,
                            frame_type: format!("{:?}", dropped.frame_type),
                        });
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
        );

        self.streams.insert(
            stream_id,
            StreamSlot {
                tx,
                stats,
                token: token.clone(),
                backlog,
            },
        );
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
            }
        });
    }

    /// Удаляет поток, отменяя его токен (мгновенно гасит связанные задачи, включая
    /// бэклог-дренер) и снимая привязку к ноге.
    pub fn remove_stream(&self, stream_id: u32) {
        // 🔥 Мгновенно убиваем "зомби-задачи", привязанные к стриму!
        if let Some((_, slot)) = self.streams.remove(&stream_id) {
            slot.token.cancel();
        }
        self.stream_bindings.remove(&stream_id);
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

    /// Инициализирует кредитное окно потока: столько байт отправитель (эта
    /// сторона) может протолкнуть, не дожидаясь `Credit`-кадра от приёмника.
    /// Вызывает тот, кто НАЧИНАЕТ производить данные для потока (например,
    /// `RemoteOpener::open_tcp` перед запуском моста к цели).
    pub fn init_credit(&self, stream_id: u32, initial_bytes: u32) {
        self.credits.insert(
            stream_id,
            Arc::new(CreditState {
                available: std::sync::atomic::AtomicI64::new(initial_bytes as i64),
                notify: Notify::new(),
                last_grant_ms: AtomicU64::new(diagnostics::current_timestamp_ms()),
            }),
        );
    }

    /// Снимает кредитное окно потока. Вызывать при завершении отправки для
    /// этого потока (симметрично `remove_stream`, но для другой карты —
    /// `credits` живёт по циклу жизни ОТПРАВКИ, а не приёма).
    pub fn drop_credit(&self, stream_id: u32) {
        self.credits.remove(&stream_id);
    }

    /// Обрабатывает входящий `Credit`-кадр: пополняет окно и будит того, кто
    /// сейчас ждёт кредит в [`consume_credit`]. No-op, если для этого
    /// `stream_id` кредит не инициализирован (например, кадр пришёл уже после
    /// `drop_credit`, или писала сторона, которая credit вообще не считает).
    pub fn grant_credit(&self, stream_id: u32, bytes: u32) {
        if let Some(state) = self.credits.get(&stream_id) {
            let state = state.value();
            state.available.fetch_add(bytes as i64, Ordering::AcqRel);
            state
                .last_grant_ms
                .store(diagnostics::current_timestamp_ms(), Ordering::Relaxed);
            state.notify.notify_one();
        }
    }

    /// Ждёт, пока для потока не появится кредит, и забирает `min(available, want)`
    /// байт. Возвращает `want` без ожидания, если credit для этого потока не
    /// инициализирован (тот, кто вызвал, просто не участвует в этой схеме —
    /// поведение как до появления credit-контроля).
    ///
    /// Не блокирует НАВСЕГДА: если приёмник ни разу не прислал `Credit` дольше
    /// [`CREDIT_FALLBACK_AFTER`] С МОМЕНТА ПОСЛЕДНЕГО РЕАЛЬНОГО ГРАНТА (не
    /// понимает кадр, или сильно отстал), считаем credit-контроль неработающим
    /// для этого потока и откатываемся на неограниченную отправку — байтовый
    /// бюджет бэклога и его ридер остаются подстраховкой в любом случае.
    ///
    /// Дедлайн считается от `last_grant_ms`, а НЕ от момента входа в эту
    /// функцию: на высокой скорости `consume_credit` вызывается на каждый
    /// ~64 КБ чанк, и если бы каждый вызов заново отсчитывал полный
    /// `CREDIT_FALLBACK_AFTER`, окно, работающее штатно, но чуть отстающее от
    /// потребления, топило бы скачивание до пары кадров в 10 секунд — то есть
    /// сильнее, чем при полном отсутствии credit-контроля. Пока приёмник шлёт
    /// гранты хоть с какой-то регулярностью, ожидание прерывается по `notify`
    /// в течение примерно одного RTT, а не по этому дедлайну.
    pub async fn consume_credit(&self, stream_id: u32, want: usize) -> usize {
        let Some(state) = self.credits.get(&stream_id).map(|e| e.value().clone()) else {
            return want;
        };

        loop {
            let avail = state.available.load(Ordering::Acquire);
            if avail > 0 {
                let take = (avail as usize).min(want);
                state.available.fetch_sub(take as i64, Ordering::AcqRel);
                return take;
            }
            let since_last_grant = diagnostics::current_timestamp_ms()
                .saturating_sub(state.last_grant_ms.load(Ordering::Relaxed));
            if since_last_grant >= crate::net::CREDIT_FALLBACK_AFTER.as_millis() as u64 {
                trace!(
                    stream_id,
                    "consume_credit: no grant for {:?} — falling back to unrestricted",
                    crate::net::CREDIT_FALLBACK_AFTER
                );
                return want;
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
                let filled = cap.saturating_sub(free);
                let congestion_factor = if cap > 0 {
                    filled as f64 / cap as f64
                } else {
                    0.0
                };
                LegMetrics {
                    leg_id: leg.id,
                    rtt_ms: leg.stats.rtt_ms.load(Ordering::Relaxed),
                    tx_mb: leg.stats.tx_bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0,
                    rx_mb: leg.stats.rx_bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0,
                    congestion_factor,
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
