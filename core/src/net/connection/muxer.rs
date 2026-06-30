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
//!   `try_send` (`dispatch_to_local`), чтобы один медленный потребитель не
//!   блокировал общий reader ноги (head-of-line).
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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use crate::net::diagnostics::{self, DiagnosticsEvent, LegMetrics, TunnelMetrics, DIAG_COUNTERS};
use crate::net::{DISPATCH_TO_LOCAL_TIMEOUT, MAX_TUNNEL_LEGS};
use crate::net::INITIAL_RTT_MS;
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

    /// Реестр потоков: id → (канал доставки данных, статистика, токен отмены).
    /// Токен мгновенно убивает связанные с потоком задачи при `remove_stream`.
    streams: Arc<DashMap<u32, (Sender<Bytes>, Arc<StreamStats>, CancellationToken)>>,
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
}

impl Muxer {
    pub fn new(is_client: bool, session_id: String) -> Self {
        Self {
            legs: Arc::new(DashMap::new()),
            active_legs_cache: Arc::new(ArcSwap::from_pointee(Vec::new())),
            streams: Arc::new(DashMap::new()),
            stream_bindings: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            pending_pings: Arc::new(DashMap::new()),
            session_id: Arc::new(session_id),
            rr_counter: Arc::new(AtomicU32::new(0)),
        }
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
        self.stream_bindings.retain(|_, bound_leg| *bound_leg != leg_id);
    }

    /// Безопасно эвиктит ногу, но только если её текущий `control_tx` совпадает с
    /// `tx` (защита от удаления ноги, уже переподключённой под тем же id). Сначала
    /// снимает привязки, потом обновляет кэш — чтобы конкурентный `select_leg` не
    /// привязался к эвиктируемой ноге.
    pub fn remove_leg(&self, leg_id: u32, tx: &Sender<MuxMessage>) {
        let should_remove = self
            .legs
            .get(&leg_id)
            .map_or(false, |leg| leg.control_tx.same_channel(tx));
        if should_remove {
            self.legs.remove(&leg_id);
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
        if self.legs.remove(&leg_id).is_some() {
            self.clear_bindings_for_leg(leg_id);
            self.update_legs_cache();
            info!(leg_id, "MUXER: TCP leg force-removed on engine exit");
        }
    }

    /// Сбрасывает все ноги и привязки (полная остановка туннеля).
    pub fn remove_all_legs(&self) {
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

        let best = legs.iter().map(|l| score(l)).fold(f64::MAX, f64::min);

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
            let idx =
                self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len();
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
                                .1
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
                                .1
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
                                .1
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

    /// Регистрирует поток и возвращает его [`CancellationToken`]. Канал `tx`
    /// используется для доставки входящих данных потоку (`dispatch_to_local`).
    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) -> CancellationToken {
        let token = CancellationToken::new();
        self.streams.insert(
            stream_id,
            (tx, Arc::new(StreamStats::default()), token.clone()),
        );
        token
    }

    /// Удаляет поток, отменяя его токен (мгновенно гасит связанные задачи) и
    /// снимая привязку к ноге.
    pub fn remove_stream(&self, stream_id: u32) {
        // 🔥 Мгновенно убиваем "зомби-задачи", привязанные к стриму!
        if let Some((_, (_, _, token))) = self.streams.remove(&stream_id) {
            token.cancel();
        }
        self.stream_bindings.remove(&stream_id);
    }

    // ORDERING CONTRACT: in-order delivery — never spawn a task to deliver data
    // from this function.
    //
    // HEAD-OF-LINE GUARD: the hot path is a non-blocking try_send, so one slow or
    // dead stream can NEVER block the shared per-leg reader. (A finished speedtest
    // socket the app stopped reading used to back its channel up and freeze EVERY
    // other download on that leg, because the reader awaited here for up to 10 s.)
    // Only a genuinely-full channel gets a SHORT grace wait (DISPATCH_TO_LOCAL_
    // TIMEOUT); if it is still full that ONE stream is closed so the leg keeps
    // serving everyone else.
    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        let size = data.len() as u64;

        let tx_and_stats = self.streams.get(&stream_id).map(|s| {
            let val = s.value();
            (val.0.clone(), val.1.clone())
        });

        let Some((tx, stats)) = tx_and_stats else {
            // No stream registered for this id (already closed / never opened).
            DIAG_COUNTERS
                .mux_dispatch_no_stream
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        // Fast path: deliver without awaiting → zero head-of-line blocking.
        let data = match tx.try_send(data) {
            Ok(()) => {
                stats.rx_bytes.fetch_add(size, Ordering::Relaxed);
                DIAG_COUNTERS.mux_dispatch_ok.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Receiver already closed — stream gone.
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                DIAG_COUNTERS
                    .mux_dispatch_recv_closed
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Channel full: recover the payload and fall through to a bounded wait.
            Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => data,
        };

        match tokio::time::timeout(DISPATCH_TO_LOCAL_TIMEOUT, tx.send(data)).await {
            Ok(Ok(_)) => {
                stats.rx_bytes.fetch_add(size, Ordering::Relaxed);
                DIAG_COUNTERS.mux_dispatch_ok.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(_)) => {
                DIAG_COUNTERS
                    .mux_dispatch_recv_closed
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                // Consumer stayed full past the grace window: close just this one
                // stream so the leg keeps serving everyone else.
                DIAG_COUNTERS
                    .mux_dispatch_full_closed
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    stream_id,
                    "dispatch_to_local: stream stalled for {:?}, closing", DISPATCH_TO_LOCAL_TIMEOUT
                );
                self.remove_stream(stream_id);
            }
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
                        .map_or(false, |l| l.control_tx.same_channel(&tx));
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

        let mut total_tx = 0;
        let mut total_rx = 0;
        let mut legs_info = Vec::new();

        let cached_legs = self.active_legs_cache.load_full();
        for leg in cached_legs.iter() {
            let tx = leg.stats.tx_bytes.load(Ordering::Relaxed);
            let rx = leg.stats.rx_bytes.load(Ordering::Relaxed);
            let rtt = leg.stats.rtt_ms.load(Ordering::Relaxed);
            total_tx += tx;
            total_rx += rx;

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
                    kv.value().1.tx_bytes.load(Ordering::Relaxed),
                    kv.value().1.rx_bytes.load(Ordering::Relaxed),
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
                }
            })
            .collect();

        TunnelMetrics {
            global_min_rtt_ms: global_min_rtt,
            active_legs,
            total_streams: self.streams.len(),
        }
    }
}
