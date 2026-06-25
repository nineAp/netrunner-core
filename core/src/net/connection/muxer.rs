use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{info, instrument, trace, warn, AppError, ERR_INFRA_TIMEOUT};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use crate::net::{INITIAL_RTT_MS, MUXER_CONGESTION_WEIGHT};
use crate::net::{HEALTH_CHECK_TIMEOUT, MAX_TUNNEL_LEGS, MUXER_POOL_SIZE};
use crate::net::diagnostics::{self, DiagnosticsEvent, DIAG_COUNTERS, LegMetrics, TunnelMetrics};
use crate::nrxp::FrameType;

#[derive(Default, Debug)]
pub struct LegStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rtt_ms: AtomicU32,
}

#[derive(Default, Debug)]
pub struct StreamStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

#[derive(Clone)]
struct MuxLeg {
    id: u32,
    control_tx: Sender<MuxMessage>,
    data_tx: Sender<MuxMessage>,
    stats: Arc<LegStats>,
}

impl MuxLeg {
    fn congestion_factor(&self) -> f64 {
        let max = self.data_tx.max_capacity();
        let current_capacity = self.data_tx.capacity();
        let filled = max.saturating_sub(current_capacity);
        (filled as f64) / (max as f64)
    }
}

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

#[derive(Clone)]
pub struct MuxMessage {
    pub(crate) stream_id: u32,
    pub(crate) frame_type: FrameType,
    pub(crate) data: Bytes,
}

pub static GLOBAL_MIN_RTT: AtomicU32 = AtomicU32::new(INITIAL_RTT_MS);

#[derive(Clone)]
pub struct Muxer {
    legs: Arc<DashMap<u32, MuxLeg>>,
    // 🔥 ОПТИМИЗАЦИЯ: Lock-Free кэш для горячего пути
    active_legs_cache: Arc<RwLock<Arc<Vec<MuxLeg>>>>,

    // Добавили CancellationToken для предотвращения утечек памяти (Зомби-задач)
    streams: Arc<DashMap<u32, (Sender<Bytes>, Arc<StreamStats>, CancellationToken)>>,
    stream_bindings: Arc<DashMap<u32, u32>>,
    pending_pings: Arc<DashMap<u32, Instant>>,
    id_gen: Arc<IdGenerator>,
    session_id: Arc<String>,
}

impl Muxer {
    pub fn new(is_client: bool, session_id: String) -> Self {
        Self {
            legs: Arc::new(DashMap::new()),
            active_legs_cache: Arc::new(RwLock::new(Arc::new(Vec::new()))),
            streams: Arc::new(DashMap::new()),
            stream_bindings: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            pending_pings: Arc::new(DashMap::new()),
            session_id: Arc::new(session_id),
        }
    }

    fn update_legs_cache(&self) {
        let new_cache: Vec<MuxLeg> = self.legs.iter().map(|kv| kv.value().clone()).collect();
        *self.active_legs_cache.write().unwrap() = Arc::new(new_cache);
    }

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

    pub fn remove_leg(&self, leg_id: u32, tx: &Sender<MuxMessage>) {
        let should_remove = self
            .legs
            .get(&leg_id)
            .map_or(false, |leg| leg.control_tx.same_channel(tx));
        if should_remove {
            self.legs.remove(&leg_id);
            self.update_legs_cache();
            info!(
                leg_id,
                "MUXER: TCP leg removed safely, streams will re-balance"
            );
        }
    }

    pub fn force_remove_leg(&self, leg_id: u32) {
        if self.legs.remove(&leg_id).is_some() {
            self.update_legs_cache();
            info!(leg_id, "MUXER: TCP leg force-removed on engine exit");
        }
    }

    pub fn remove_all_legs(&self) {
        self.legs.clear();
        self.stream_bindings.clear();
        self.update_legs_cache();
    }

    pub fn active_legs_count(&self) -> usize {
        self.legs.len()
    }

    fn select_leg(&self, stream_id: u32) -> Option<MuxLeg> {
        // 1. Читаем кэш (это Arc, поэтому clone здесь — это просто инкремент счетчика, не копирование данных)
        let legs = self.active_legs_cache.read().unwrap().clone();
        if legs.is_empty() {
            return None;
        }

        // 2. Если поток уже привязан к леге, используем её (Sticky Connection)
        if let Some(leg_id_ref) = self.stream_bindings.get(&stream_id) {
            let leg_id = *leg_id_ref;
            if let Some(leg) = legs.iter().find(|l| l.id == leg_id) {
                return Some(leg.clone());
            }
        }

        // 3. O(N) поиск лучшей леги без сортировки всего вектора
        // Мы берем подмножество (pool) и сразу ищем в нем минимум
        let pool_size = std::cmp::min(legs.len(), MUXER_POOL_SIZE);

        // Используем min_by, чтобы найти лучший вариант за один проход
        let selected_leg = legs
            .iter()
            .take(pool_size) // Берем только пул
            .min_by(|a, b| {
                let score_a = a.stats.rtt_ms.load(Ordering::Relaxed) as f64
                    + (a.congestion_factor() * MUXER_CONGESTION_WEIGHT);
                let score_b = b.stats.rtt_ms.load(Ordering::Relaxed) as f64
                    + (b.congestion_factor() * MUXER_CONGESTION_WEIGHT);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned();

        if let Some(leg) = selected_leg {
            self.stream_bindings.insert(stream_id, leg.id);
            return Some(leg);
        }

        None
    }

    pub fn record_ping_sent(&self, leg_id: u32) {
        self.pending_pings.insert(leg_id, Instant::now());
    }

    pub async fn record_pong(&self, leg_id: u32) {
        if let Some((_, start_time)) = self.pending_pings.remove(&leg_id) {
            let rtt = start_time.elapsed().as_millis() as u32;
            if let Some(leg) = self.legs.get(&leg_id) {
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

    #[instrument(skip(self, message), fields(session_id = %self.session_id, stream_id = message.stream_id, frame = ?message.frame_type))]
    pub async fn send_to_network(&self, message: MuxMessage) -> Result<(), AppError> {
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

        let is_data = matches!(message.frame_type, FrameType::Data | FrameType::UdpData);
        let stream_id = message.stream_id;
        let size = message.data.len() as u64;

        if is_data {
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
                    Ok(())
                }
                Err(_) => {
                    DIAG_COUNTERS.upload_fails.fetch_add(1, Ordering::Relaxed);
                    diagnostics::send_diag_event(DiagnosticsEvent::UploadFailed {
                        stream_id,
                        reason: "data channel closed (leg dropped)".into(),
                    });
                    self.remove_leg(leg.id, &leg.control_tx);
                    Err(AppError::new(ERR_INFRA_TIMEOUT, "Обрыв", "Leg closed"))
                }
            }
        } else {
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
                            stream_ref.value().1.tx_bytes.fetch_add(size, Ordering::Relaxed);
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
                            stream_ref.value().1.tx_bytes.fetch_add(size, Ordering::Relaxed);
                        }
                        Ok(())
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(ref dropped)) => {
                        netrunner_logger::warn!(
                            stream_id,
                            "Control queue FULL! Dropping non-critical control frame."
                        );
                        DIAG_COUNTERS.control_full_drops.fetch_add(1, Ordering::Relaxed);
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

    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) -> CancellationToken {
        let token = CancellationToken::new();
        self.streams.insert(
            stream_id,
            (tx, Arc::new(StreamStats::default()), token.clone()),
        );
        token
    }

    pub fn remove_stream(&self, stream_id: u32) {
        // 🔥 Мгновенно убиваем "зомби-задачи", привязанные к стриму!
        if let Some((_, (_, _, token))) = self.streams.remove(&stream_id) {
            token.cancel();
        }
        self.stream_bindings.remove(&stream_id);
    }

    // ORDERING CONTRACT: callers MUST .await this; the caller (TunnelEngine reader)
    // is a spawned task, so blocking here creates correct back-pressure all the way
    // back to the kernel TCP socket buffer.  Never spawn a task to deliver data
    // from this function — that breaks in-order delivery guarantees.
    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        let size = data.len() as u64;

        let tx_and_stats = self.streams.get(&stream_id).map(|s| {
            let val = s.value();
            (val.0.clone(), val.1.clone())
        });

        if let Some((tx, stats)) = tx_and_stats {
            // .send().await blocks until the receiver has space.
            // If the receiver is closed the error is silently ignored.
            if tx.send(data).await.is_ok() {
                stats.rx_bytes.fetch_add(size, Ordering::Relaxed);
            }
        }
    }

    pub fn record_leg_rx(&self, leg_id: u32, bytes: u64) {
        if let Some(leg) = self.legs.get(&leg_id) {
            leg.stats.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn next_stream_id(&self) -> u32 {
        self.id_gen.next()
    }

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
                    warn!(leg_id, "Health check: control channel closed, evicting dead leg");
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

    pub fn print_topology_tree(&self) {
        let mut out = String::new();
        out.push_str(&format!(
            "🌐 Netrunner Tunnel Topology [Session: {}]\n",
            self.session_id
        ));

        let mut total_tx = 0;
        let mut total_rx = 0;
        let mut legs_info = Vec::new();

        let cached_legs = self.active_legs_cache.read().unwrap().clone();
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
        info!("\n{}", out);
    }

    /// Collect a point-in-time snapshot of tunnel metrics for diagnostics.
    /// Lock-free: reads only atomics and the RwLock-protected legs cache.
    pub fn snapshot_tunnel_metrics(&self) -> TunnelMetrics {
        let global_min_rtt = crate::net::GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        let cached_legs = self.active_legs_cache.read().unwrap().clone();

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
