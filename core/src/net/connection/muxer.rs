use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{AppError, ERR_INFRA_TIMEOUT, info, instrument, trace, warn};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::Sender;

use crate::net::{HEALTH_CHECK_TIMEOUT, MAX_TUNNEL_LEGS, MUXER_POOL_SIZE};
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
    control_tx: Sender<MuxMessage>,
    data_tx: Sender<MuxMessage>,
    stats: Arc<LegStats>,
}

impl MuxLeg {
    fn congestion_factor(&self) -> f64 {
        0.0
    }
}

struct IdGenerator {
    counter: AtomicU32,
}

impl IdGenerator {
    pub fn new(is_client: bool) -> Self {
        let start = if is_client { 1 } else { 2 };
        Self {
            counter: AtomicU32::new(start),
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

pub static GLOBAL_MIN_RTT: AtomicU32 = AtomicU32::new(250);

#[derive(Clone)]
pub struct Muxer {
    legs: Arc<DashMap<u32, MuxLeg>>,
    streams: Arc<DashMap<u32, (Sender<Bytes>, Arc<StreamStats>)>>,
    stream_bindings: Arc<DashMap<u32, u32>>,
    pending_pings: Arc<DashMap<u32, Instant>>,
    id_gen: Arc<IdGenerator>,
    session_id: Arc<String>,
}

impl Muxer {
    pub fn new(is_client: bool, session_id: String) -> Self {
        Self {
            legs: Arc::new(DashMap::new()),
            streams: Arc::new(DashMap::new()),
            stream_bindings: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            pending_pings: Arc::new(DashMap::new()),
            session_id: Arc::new(session_id),
        }
    }

    pub fn add_leg(
        &self,
        leg_id: u32,
        control_tx: Sender<MuxMessage>,
        data_tx: Sender<MuxMessage>,
    ) {
        if self.legs.len() >= MAX_TUNNEL_LEGS as usize && !self.legs.contains_key(&leg_id) {
            warn!(leg_id, "MUXER: Max legs reached: {}", MAX_TUNNEL_LEGS);
            return;
        }

        self.legs.insert(
            leg_id,
            MuxLeg {
                control_tx,
                data_tx,
                stats: Arc::new(LegStats::default()),
            },
        );
        info!(
            leg_id,
            "MUXER: Physical TCP+TLS leg registered (Total: {})",
            self.legs.len()
        );
    }

    pub fn remove_leg(&self, leg_id: u32, tx: &Sender<MuxMessage>) {
        let should_remove = if let Some(leg) = self.legs.get(&leg_id) {
            leg.control_tx.same_channel(tx)
        } else {
            false
        };

        if should_remove {
            self.legs.remove(&leg_id);
            info!(
                leg_id,
                "MUXER: TCP leg removed safely, streams will re-balance"
            );
        } else {
            trace!(
                leg_id,
                "MUXER: Leg removal skipped (already removed or replaced by a new connection)"
            );
        }
    }

    pub fn remove_all_legs(&self) {
        warn!("🚨 MUXER: Emergency reset! Removing all physical legs due to network change.");
        self.legs.clear();
        self.stream_bindings.clear();
    }

    pub fn active_legs_count(&self) -> usize {
        self.legs.len()
    }

    fn select_leg(&self, _frame_type: &FrameType, stream_id: u32) -> Option<(u32, MuxLeg)> {
        if self.legs.is_empty() {
            return None;
        }

        if let Some(leg_id_ref) = self.stream_bindings.get(&stream_id) {
            let leg_id = *leg_id_ref;
            if let Some(leg) = self.legs.get(&leg_id) {
                return Some((leg_id, leg.clone()));
            }
        }

        let mut candidates: Vec<(u32, MuxLeg)> = self
            .legs
            .iter()
            .map(|kv| (*kv.key(), kv.value().clone()))
            .collect();

        candidates.sort_by(|(_, leg_a), (_, leg_b)| {
            let rtt_a = leg_a.stats.rtt_ms.load(Ordering::Relaxed) as f64;
            let rtt_b = leg_b.stats.rtt_ms.load(Ordering::Relaxed) as f64;
            let score_a = rtt_a + (leg_a.congestion_factor() * 2000.0);
            let score_b = rtt_b + (leg_b.congestion_factor() * 2000.0);

            score_a
                .partial_cmp(&score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let pool_size = std::cmp::min(candidates.len(), MUXER_POOL_SIZE);
        let (selected_id, selected_leg) = candidates[stream_id as usize % pool_size].clone();

        self.stream_bindings.insert(stream_id, selected_id);

        Some((selected_id, selected_leg))
    }

    pub fn record_ping_sent(&self, leg_id: u32) {
        self.pending_pings.insert(leg_id, Instant::now());
    }

    pub async fn record_pong(&self, leg_id: u32) {
        if let Some((_, start_time)) = self.pending_pings.remove(&leg_id) {
            let rtt = start_time.elapsed().as_millis() as u32;
            if let Some(leg) = self.legs.get(&leg_id) {
                leg.stats.rtt_ms.store(rtt, Ordering::Relaxed);
                trace!(leg_id, rtt, "💓 [Muxer] RTT updated for physical leg");

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

    #[instrument(skip(self, message), fields(
    session_id = %self.session_id, 
    stream_id = message.stream_id,
    frame = ?message.frame_type
    ))]
    pub async fn send_to_network(&self, message: MuxMessage) -> Result<(), AppError>{
        let size = message.data.len() as u64;
        let mut attempts = 0;

        loop {
            if attempts >= 3 {
                return Err(AppError::new(ERR_INFRA_TIMEOUT, "Сбой передачи данных", "MUXER: All attempts to send failed"));
            }
            attempts += 1;

            let (leg_id, leg) = match self.select_leg(&message.frame_type, message.stream_id) {
                Some(l) => l,
                None => return Err(AppError::new(ERR_INFRA_TIMEOUT, "Нет связи с сервером", "MUXER: No active physical legs available")),
            };

            let target_tx = match message.frame_type {
                FrameType::Connect
                | FrameType::Close
                | FrameType::UdpConnect
                | FrameType::Heartbeat => &leg.control_tx,
                _ => &leg.data_tx,
            };

            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                target_tx.send(message.clone()),
            )
            .await
            {
                Ok(Ok(_)) => {
                    leg.stats.tx_bytes.fetch_add(size, Ordering::Relaxed);
                    if let Some(stream_ref) = self.streams.get(&message.stream_id) {
                        stream_ref
                            .value()
                            .1
                            .tx_bytes
                            .fetch_add(size, Ordering::Relaxed);
                    }
                    return Ok(());
                }
                Ok(Err(_)) => {
                    self.remove_leg(leg_id, &leg.control_tx);
                    continue;
                }
                Err(_) => {
                    warn!(
                        message.stream_id,
                        "Physical TCP TX full for 10s! Leg {} is dead. Evicting.", leg_id
                    );
                    self.remove_leg(leg_id, &leg.control_tx);
                    continue;
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
        let frame_type = if is_udp {
            FrameType::UdpData
        } else {
            FrameType::Data
        };
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type,
            data,
        })
        .await
    }

    pub(crate) async fn send_control(
        &self,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), AppError>{
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type: f_type,
            data,
        })
        .await
    }

    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) {
        self.streams
            .insert(stream_id, (tx, Arc::new(StreamStats::default())));
    }

    pub fn remove_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
        self.stream_bindings.remove(&stream_id);
    }

    #[instrument(skip(self, data), fields(session_id = %self.session_id, stream_id = stream_id))]
    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        let stream_opt = self
            .streams
            .get(&stream_id)
            .map(|s| (s.value().0.clone(), s.value().1.clone()));

        if let Some((tx, stats)) = stream_opt {
            let size = data.len() as u64;

            // 🔥 КЛЮЧЕВОЙ ФИКС: Используем .send().await
            // Мы больше не выбрасываем пакеты! Мы ждем, пока освободится очередь.
            // Это создает естественный TCP Backpressure на стороне сервера.
            match tx.send(data).await {
                Ok(_) => {
                    stats.rx_bytes.fetch_add(size, Ordering::Relaxed);
                }
                Err(_) => {
                    // Канал закрыт (клиент отвалился)
                    self.remove_stream(stream_id);
                }
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
            let Some(leg) = self.legs.get(&leg_id) else {
                continue;
            };
            let tx = leg.control_tx.clone();

            let probe_stream_id = self.id_gen.next();
            let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel(10);
            self.register_stream(probe_stream_id, probe_tx);

            self.record_ping_sent(leg_id);

            let msg = MuxMessage {
                stream_id: probe_stream_id,
                frame_type: FrameType::Heartbeat,
                data: Bytes::from("PING"),
            };

            if tx.try_send(msg).is_err() {
                warn!(leg_id, "❌ MUXER: Leg channel overflow/blocked, evicting");
                self.remove_leg(leg_id, &tx);
                self.remove_stream(probe_stream_id);
                continue;
            }

            match tokio::time::timeout(crate::net::HEALTH_CHECK_TIMEOUT, probe_rx.recv()).await {
                Ok(Some(_)) => {
                    trace!(leg_id, "✅ TCP Leg Health Check OK");
                }
                _ => {
                    warn!(leg_id, "❌ TCP Leg Health Check FAIL/Timeout - Evicting");
                    self.remove_leg(leg_id, &tx);
                }
            }
            self.remove_stream(probe_stream_id);
        }
    }

    fn format_size(bytes: u64) -> String {
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

        for kv in self.legs.iter() {
            let id = kv.key();
            let stats = &kv.value().stats;
            let tx = stats.tx_bytes.load(Ordering::Relaxed);
            let rx = stats.rx_bytes.load(Ordering::Relaxed);
            let rtt = stats.rtt_ms.load(Ordering::Relaxed);

            total_tx += tx;
            total_rx += rx;

            let rtt_str = if rtt == 0 {
                "N/A".to_string()
            } else {
                format!("{}ms", rtt)
            };

            legs_info.push(format!(
                "   ├─ Leg {} (TCP+TLS) ─ ⇡ {:<9} | ⇣ {:<9} [RTT: {}]",
                id,
                Self::format_size(tx),
                Self::format_size(rx),
                rtt_str
            ));
        }

        out.push_str(&format!(
            "├─ 📊 Global Traffic: ⇡ {} | ⇣ {}\n",
            Self::format_size(total_tx),
            Self::format_size(total_rx)
        ));
        out.push_str(&format!(
            "├─ 🦵 Physical Connections (Active: {})\n",
            legs_info.len()
        ));

        for (i, info) in legs_info.iter().enumerate() {
            if i == legs_info.len() - 1 {
                out.push_str(&format!("{}\n", info.replace("├─", "└─")));
            } else {
                out.push_str(&format!("{}\n", info));
            }
        }

        let streams_count = self.streams.len();
        out.push_str(&format!(
            "└─ 🔀 Virtual Streams (TCP/UDP multiplexed: {})\n",
            streams_count
        ));

        let mut count = 0;
        for kv in self.streams.iter() {
            count += 1;
            let id = kv.key();
            let stats = &kv.value().1;

            let tx = stats.tx_bytes.load(Ordering::Relaxed);
            let rx = stats.rx_bytes.load(Ordering::Relaxed);

            let prefix = if count == streams_count {
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
}
