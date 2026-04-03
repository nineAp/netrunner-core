use bytes::Bytes;
use dashmap::DashMap;
use netrunner_logger::{debug, info, warn};
use tokio::sync::mpsc::error::TrySendError;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

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

pub struct MuxMessage {
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub data: Bytes,
}

#[derive(Clone)]
pub struct Muxer {
    legs: Arc<DashMap<u32, MuxLeg>>,
    streams: Arc<DashMap<u32, (Sender<Bytes>, Arc<StreamStats>)>>,
    id_gen: Arc<IdGenerator>,
    session_id: Arc<String>,
}

impl Muxer {
    
    pub fn new(is_client: bool, session_id: String) -> Self {
        Self {
            legs: Arc::new(DashMap::new()),
            streams: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            session_id: Arc::new(session_id),
        }
    }

    pub fn add_leg(
        &self,
        leg_id: u32,
        control_tx: Sender<MuxMessage>,
        data_tx: Sender<MuxMessage>,
    ) {
        
        if self.legs.len() >= 10 {
            warn!(
                leg_id,
                "MUXER: Maximum of 10 legs reached. Ignoring new leg."
            );
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
        info!(leg_id, "MUXER: Leg registered (Total: {})", self.legs.len());
    }

    pub fn remove_leg(&self, leg_id: u32) {
        self.legs.remove(&leg_id);
        info!(leg_id, "MUXER: Leg removed");
    }

    pub fn active_legs_count(&self) -> usize {
        self.legs.len()
    }

  fn select_leg(&self, frame_type: &FrameType, stream_id: u32) -> Option<(u32, MuxLeg)> {
        if self.legs.is_empty() {
            return None;
        }

        let is_udp = matches!(frame_type, FrameType::UdpData | FrameType::UdpConnect);

        
        let mut candidates: Vec<(u32, MuxLeg)> = self.legs
            .iter()
            .map(|kv| (*kv.key(), kv.value().clone()))
            .filter(|(id, _)| {
                
                if is_udp { id % 2 != 0 } else { id % 2 == 0 }
            })
            .collect();

        
        if candidates.is_empty() {
            candidates = self.legs.iter().map(|kv| (*kv.key(), kv.value().clone())).collect();
        }

        
        
        
        candidates.sort_by_key(|(_, leg)| {
            let rtt = leg.stats.rtt_ms.load(Ordering::Relaxed);
            if rtt == 0 { 9999 } else { rtt }
        });

        
        
        let pool_size = std::cmp::min(candidates.len(), 2);
        let target = &candidates[stream_id as usize % pool_size];

        Some(target.clone())
    }

    
    pub fn send_to_network(&self, message: MuxMessage) -> Result<(), String> {
        let stream_id = message.stream_id;
        let size = message.data.len() as u64;

        
        let (leg_id, leg) = self
            .select_leg(&message.frame_type, stream_id)
            .ok_or_else(|| "MUXER: No active legs available".to_string())?;

        let target_tx = match message.frame_type {
            FrameType::Connect
            | FrameType::Close
            | FrameType::UdpConnect
            | FrameType::Handshake => &leg.control_tx,
            _ => &leg.data_tx,
        };

        match target_tx.try_send(message) {
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
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                
                warn!(
                    leg_id,
                    "MUXER: Network queue full! Dropping outbound packet."
                );
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.remove_leg(leg_id);
                Err(format!("MUXER: Leg {} died during send", leg_id))
            }
        }
    }

    pub fn send_data_safe(
        &self,
        stream_id: u32,
        data: Bytes, // Больше не mut
        is_udp: bool,
    ) -> Result<(), String> {
        let frame_type = if is_udp {
            FrameType::UdpData
        } else {
            FrameType::Data
        };

        // Отправляем как есть, целиком!
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type,
            data,
        })
    }

    pub fn send_control(
        &self,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), String> {
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type: f_type,
            data,
        })
    }

    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) {
        self.streams
            .insert(stream_id, (tx, Arc::new(StreamStats::default())));
    }

    pub fn remove_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

pub fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
    
    let stream_opt = self
        .streams
        .get(&stream_id)
        .map(|s| (s.0.clone(), s.1.clone()));

    if let Some((tx, stats)) = stream_opt {
        let size = data.len() as u64;

        
        match tx.try_send(data) {
            Ok(_) => {
                stats.rx_bytes.fetch_add(size, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                netrunner_logger::warn!(
                    stream_id, 
                    "Muxer -> Local: Buffer full, dropping packet. Check your bridge/TUN speed."
                );
            }
            Err(TrySendError::Closed(_)) => {
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
        
        let legs: Vec<(u32, Sender<MuxMessage>)> = self.legs.iter()
            .map(|k| (*k.key(), k.value().control_tx.clone()))
            .collect();

        for (leg_id, tx) in legs {
            let probe_stream_id = self.id_gen.next();
            let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel(2);
            
            
            self.register_stream(probe_stream_id, probe_tx);

            let msg = MuxMessage {
                stream_id: probe_stream_id,
                frame_type: FrameType::Handshake,
                data: Bytes::from("PING"),
            };

            let start = std::time::Instant::now();
            
            
            if tx.try_send(msg).is_ok() {
                
                match tokio::time::timeout(std::time::Duration::from_secs(2), probe_rx.recv()).await {
                    Ok(Some(_)) => {
                        let rtt = start.elapsed().as_millis() as u32;
                        if let Some(leg) = self.legs.get(&leg_id) {
                            leg.stats.rtt_ms.store(rtt, Ordering::Relaxed);
                            debug!(leg_id, rtt, "✅ Leg Health Check OK");
                        }
                    }
                    _ => {
                        
                        if let Some(leg) = self.legs.get(&leg_id) {
                            leg.stats.rtt_ms.store(5000, Ordering::Relaxed);
                            warn!(leg_id, "❌ Leg Health Check Timeout (marked as slow)");
                        }
                    }
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
        println!(
            "\n🌐 Netrunner Tunnel Topology [Session: {}]",
            self.session_id
        );

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

            let leg_type = if id % 2 == 0 { "TCP" } else { "UDP" };
            let rtt_str = if rtt == 0 {
                "N/A".to_string()
            } else {
                format!("{}ms", rtt)
            };

            legs_info.push(format!(
                "   ├─ Leg {} ({}) ─ ⇡ {:<9} | ⇣ {:<9} [RTT: {}]",
                id,
                leg_type,
                Self::format_size(tx),
                Self::format_size(rx),
                rtt_str
            ));
        }

        println!(
            "├─ 📊 Global Traffic: ⇡ {} | ⇣ {}",
            Self::format_size(total_tx),
            Self::format_size(total_rx)
        );

        println!("├─ 🦵 Physical Legs (Active: {})", legs_info.len());
        for (i, info) in legs_info.iter().enumerate() {
            if i == legs_info.len() - 1 {
                println!("{}", info.replace("├─", "└─"));
            } else {
                println!("{}", info);
            }
        }

        let streams_count = self.streams.len();
        println!("└─ 🔀 Virtual Streams (Active: {})", streams_count);

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

            println!(
                "{} Stream {:<4} ─ ⇡ {:<9} | ⇣ {}",
                prefix,
                id,
                Self::format_size(tx),
                Self::format_size(rx)
            );
        }
        println!();
    }
}
