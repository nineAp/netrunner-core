use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant as StdInstant;

pub static GLOBAL_RX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_RX_PACKETS: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TX_PACKETS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_speed_mb_s: f64,
    pub tx_speed_mb_s: f64,
}

/// Per-session traffic counter with rolling speed estimate.
pub struct TrafficCounter {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,

    last_speed_calc: StdInstant,
    last_rx_bytes: u64,
    last_tx_bytes: u64,
    cached_rx_speed: f64,
    cached_tx_speed: f64,
}

impl TrafficCounter {
    pub fn new() -> Self {
        let now = StdInstant::now();
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_speed_calc: now,
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            cached_rx_speed: 0.0,
            cached_tx_speed: 0.0,
        }
    }

    pub fn record_rx(&mut self, bytes: usize) {
        self.rx_bytes += bytes as u64;
        self.rx_packets += 1;
        GLOBAL_RX_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        GLOBAL_RX_PACKETS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_bytes += bytes as u64;
        self.tx_packets += 1;
        GLOBAL_TX_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        GLOBAL_TX_PACKETS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&mut self) -> TrafficStats {
        let now = StdInstant::now();
        let elapsed = now.duration_since(self.last_speed_calc).as_secs_f64();

        if elapsed >= 1.0 {
            let rx_diff = self.rx_bytes.saturating_sub(self.last_rx_bytes);
            let tx_diff = self.tx_bytes.saturating_sub(self.last_tx_bytes);
            self.cached_rx_speed = (rx_diff as f64 / 1_048_576.0) / elapsed;
            self.cached_tx_speed = (tx_diff as f64 / 1_048_576.0) / elapsed;
            self.last_rx_bytes = self.rx_bytes;
            self.last_tx_bytes = self.tx_bytes;
            self.last_speed_calc = now;
        }

        TrafficStats {
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
            rx_packets: self.rx_packets,
            tx_packets: self.tx_packets,
            rx_speed_mb_s: self.cached_rx_speed,
            tx_speed_mb_s: self.cached_tx_speed,
        }
    }
}
