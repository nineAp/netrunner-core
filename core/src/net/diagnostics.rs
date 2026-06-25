use std::{
    collections::VecDeque,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::sync::mpsc;

// ── Public event channel ──────────────────────────────────────────────────────

/// Global sender end of the diagnostics event channel.
/// Initialised once by `init_diagnostics()`; all producers call `send_diag_event()`.
static GLOBAL_DIAG_TX: OnceLock<DiagnosisTx> = OnceLock::new();

pub type DiagnosisTx = mpsc::UnboundedSender<DiagnosticsEvent>;
pub type DiagnosisRx = mpsc::UnboundedReceiver<DiagnosticsEvent>;

/// Call once at startup (from EngineBuilder on the client, from Network::run on
/// the server).  Returns the receiver end that the consumer task/engine must hold.
pub fn init_diagnostics() -> DiagnosisRx {
    let (tx, rx) = mpsc::unbounded_channel();
    // Ignore the error if called twice (server may re-init across tests).
    let _ = GLOBAL_DIAG_TX.set(tx);
    rx
}

/// Fire-and-forget: enqueue a diagnostics event from anywhere in the codebase.
/// Does nothing if `init_diagnostics()` has not been called yet.
pub fn send_diag_event(event: DiagnosticsEvent) {
    if let Some(tx) = GLOBAL_DIAG_TX.get() {
        let _ = tx.send(event);
    }
}

// ── Event types ───────────────────────────────────────────────────────────────

/// What triggered this diagnostics snapshot.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiagnosticsEvent {
    UploadFailed {
        stream_id: u32,
        reason: String,
    },
    DownloadBackpressure {
        stream_id: u32,
        /// How many background retry tasks are in flight for this stream.
        queued_tasks: usize,
    },
    LegDisconnected {
        leg_id: u32,
        rtt_ms: u32,
        reason: String,
    },
    LegReconnecting {
        leg_id: u32,
        attempt: u32,
    },
    StreamClosedWithError {
        stream_id: u32,
        up_bytes: u64,
        down_bytes: u64,
        error: String,
    },
    ControlChannelFull {
        stream_id: u32,
        frame_type: String,
    },
    TunnelWriteStuck {
        leg_id: u32,
        stream_id: u32,
    },
}

// ── Per-snapshot sub-structs (all Serialize) ──────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct EngineMetrics {
    pub rx_total_mb: f64,
    pub tx_total_mb: f64,
    pub rx_speed_mb_s: f64,
    pub tx_speed_mb_s: f64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Current depth of the smoltcp ChannelDevice RX queue (packets).
    pub device_rx_queue_depth: usize,
    /// Current depth of the smoltcp ChannelDevice TX queue (packets).
    pub device_tx_queue_depth: usize,
    /// Free slots in the engine→TUN writer channel.
    pub tun_tx_channel_free: usize,
    /// Free slots in the TUN reader→engine channel.
    pub tun_rx_channel_free: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LegMetrics {
    pub leg_id: u32,
    pub rtt_ms: u32,
    pub tx_mb: f64,
    pub rx_mb: f64,
    /// 0.0 = idle, 1.0 = data channel completely full.
    pub congestion_factor: f64,
    pub data_channel_free: usize,
    pub data_channel_capacity: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelMetrics {
    pub global_min_rtt_ms: u32,
    pub active_legs: Vec<LegMetrics>,
    pub total_streams: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketMetrics {
    pub stream_id: u32,
    pub state: String,
    pub send_queue_bytes: usize,
    pub send_capacity_bytes: usize,
    pub recv_queue_bytes: usize,
    pub recv_capacity_bytes: usize,
    /// Bytes held in the single pending_chunk (partial write to smoltcp TX buf).
    pub pending_chunk_bytes: usize,
    /// Whether the upload path is currently blocked by smoltcp backpressure.
    pub tx_congested: bool,
    pub total_up_bytes: u64,
    pub total_down_bytes: u64,
}

/// Cumulative error/event counters at the moment of the snapshot.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ErrorCounters {
    pub upload_fails: u64,
    pub download_backpressure_events: u64,
    pub leg_disconnects: u64,
    pub control_channel_full_drops: u64,
    pub tunnel_write_stalls: u64,
    pub stream_errors: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsSnapshot {
    pub timestamp_ms: u64,
    pub trigger: DiagnosticsEvent,
    /// Engine-side metrics (traffic, device queue depths, channel free space).
    /// Present only on the client; `None` on server snapshots.
    pub engine: Option<EngineMetrics>,
    pub tunnel: TunnelMetrics,
    /// Per-socket smoltcp state.  Present only on the client engine.
    pub sockets: Vec<SocketMetrics>,
    /// Running totals of all error/event counters up to this snapshot.
    pub error_totals: ErrorCounters,
}

// ── Atomic error counters (global, updated at event sites) ───────────────────

pub struct DiagnosticsCounters {
    pub upload_fails: AtomicU64,
    pub download_backpressure: AtomicU64,
    pub leg_disconnects: AtomicU64,
    pub control_full_drops: AtomicU64,
    pub tunnel_write_stalls: AtomicU64,
    pub stream_errors: AtomicU64,
}

impl DiagnosticsCounters {
    const fn new() -> Self {
        Self {
            upload_fails: AtomicU64::new(0),
            download_backpressure: AtomicU64::new(0),
            leg_disconnects: AtomicU64::new(0),
            control_full_drops: AtomicU64::new(0),
            tunnel_write_stalls: AtomicU64::new(0),
            stream_errors: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> ErrorCounters {
        ErrorCounters {
            upload_fails: self.upload_fails.load(Ordering::Relaxed),
            download_backpressure_events: self.download_backpressure.load(Ordering::Relaxed),
            leg_disconnects: self.leg_disconnects.load(Ordering::Relaxed),
            control_channel_full_drops: self.control_full_drops.load(Ordering::Relaxed),
            tunnel_write_stalls: self.tunnel_write_stalls.load(Ordering::Relaxed),
            stream_errors: self.stream_errors.load(Ordering::Relaxed),
        }
    }
}

/// Process-global counters incremented at every event site.
pub static DIAG_COUNTERS: DiagnosticsCounters = DiagnosticsCounters::new();

// ── DiagnosticsStore — holds the last N snapshots ─────────────────────────────

pub struct DiagnosticsStore {
    snapshots: Mutex<VecDeque<DiagnosticsSnapshot>>,
    max_snapshots: usize,
}

impl DiagnosticsStore {
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            snapshots: Mutex::new(VecDeque::new()),
            max_snapshots,
        }
    }

    pub fn push(&self, snap: DiagnosticsSnapshot) {
        let mut q = self.snapshots.lock().unwrap();
        if q.len() >= self.max_snapshots {
            q.pop_front();
        }
        q.push_back(snap);
    }

    /// Returns all stored snapshots as a pretty-printed JSON array.
    pub fn get_all_json(&self) -> String {
        let q = self.snapshots.lock().unwrap();
        let items: Vec<&DiagnosticsSnapshot> = q.iter().collect();
        serde_json::to_string_pretty(&items)
            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Returns only the most recent snapshot as pretty-printed JSON, or `"null"`.
    pub fn get_latest_json(&self) -> String {
        let q = self.snapshots.lock().unwrap();
        match q.back() {
            Some(s) => serde_json::to_string_pretty(s)
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")) ,
            None => "null".to_string(),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
