//! Серверный логгер диагностики: события ядра → JSONL-файл.
//!
//! Подписывается на канал диагностики ([`diagnostics::init_diagnostics`]) и
//! пишет снапшоты в `netrunner_diagnostics.jsonl` (по одной JSON-строке на
//! событие) с ротацией файла по размеру. Дополнительно пишет стартовый и
//! периодические heartbeat-снапшоты, чтобы файл всегда существовал и было видно,
//! что сервер жив. У сервера нет smoltcp-движка, поэтому socket-метрики пусты —
//! только метрики туннеля.

use netrunner_core::net::diagnostics::{
    self, DiagnosticsEvent, DiagnosticsSnapshot, DiagnosticsStore, TunnelMetrics,
    current_timestamp_ms,
};
use netrunner_logger::{error, info, warn};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    time::{interval, Duration},
};

/// Maximum number of snapshots kept in the in-memory store on the server.
const SERVER_MAX_SNAPSHOTS: usize = 100;
/// Rotate the log file when it exceeds this many bytes (~10 MB).
const LOG_ROTATE_THRESHOLD: u64 = 10 * 1024 * 1024;
/// Write a periodic heartbeat snapshot every N seconds even without error events.
const HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// Логгер серверной диагностики: in-memory store последних снапшотов + файл.
pub struct ServerDiagnosticsLogger {
    store: Arc<DiagnosticsStore>,
    log_path: PathBuf,
}

impl ServerDiagnosticsLogger {
    pub fn new(log_dir: impl Into<PathBuf>) -> Self {
        let mut path = log_dir.into();
        path.push("netrunner_diagnostics.jsonl");
        Self {
            store: Arc::new(DiagnosticsStore::new(SERVER_MAX_SNAPSHOTS)),
            log_path: path,
        }
    }

    /// Start the background task that:
    /// 1. Writes an immediate startup snapshot (so the log file is always created).
    /// 2. Writes a periodic heartbeat snapshot every HEARTBEAT_INTERVAL_SECS.
    /// 3. Writes a snapshot on every error/diagnostic event.
    pub fn start(self: Arc<Self>) {
        let mut diag_rx = diagnostics::init_diagnostics();
        let logger = self.clone();

        tokio::spawn(async move {
            info!(
                "Server diagnostics logger started → {}",
                logger.log_path.display()
            );

            // Write an immediate startup snapshot so the file is created on boot.
            let startup = logger.build_server_snapshot(DiagnosticsEvent::LegReconnecting {
                leg_id: 0,
                attempt: 0,
            }).await;
            logger.store.push(startup.clone());
            logger.append_to_file(&startup).await;

            let mut heartbeat = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            heartbeat.tick().await; // consume the immediate first tick

            loop {
                tokio::select! {
                    event = diag_rx.recv() => {
                        match event {
                            Some(e) => {
                                let snap = logger.build_server_snapshot(e).await;
                                logger.store.push(snap.clone());
                                logger.append_to_file(&snap).await;
                            }
                            None => break,
                        }
                    }
                    _ = heartbeat.tick() => {
                        // Periodic heartbeat — lets operators confirm the server is
                        // alive even when everything is working perfectly.
                        let snap = logger.build_server_snapshot(DiagnosticsEvent::LegReconnecting {
                            leg_id: 0,
                            attempt: 0,
                        }).await;
                        logger.store.push(snap.clone());
                        logger.append_to_file(&snap).await;
                    }
                }
            }
        });
    }

    /// Returns all stored snapshots as a JSON array string.
    pub fn get_all_json(&self) -> String {
        self.store.get_all_json()
    }

    /// Builds a server-side snapshot.  The server has no smoltcp engine, so
    /// socket metrics are omitted; only tunnel metrics are included.
    async fn build_server_snapshot(&self, trigger: DiagnosticsEvent) -> DiagnosticsSnapshot {
        DiagnosticsSnapshot {
            timestamp_ms: current_timestamp_ms(),
            trigger,
            engine: None,
            // Tunnel metrics can be added later if the server gains access to
            // a specific Muxer.  For now we report an empty structure.
            tunnel: TunnelMetrics {
                global_min_rtt_ms: netrunner_core::net::GLOBAL_MIN_RTT
                    .load(std::sync::atomic::Ordering::Relaxed),
                active_legs: vec![],
                total_streams: 0,
            },
            sockets: vec![],
            error_totals: diagnostics::DIAG_COUNTERS.snapshot(),
        }
    }

    /// Appends one JSON line to the log file, rotating if the file is too large.
    async fn append_to_file(&self, snap: &DiagnosticsSnapshot) {
        if let Err(e) = self.try_rotate().await {
            warn!("Diagnostics log rotation failed: {}", e);
        }

        let line = match serde_json::to_string(snap) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize diagnostics snapshot: {}", e);
                return;
            }
        };

        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await;

        match result {
            Ok(mut file) => {
                let _ = file.write_all(line.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
            Err(e) => error!("Cannot open diagnostics log: {}", e),
        }
    }

    /// If the log file exceeds LOG_ROTATE_THRESHOLD, rename it to `.1` and
    /// start a fresh file.
    async fn try_rotate(&self) -> std::io::Result<()> {
        match tokio::fs::metadata(&self.log_path).await {
            Ok(meta) if meta.len() >= LOG_ROTATE_THRESHOLD => {
                let mut rotated = self.log_path.clone();
                rotated.set_extension("jsonl.1");
                tokio::fs::rename(&self.log_path, &rotated).await?;
                info!(
                    "Diagnostics log rotated → {}",
                    rotated.display()
                );
            }
            _ => {}
        }
        Ok(())
    }
}
