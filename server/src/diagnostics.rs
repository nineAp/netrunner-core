//! Серверный логгер диагностики: события ядра → JSONL-файл.
//!
//! Подписывается на канал диагностики ([`diagnostics::init_diagnostics`]) и
//! пишет снапшоты в `netrunner_diagnostics.jsonl` (по одной JSON-строке на
//! событие) с ротацией файла по размеру. Дополнительно пишет стартовый и
//! периодические heartbeat-снапшоты, чтобы файл всегда существовал и было видно,
//! что сервер жив. У сервера нет smoltcp-движка, поэтому socket-метрики пусты —
//! только метрики туннеля, но они реальные: логгер держит [`SessionManager`] и
//! на каждый снапшот опрашивает `Muxer` всех живых сессий (см.
//! [`ServerDiagnosticsLogger::snapshot_all_sessions`]).

use netrunner_core::net::diagnostics::{
    self, DiagnosticsEvent, DiagnosticsSnapshot, DiagnosticsStore, TunnelMetrics,
    current_timestamp_ms,
};
use netrunner_core::net::SessionManager;
use netrunner_logger::{error, info, warn};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    time::{interval, Duration},
};

/// Max bytes of a session id used when building a client-diagnostics filename.
/// Generated ids are 32 hex chars; the cap just bounds a hostile/oversized id.
const CLIENT_DIAG_SESSION_ID_MAX: usize = 64;

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
    /// Общий реестр сессий сервера — источник правды для реальных метрик
    /// туннеля (раньше их не было вовсе, снапшот всегда сообщал пустоту).
    session_manager: Arc<SessionManager>,
}

impl ServerDiagnosticsLogger {
    pub fn new(log_dir: impl Into<PathBuf>, session_manager: Arc<SessionManager>) -> Self {
        let mut path = log_dir.into();
        path.push("netrunner_diagnostics.jsonl");
        Self {
            store: Arc::new(DiagnosticsStore::new(SERVER_MAX_SNAPSHOTS)),
            log_path: path,
            session_manager,
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
            let startup = logger
                .build_server_snapshot(DiagnosticsEvent::Heartbeat)
                .await;
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
                        let snap = logger
                            .build_server_snapshot(DiagnosticsEvent::Heartbeat)
                            .await;
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
    /// socket metrics are omitted; tunnel metrics are real, aggregated across
    /// every currently connected client session.
    async fn build_server_snapshot(&self, trigger: DiagnosticsEvent) -> DiagnosticsSnapshot {
        DiagnosticsSnapshot {
            timestamp_ms: current_timestamp_ms(),
            trigger,
            engine: None,
            tunnel: self.snapshot_all_sessions(),
            sockets: vec![],
            error_totals: diagnostics::DIAG_COUNTERS.snapshot(),
        }
    }

    /// Опрашивает `Muxer` каждой живой сессии и сводит их в одну [`TunnelMetrics`]:
    /// ноги всех сессий (каждая помечена своим `session_id` — иначе `leg_id`
    /// разных клиентов совпадали бы, они нумеруются независимо 0..MAX_TUNNEL_LEGS)
    /// и сумма потоков. `global_min_rtt_ms` остаётся процесс-глобальным значением
    /// ([`GLOBAL_MIN_RTT`](netrunner_core::net::GLOBAL_MIN_RTT)) — это отдельное,
    /// более глубокое ограничение (RTT не разведён по сессиям нигде в ядре), не
    /// то же самое, что пустая заглушка активных ног/потоков, которую эта функция
    /// заменяет.
    fn snapshot_all_sessions(&self) -> TunnelMetrics {
        let sessions: Vec<_> = self
            .session_manager
            .get_session()
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        let mut active_legs = Vec::new();
        let mut total_streams = 0;
        for muxer in &sessions {
            let m = muxer.snapshot_tunnel_metrics();
            total_streams += m.total_streams;
            active_legs.extend(m.active_legs);
        }

        TunnelMetrics {
            global_min_rtt_ms: netrunner_core::net::GLOBAL_MIN_RTT
                .load(std::sync::atomic::Ordering::Relaxed),
            active_legs,
            total_streams,
            session_count: sessions.len(),
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

/// Логгер клиентской диагностики, доставленной по туннелю.
///
/// Подписывается на сток [`diagnostics::init_client_diag_sink`] и для каждого
/// пришедшего отчёта дописывает его JSON-строку в пер-сессионный JSONL-файл
/// `netrunner_client_diag_<session_id>.jsonl`. Так снапшоты ядра клиента, которые
/// раньше копились вхолостую в памяти приложения, оседают на сервере рядом с его
/// собственной диагностикой, разложенные по сессиям.
pub struct ClientDiagnosticsLogger {
    log_dir: PathBuf,
}

impl ClientDiagnosticsLogger {
    pub fn new(log_dir: impl Into<PathBuf>) -> Self {
        Self {
            log_dir: log_dir.into(),
        }
    }

    /// Очищает `session_id` для безопасного использования в имени файла: оставляет
    /// только `[A-Za-z0-9._-]` и ограничивает длину. Защита от path-traversal —
    /// `session_id` приходит из клиентского auth-payload и не доверенный.
    fn sanitize_session_id(session_id: &str) -> String {
        let cleaned: String = session_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(CLIENT_DIAG_SESSION_ID_MAX)
            .collect();
        if cleaned.is_empty() {
            "unknown".to_string()
        } else {
            cleaned
        }
    }

    /// Запускает фоновую задачу: читает отчёты из стока и пишет их по сессиям.
    /// Завершается, когда сток закрыт (все отправители ушли).
    pub fn start(self: Arc<Self>) {
        let mut rx = diagnostics::init_client_diag_sink();
        tokio::spawn(async move {
            info!(
                "Client diagnostics logger started → {}/netrunner_client_diag_<session>.jsonl",
                self.log_dir.display()
            );
            while let Some(report) = rx.recv().await {
                self.append_report(&report.session_id, &report.json_line)
                    .await;
            }
            warn!("Client diagnostics sink closed; logger task stopping");
        });
    }

    /// Дописывает одну JSON-строку в файл сессии (создавая его при необходимости).
    async fn append_report(&self, session_id: &str, json_line: &str) {
        let safe_id = Self::sanitize_session_id(session_id);
        let mut path = self.log_dir.clone();
        path.push(format!("netrunner_client_diag_{}.jsonl", safe_id));

        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await;

        match result {
            Ok(mut file) => {
                let _ = file.write_all(json_line.as_bytes()).await;
                let _ = file.write_all(b"\n").await;
            }
            Err(e) => error!(
                "Cannot open client diagnostics log {}: {}",
                path.display(),
                e
            ),
        }
    }
}
