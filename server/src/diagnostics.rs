//! Серверный логгер диагностики: события ядра → ограниченный in-memory store.
//!
//! Подписывается на канал диагностики ([`diagnostics::init_diagnostics`]) и
//! хранит последние [`SERVER_MAX_SNAPSHOTS`] снапшотов в памяти (никакого
//! файла на диске ноды — см. `Logger::init` в `netrunner-logger` за тем же
//! решением для основного лога: локальный файл на проде уже дважды приводил
//! к забитому диску). Дополнительно пишет стартовый и периодические
//! heartbeat-снапшоты, чтобы было видно, что сервер жив. У сервера нет
//! smoltcp-движка, поэтому socket-метрики пусты — только метрики туннеля, но
//! они реальные: логгер держит [`SessionManager`] и на каждый снапшот
//! опрашивает `Muxer` всех живых сессий (см.
//! [`ServerDiagnosticsLogger::snapshot_all_sessions`]).

use netrunner_core::net::diagnostics::{
    self, current_timestamp_ms, DiagnosticsEvent, DiagnosticsSnapshot, DiagnosticsStore,
    TunnelMetrics,
};
use netrunner_core::net::SessionManager;
use netrunner_logger::{info, warn};
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Maximum number of snapshots kept in the in-memory store on the server.
const SERVER_MAX_SNAPSHOTS: usize = 100;
/// Write a periodic heartbeat snapshot every N seconds even without error events.
const HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// Логгер серверной диагностики: только ограниченный in-memory store, без
/// файла на диске.
pub struct ServerDiagnosticsLogger {
    store: Arc<DiagnosticsStore>,
    /// Общий реестр сессий сервера — источник правды для реальных метрик
    /// туннеля (раньше их не было вовсе, снапшот всегда сообщал пустоту).
    session_manager: Arc<SessionManager>,
}

impl ServerDiagnosticsLogger {
    pub fn new(session_manager: Arc<SessionManager>) -> Self {
        Self {
            store: Arc::new(DiagnosticsStore::new(SERVER_MAX_SNAPSHOTS)),
            session_manager,
        }
    }

    /// Start the background task that:
    /// 1. Builds an immediate startup snapshot (in-memory store only).
    /// 2. Builds a periodic heartbeat snapshot every HEARTBEAT_INTERVAL_SECS.
    /// 3. Builds a snapshot on every error/diagnostic event.
    pub fn start(self: Arc<Self>) {
        let mut diag_rx = diagnostics::init_diagnostics();
        let logger = self.clone();

        tokio::spawn(async move {
            info!("Server diagnostics logger started (in-memory only, no disk file)");

            // Immediate startup snapshot in the bounded in-memory store — no
            // disk write (see doc comment above: local files on the node are
            // exactly the pattern that caused prior disk-full incidents).
            let startup = logger
                .build_server_snapshot(DiagnosticsEvent::Heartbeat)
                .await;
            logger.store.push(startup);

            let mut heartbeat = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            heartbeat.tick().await; // consume the immediate first tick

            loop {
                tokio::select! {
                    event = diag_rx.recv() => {
                        match event {
                            Some(e) => {
                                let snap = logger.build_server_snapshot(e).await;
                                logger.store.push(snap);
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
                        logger.store.push(snap);
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
}

/// Дренирует сток клиентской диагностики (`FrameType::Diag`, произвольный
/// JSON, который решает отправлять сам клиент).
///
/// Раньше каждый отчёт дописывался в свой файл на диске ноды
/// (`netrunner_client_diag_<session_id>.jsonl`, без ограничения по числу
/// файлов) — то же самое "дебаг-решение", что и общий JSON-лог: локальный
/// диск ноды не должен копить содержимое клиентской диагностики. Прокси
/// собирает только то, что нужно для поддержания тоннеля (агрегированные
/// метрики — см. [`ServerDiagnosticsLogger`]); произвольные клиентские
/// самоотчёты просто дренируются и отбрасываются — сток `unbounded`, и без
/// читателя он копился бы в памяти неограниченно.
pub struct ClientDiagnosticsLogger;

impl ClientDiagnosticsLogger {
    pub fn new() -> Self {
        Self
    }

    /// Запускает фоновую задачу-дренаж. Завершается, когда сток закрыт (все
    /// отправители ушли).
    pub fn start(self: Arc<Self>) {
        let mut rx = diagnostics::init_client_diag_sink();
        tokio::spawn(async move {
            info!("Client diagnostics drain task started (не сохраняется, только дренаж стока)");
            while rx.recv().await.is_some() {
                // Осознанно отбрасываем: см. doc-комментарий на структуре.
            }
            warn!("Client diagnostics sink closed; drain task stopping");
        });
    }
}

impl Default for ClientDiagnosticsLogger {
    fn default() -> Self {
        Self::new()
    }
}
