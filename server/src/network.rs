//! TCP-листенер сервера и приём входящих туннельных соединений.
//!
//! [`Network::run`] инициализирует глобальный конфиг и серверную диагностику,
//! создаёт **один** общий [`SessionManager`] (мультиплексирование: разные ноги
//! одной сессии цепляются к одному muxer), запускает фоновую задачу health-check
//! и печати топологии, после чего в цикле принимает соединения и на каждое
//! спавнит `ServerHandler::run` из ядра под отдельным tracing-span клиента.

use netrunner_core::net::{
    Connection, NetworkConfig, ServerHandler, SessionManager, TunnelHandler,
    TOPOLOGY_PRINT_INTERVAL,
};
use netrunner_logger::{error, info};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::diagnostics::{ClientDiagnosticsLogger, ServerDiagnosticsLogger};

/// Параметры прослушивания сервера.
pub struct Network {
    host: String,
    port: u16,
    /// Домен-декой этой ноды для stealth-fallback (атрибут ноды — задаётся при
    /// старте через `--decoy-host`, раньше был захардкожен на `ubuntu.com`).
    decoy_host: Arc<str>,
}

impl Network {
    pub fn new(host: String, port: u16, decoy_host: impl Into<Arc<str>>) -> Self {
        Self {
            host,
            port,
            decoy_host: decoy_host.into(),
        }
    }

    /// Запускает сервер: слушает TCP и обслуживает соединения до отмены `token`.
    pub async fn run(&self, token: CancellationToken) {
        let addr = format!("{}:{}", self.host, self.port);

        NetworkConfig::init_global(1450);

        // 🔥 CRITICAL FIX: Create ONE global session manager for multiplexing
        let session_manager = Arc::new(SessionManager::new());

        // Start diagnostics logger — writes events to ./netrunner_diagnostics.jsonl.
        // Shares the session manager so snapshots report real per-session tunnel
        // state (active legs, streams) instead of an always-empty placeholder.
        Arc::new(ServerDiagnosticsLogger::new(".", session_manager.clone())).start();

        // Start client-diagnostics logger — saves snapshots shipped by clients
        // over the tunnel into ./netrunner_client_diag_<session>.jsonl
        Arc::new(ClientDiagnosticsLogger::new(".")).start();

        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;

                let mut active_muxers = Vec::new();
                for entry in sm_clone.get_session().iter() {
                    active_muxers.push(entry.value().clone());
                }
                for muxer in active_muxers {
                    if muxer.active_legs_count() > 0 {
                        let m = muxer.clone();
                        tokio::spawn(async move {
                            m.perform_health_check().await;
                        });
                    }
                }

                sm_clone.print_all_sessions();
            }
        });
        info!("🌐 Netrunner Server: Listening on {}", addr);
        let listener = TcpListener::bind(&addr).await.expect("Server bind failed");

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("🛑 Shutdown signal received, stopping server.");
                    break;
                }
                res = listener.accept() => {
                    if let Ok((stream, client_addr)) = res {
                        let span = tracing::info_span!("client_conn", ip = %client_addr);

                        let conn = Connection::new(stream);

                        // Pass the Arc clone down to the ServerHandler
                        let handler = ServerHandler::new(
                            conn,
                            session_manager.clone(),
                            self.decoy_host.clone(),
                        );

                    tokio::spawn(async move {
                                // "Входим" в этот Span. Все логи внутри handler.run() привяжутся к этому IP.
                        let _enter = span.enter();

                        info!("🔌 New physical connection accepted");
                        if let Err(e) = handler.run().await {
                            error!(error = %e, "⚠️ Server handler terminated with error");
                        }
                        });
                    }
                }
            }
        }
    }
}
