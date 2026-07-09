//! TCP-листенер сервера и приём входящих туннельных соединений.
//!
//! [`Network::run`] инициализирует глобальный конфиг и серверную диагностику,
//! создаёт **один** общий [`SessionManager`] (мультиплексирование: разные ноги
//! одной сессии цепляются к одному muxer), запускает фоновую задачу health-check
//! и печати топологии, после чего в цикле принимает соединения и на каждое
//! спавнит `ServerHandler::run` из ядра под отдельным tracing-span клиента.

use netrunner_core::net::{
    AuthValidator, Connection, NetworkConfig, ServerHandler, SessionManager, TunnelHandler,
    TOPOLOGY_PRINT_INTERVAL,
};
use netrunner_logger::{error, info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::diagnostics::{ClientDiagnosticsLogger, ServerDiagnosticsLogger};
use crate::health;

/// Сколько ждём при остановке, пока уже принятые соединения сами закроются,
/// прежде чем отпустить рантайм (который при Drop абортит все задачи разом,
/// без предупреждения клиентам).
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Параметры прослушивания сервера.
pub struct Network {
    host: String,
    port: u16,
    /// Домен-декой этой ноды для stealth-fallback (атрибут ноды — задаётся при
    /// старте через `--decoy-host`, раньше был захардкожен на `ubuntu.com`).
    decoy_host: Arc<str>,
    /// `None` — `--require-auth` не передан, авторизация и лимиты трафика
    /// выключены на этом инстансе целиком (поведение как до этой фичи).
    auth: Option<Arc<dyn AuthValidator>>,
    /// `None` — health-эндпоинт выключен (по умолчанию для обратной
    /// совместимости с уже развёрнутыми нодами без этого флага).
    health_port: Option<u16>,
}

impl Network {
    pub fn new(
        host: String,
        port: u16,
        decoy_host: impl Into<Arc<str>>,
        auth: Option<Arc<dyn AuthValidator>>,
        health_port: Option<u16>,
    ) -> Self {
        Self {
            host,
            port,
            decoy_host: decoy_host.into(),
            auth,
            health_port,
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
        let quota_auth = self.auth.clone();
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

                // Динамические лимиты трафика: только сессии с проверенным
                // владельцем (`--require-auth` включён и хендшейк прошёл
                // валидацию токена, см. `ServerHandler::run`). Бэкенд читает
                // текущий лимит из БД на каждый вызов — админ меняет его в
                // любой момент, следующий тик подхватит новое значение без
                // перезапуска прокси.
                if let Some(validator) = &quota_auth {
                    for entry in sm_clone.get_session().iter() {
                        let muxer = entry.value().clone();
                        let Some(user_id) = muxer.quota_user_id() else {
                            continue;
                        };
                        let delta = muxer.take_usage_delta();
                        if delta == 0 {
                            continue;
                        }
                        match validator.report_usage(&user_id, delta).await {
                            Ok(report) if report.over_limit => {
                                warn!(
                                    user_id,
                                    used = report.used_bytes,
                                    limit = ?report.limit_bytes,
                                    "🚫 Traffic limit exceeded, tearing down session"
                                );
                                muxer.remove_all_legs();
                                sm_clone.remove(muxer.session_id());
                            }
                            Ok(_) => {}
                            Err(e) => {
                                // Бэкенд недоступен/ошибка — не терять дельту
                                // навсегда, отчитаемся вместе со следующим тиком.
                                muxer.rollback_usage_delta(delta);
                                warn!(user_id, error = %e, "Usage report failed, will retry");
                            }
                        }
                    }
                }
            }
        });
        info!("🌐 Netrunner Server: Listening on {}", addr);
        let listener = TcpListener::bind(&addr).await.expect("Server bind failed");

        // Число реально обслуживаемых физических соединений прямо сейчас — не
        // "процесс жив", а "сколько клиентов на нём висит". Отдаётся в /health
        // и используется ниже, чтобы дождаться отключения клиентов при
        // остановке вместо мгновенного разрыва при drop рантайма.
        let active_connections = Arc::new(AtomicU64::new(0));

        if let Some(health_port) = self.health_port {
            let health_token = token.clone();
            let health_connections = active_connections.clone();
            tokio::spawn(health::run(
                "127.0.0.1".to_string(),
                health_port,
                health_connections,
                health_token,
            ));
        }

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
                            self.auth.clone(),
                        );

                        active_connections.fetch_add(1, Ordering::Relaxed);
                        let conn_counter = active_connections.clone();
                    tokio::spawn(async move {
                                // "Входим" в этот Span. Все логи внутри handler.run() привяжутся к этому IP.
                        let _enter = span.enter();

                        info!("🔌 New physical connection accepted");
                        if let Err(e) = handler.run().await {
                            error!(error = %e, "⚠️ Server handler terminated with error");
                        }
                        conn_counter.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                }
            }
        }

        // Graceful drain: приём новых соединений уже остановлен (цикл выше
        // прерван), но уже принятые клиенты продолжают жить как detached-задачи
        // рантайма. Без этого ожидания следующий за `run()` выход из
        // `rt.block_on` уронит рантайм и оборвёт их все разом без предупреждения.
        let drain_start = tokio::time::Instant::now();
        while active_connections.load(Ordering::Relaxed) > 0 {
            if drain_start.elapsed() > SHUTDOWN_DRAIN_TIMEOUT {
                warn!(
                    remaining = active_connections.load(Ordering::Relaxed),
                    "Drain timeout истёк, принудительно завершаем оставшиеся соединения"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        info!("✅ Drain завершён, соединений осталось: {}", active_connections.load(Ordering::Relaxed));
    }
}
