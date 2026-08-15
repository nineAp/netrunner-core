//! TCP-листенер сервера и приём входящих туннельных соединений.
//!
//! [`Network::run`] инициализирует глобальный конфиг и серверную диагностику,
//! создаёт **один** общий [`SessionManager`] (мультиплексирование: разные ноги
//! одной сессии цепляются к одному muxer), запускает фоновую задачу health-check
//! и печати топологии, после чего в цикле принимает соединения и на каждое
//! спавнит `ServerHandler::run` из ядра под отдельным tracing-span клиента.

use netrunner_core::net::{
    AuthValidator, Connection, NetworkConfig, NodeHealthReport, ServerHandler, SessionManager,
    TunnelHandler, TOPOLOGY_PRINT_INTERVAL,
};
use netrunner_core::Identity;
use netrunner_logger::{debug, error, info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// Локальный, ничего не значащий вне этого процесса счётчик соединений —
/// только для корреляции строк одного и того же соединения в логе, не
/// идентификатор клиента (см. `Network::run`).
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(0);

/// Момент старта процесса — для `uptime_secs` в `NodeHealthReport`.
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Unix-время (сек) последнего успешного прохода периодического таска
/// (health-check ног + отчёты). `/health` считает ноду нездоровой, если этот
/// таск не отмечался дольше пары интервалов — defense-in-depth: именно этот
/// таск дважды виновато зависал (см. фиксы `.enter()`-через-`.await` и
/// DashMap-итератора через `.await`), и раньше зависание одной корутины
/// внутри него было невидимо снаружи (health-эндпоинт — отдельная задача,
/// продолжал отвечать "ok", пока сам процесс не зависал целиком).
static LAST_PERIODIC_TICK_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Публичная, доступная из `health.rs` проверка: не завис ли периодический
/// таск. `true` — нода жива с точки зрения этого сигнала.
pub(crate) fn periodic_task_is_healthy() -> bool {
    let last = LAST_PERIODIC_TICK_UNIX_SECS.load(Ordering::Relaxed);
    if last == 0 {
        // Ещё ни разу не отметился — либо только что стартовали (в пределах
        // первого интервала это нормально), либо таск не запущен вовсе.
        return START_TIME
            .get()
            .map(|t| t.elapsed() < TOPOLOGY_PRINT_INTERVAL * 3)
            .unwrap_or(true);
    }
    now_unix_secs().saturating_sub(last) < (TOPOLOGY_PRINT_INTERVAL * 3).as_secs()
}

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
    /// Долговременные учётные данные ноды (`PROXY_NRXP_SECRET` +
    /// `PROXY_NRXP_PRIVATE_KEY`), заведённые в админке бэкенда. `None` — не
    /// настроены, нода принимает только старый анонимный хендшейк.
    identity: Option<Identity>,
}

impl Network {
    pub fn new(
        host: String,
        port: u16,
        decoy_host: impl Into<Arc<str>>,
        auth: Option<Arc<dyn AuthValidator>>,
        health_port: Option<u16>,
        identity: Option<Identity>,
    ) -> Self {
        Self {
            host,
            port,
            decoy_host: decoy_host.into(),
            auth,
            health_port,
            identity,
        }
    }

    /// Запускает сервер: слушает TCP и обслуживает соединения до отмены `token`.
    pub async fn run(&self, token: CancellationToken) {
        let addr = format!("{}:{}", self.host, self.port);
        START_TIME.get_or_init(Instant::now);

        NetworkConfig::init_global(1450);

        // 🔥 CRITICAL FIX: Create ONE global session manager for multiplexing
        let session_manager = Arc::new(SessionManager::new());

        // Диагностика — только ограниченный in-memory store, без файлов на
        // диске ноды (см. diagnostics.rs). Делит SessionManager, чтобы снапшоты
        // отражали реальное состояние тоннеля (активные ноги/потоки), а не
        // всегда-пустую заглушку.
        Arc::new(ServerDiagnosticsLogger::new(session_manager.clone())).start();

        // Дренирует произвольную клиентскую само-диагностику — не сохраняется
        // нигде (см. doc-комментарий на ClientDiagnosticsLogger).
        Arc::new(ClientDiagnosticsLogger::new()).start();

        let sm_clone = session_manager.clone();
        let quota_auth = self.auth.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                LAST_PERIODIC_TICK_UNIX_SECS.store(now_unix_secs(), Ordering::Relaxed);

                let mut active_muxers = Vec::new();
                for entry in sm_clone.get_session().iter() {
                    active_muxers.push(entry.value().clone());
                }
                // Заимствуем, а не потребляем `active_muxers` — он ещё нужен
                // ниже, для отчёта об использовании трафика.
                for muxer in &active_muxers {
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
                //
                // Переиспользуем уже собранный `active_muxers` (owned Vec, см.
                // выше), а не свежий `sm_clone.get_session().iter()` — тот
                // держит shard-лок DashMap на всё тело цикла, включая этот
                // `.await` к бэкенду. Реальный инцидент: вторая нога той же
                // сессии регистрируется через `SessionManager::get_or_create`,
                // которому нужен write-лок НА ТОТ ЖЕ шард — блокировалась,
                // пока тут не освобождался read-лок, и хвостом вешался весь
                // тред (в т.ч. этот же периодический таск, который потом сам
                // не мог провернуть следующий тик).
                if let Some(validator) = &quota_auth {
                    for muxer in &active_muxers {
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

                // Единая точка сбора состояния ноды — вместо локальных файлов
                // на диске (см. `Logger::init`/diagnostics.rs). Полностью
                // анонимный агрегат: ни IP, ни хостов назначения, ни user_id.
                if let Some(validator) = &quota_auth {
                    let mut active_legs = 0usize;
                    let mut total_streams = 0usize;
                    let mut bytes_up_total_mb = 0.0;
                    let mut bytes_down_total_mb = 0.0;
                    for muxer in &active_muxers {
                        let m = muxer.snapshot_tunnel_metrics();
                        total_streams += m.total_streams;
                        active_legs += m.active_legs.len();
                        for leg in &m.active_legs {
                            bytes_up_total_mb += leg.tx_mb;
                            bytes_down_total_mb += leg.rx_mb;
                        }
                    }

                    let report = NodeHealthReport {
                        active_sessions: active_muxers.len(),
                        active_legs,
                        active_streams: total_streams,
                        bytes_up_total_mb,
                        bytes_down_total_mb,
                        error_totals: netrunner_core::net::diagnostics::DIAG_COUNTERS.snapshot(),
                        uptime_secs: START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0),
                    };
                    if let Err(e) = validator.report_node_health(report).await {
                        debug!(error = %e, "Node health report failed, will retry next tick");
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
                    if let Ok((stream, _client_addr)) = res {
                        // Приватность: НЕ привязываем IP клиента к спану — раньше
                        // `ip = %client_addr` попадал в КАЖДУЮ последующую лог-строку
                        // этого соединения (span-поля наследуются), деанонимизируя
                        // весь журнал. Для корреляции строк одного соединения
                        // достаточно локального счётчика — он ничего не говорит о
                        // том, кто и откуда подключился, только "какое по счёту".
                        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                        let span = tracing::info_span!("client_conn", conn_id);

                        let conn = Connection::new(stream);

                        // Pass the Arc clone down to the ServerHandler
                        let handler = ServerHandler::new(
                            conn,
                            session_manager.clone(),
                            self.decoy_host.clone(),
                            self.auth.clone(),
                            self.identity.clone(),
                        );

                        let active_now = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        metrics::gauge!("netrunner_connections_active").set(active_now as f64);
                        metrics::counter!("netrunner_connections_total").increment(1);
                        let conn_counter = active_connections.clone();
                        // `span.enter()` держит guard синхронно — `.enter()` НЕЛЬЗЯ
                        // держать через `.await` в async-коде (сам `tracing` явно
                        // документирует это как ошибку): у соединения, живущего
                        // часами (весь VPN-сеанс), это на многопоточном рантайме
                        // ломает thread-local стек спанов ЧУЖИХ задач, деля с этой
                        // один воркер-поток между поллингами — отсюда и снежный ком
                        // из вложенных "client_conn" в каждой JSON-строке лога
                        // (реальный инцидент: 24ГБ логов за сутки, диск в 100%,
                        // прокси зависал без падения). `.instrument(span)` на
                        // самом future — единственный async-safe способ.
                        let conn_future = async move {
                            debug!("🔌 New physical connection accepted");
                            if let Err(e) = handler.run().await {
                                error!(error = %e, "⚠️ Server handler terminated with error");
                            }
                            let active_now = conn_counter.fetch_sub(1, Ordering::Relaxed) - 1;
                            metrics::gauge!("netrunner_connections_active").set(active_now as f64);
                        };
                        tokio::spawn(conn_future.instrument(span));
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
        info!(
            "✅ Drain завершён, соединений осталось: {}",
            active_connections.load(Ordering::Relaxed)
        );
    }
}
