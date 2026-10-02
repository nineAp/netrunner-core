//! TCP-листенер сервера и приём входящих туннельных соединений.
//!
//! [`Network::run`] инициализирует глобальный конфиг и серверную диагностику,
//! создаёт **один** общий [`SessionManager`] (мультиплексирование: разные ноги
//! одной сессии цепляются к одному muxer), запускает фоновую задачу health-check
//! и печати топологии, после чего в цикле принимает соединения и на каждое
//! спавнит `ServerHandler::run` из ядра под отдельным tracing-span клиента.

use netrunner_core::net::{
    run_datagram_listener, AuthValidator, Connection, Muxer, NetworkConfig, NodeHealthReport,
    NodeMesh, ServerHandler, SessionManager, TunnelHandler, MAX_TUNNEL_LEGS,
    TOPOLOGY_PRINT_INTERVAL,
};
use netrunner_core::Identity;
use netrunner_logger::{debug, error, info, warn};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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

struct PendingUsageBatch {
    batch_id: String,
    deltas: Vec<(String, u64)>,
    sessions: Vec<(String, Vec<Arc<Muxer>>)>,
}

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
/// The QUIC mesh port is reachable before NRXP authentication. Bound the
/// number of handshakes and active peer sessions that can reserve resources.
const MAX_MESH_QUIC_CONNECTIONS: usize = 512;

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
    require_auth: bool,
    mesh_enabled: bool,
    mesh: Option<Arc<NodeMesh>>,
    mesh_quic_port: u16,
    /// `None` — health-эндпоинт выключен (по умолчанию для обратной
    /// совместимости с уже развёрнутыми нодами без этого флага).
    health_port: Option<u16>,
    /// Долговременные учётные данные ноды (`PROXY_NRXP_SECRET` +
    /// `PROXY_NRXP_PRIVATE_KEY`), заведённые в админке бэкенда. `None` — не
    /// настроены, нода принимает только старый анонимный хендшейк.
    identity: Option<Identity>,
    /// Длины записей cover-flight — одни на весь узел (см. `ServerHandler`).
    cover_flight: Arc<[usize]>,
    /// Режим маскировки: ретранслировать ли fallback на запрошенный SNI
    /// (`Relay`) или всегда отдавать свой сайт (`SelfHosted`). См.
    /// `netrunner_core::decoy::DecoyMode`.
    honor_requested_sni: bool,
}

impl Network {
    pub fn new(
        host: String,
        port: u16,
        decoy_host: impl Into<Arc<str>>,
        auth: Option<Arc<dyn AuthValidator>>,
        require_auth: bool,
        mesh_enabled: bool,
        mesh: Option<Arc<NodeMesh>>,
        mesh_quic_port: u16,
        health_port: Option<u16>,
        identity: Option<Identity>,
        cover_flight: Arc<[usize]>,
        honor_requested_sni: bool,
    ) -> Self {
        Self {
            host,
            port,
            decoy_host: decoy_host.into(),
            auth,
            require_auth,
            mesh_enabled,
            mesh,
            mesh_quic_port,
            health_port,
            identity,
            cover_flight,
            honor_requested_sni,
        }
    }

    /// Запускает сервер: слушает TCP и обслуживает соединения до отмены `token`.
    /// Like `TcpListener::bind`, but with `SO_RCVBUF` raised to the leg-buffer ceiling
    /// before `listen` (see the call site for why).
    async fn bind_with_big_rcvbuf(addr: &str) -> std::io::Result<TcpListener> {
        let sock_addr = tokio::net::lookup_host(addr)
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("no address to bind"))?;
        let socket = if sock_addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        #[cfg(unix)]
        socket.set_reuseaddr(true)?;
        let _ = socket.set_recv_buffer_size(netrunner_core::net::BUF_CAP as u32);
        socket.bind(sock_addr)?;
        socket.listen(1024)
    }

    pub async fn run(&self, token: CancellationToken) {
        let addr = format!("{}:{}", self.host, self.port);
        START_TIME.get_or_init(Instant::now);

        NetworkConfig::init_global(1450);

        // 🔥 CRITICAL FIX: Create ONE global session manager for multiplexing
        let session_manager = Arc::new(SessionManager::new());

        // The control plane supplies peer metadata; each node probes from its
        // own location and forwards each stream over authenticated NRXP legs.
        if let (Some(mesh), Some(validator)) = (self.mesh.clone(), self.auth.clone()) {
            tokio::spawn(async move {
                loop {
                    match validator.list_mesh_peers().await {
                        Ok(peers) => {
                            mesh.update_peers(peers).await;
                            mesh.probe_peers().await;
                            metrics::gauge!("netrunner_mesh_peers_available")
                                .set(mesh.peer_count().await as f64);
                        }
                        Err(error) => {
                            warn!(error = %error.internal_msg, "Mesh peer directory refresh failed");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(20)).await;
                }
            });
        }

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
            let mut pending_usage_batches = VecDeque::<PendingUsageBatch>::new();
            loop {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                LAST_PERIODIC_TICK_UNIX_SECS.store(now_unix_secs(), Ordering::Relaxed);

                let mut active_muxers = Vec::new();
                for entry in sm_clone.get_session().iter() {
                    active_muxers.push(entry.value().clone());
                }

                // Aggregate leg health across every session on this node —
                // Prometheus already scrapes this node's /metrics (see
                // netrunner-data/observability/prometheus.yml), so this is
                // enough to alert on "legs died and did not come back"
                // without reading logs by hand. `netrunner_sessions_leg_degraded`
                // is the actionable one: a session sitting below
                // MAX_TUNNEL_LEGS is one `TunnelEngine::run` failure away from
                // the requeue path (see `TunnelEngine::requeue_pending`)
                // having fewer and fewer legs to fail over onto.
                let total_active_legs: usize =
                    active_muxers.iter().map(|m| m.active_legs_count()).sum();
                let expected_legs = active_muxers.len() * MAX_TUNNEL_LEGS as usize;
                let degraded_sessions = active_muxers
                    .iter()
                    .filter(|m| m.active_legs_count() < MAX_TUNNEL_LEGS as usize)
                    .count();
                metrics::gauge!("netrunner_legs_active").set(total_active_legs as f64);
                metrics::gauge!("netrunner_legs_expected").set(expected_legs as f64);
                metrics::gauge!("netrunner_sessions_leg_degraded").set(degraded_sessions as f64);

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
                // валидацию токена, см. `ServerHandler::run`). Дельты
                // агрегируются по пользователям и отправляются пакетами,
                // поэтому объём HTTP-запросов и SQL UPDATE зависит от числа
                // активных пользователей, а не туннельных сессий.
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
                    // Не меняем состав уже отправленной пачки, пока не
                    // получим ответ: если БД успела commit, а HTTP-ответ
                    // потерялся, повтор с тем же ID вернёт сохранённый итог.
                    // Пока есть очередь, новые байты остаются в счётчиках muxer.
                    if pending_usage_batches.is_empty() {
                        let mut usage_by_user: HashMap<String, (u64, Vec<Arc<Muxer>>)> =
                            HashMap::new();
                        for muxer in &active_muxers {
                            let Some(user_id) = muxer.quota_user_id() else {
                                continue;
                            };
                            let delta = muxer.take_usage_delta();
                            if delta == 0 {
                                continue;
                            }
                            let (total, sessions) = usage_by_user
                                .entry(user_id)
                                .or_insert_with(|| (0, Vec::new()));
                            *total = total.saturating_add(delta);
                            sessions.push(muxer.clone());
                        }

                        let mut grouped: Vec<_> = usage_by_user.into_iter().collect();
                        grouped.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                        for chunk in grouped.chunks(1000) {
                            let deltas = chunk
                                .iter()
                                .map(|(user_id, (delta, _))| (user_id.clone(), *delta))
                                .collect();
                            let sessions = chunk
                                .iter()
                                .map(|(user_id, (_, sessions))| (user_id.clone(), sessions.clone()))
                                .collect();
                            pending_usage_batches.push_back(PendingUsageBatch {
                                batch_id: uuid::Uuid::new_v4().to_string(),
                                deltas,
                                sessions,
                            });
                        }
                    }

                    while let Some(batch) = pending_usage_batches.front() {
                        let result = validator
                            .report_usage_batch(&batch.batch_id, &batch.deltas)
                            .await;
                        match result {
                            Ok(reports) => {
                                let batch = pending_usage_batches
                                    .pop_front()
                                    .expect("front batch exists");
                                let mut all_reported = true;
                                for (user_id, sessions) in &batch.sessions {
                                    match reports.get(user_id) {
                                        Some(report) if report.over_limit => {
                                            warn!(
                                                user_id,
                                                used = report.used_bytes,
                                                limit = ?report.limit_bytes,
                                                "🚫 Traffic limit exceeded, tearing down session"
                                            );
                                            for muxer in sessions {
                                                muxer.remove_all_legs();
                                                sm_clone.remove(muxer.session_id());
                                            }
                                        }
                                        Some(_) => {}
                                        None => {
                                            all_reported = false;
                                            warn!(
                                                user_id,
                                                "Usage report returned no row; will retry"
                                            );
                                        }
                                    }
                                }
                                if !all_reported {
                                    pending_usage_batches.push_front(batch);
                                    break;
                                }
                            }
                            Err(error) => {
                                warn!(
                                    batch_id = %batch.batch_id,
                                    error = %error,
                                    "Usage batch failed; retaining it for idempotent retry"
                                );
                                break;
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
        // Receive buffer at its ceiling BEFORE listen: accepted sockets inherit it, and
        // the TCP window scale is fixed at the handshake, so this is what lets the
        // per-leg adaptive tuner (core `buftune`) grow the download window later. Each
        // leg is brought down to a small initial value right after accept. Any failure
        // here falls back to the plain bind (old behaviour).
        let listener = match Self::bind_with_big_rcvbuf(&addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "Tuned listener bind failed, falling back to plain bind");
                TcpListener::bind(&addr).await.expect("Server bind failed")
            }
        };

        // Тот же адрес и порт, что и у TCP — опциональная UDP-нога (см.
        // `netrunner_core::net::run_datagram_listener`) существует ровно
        // поверх уже установленных TCP-сессий этого же `session_manager`, а
        // не как отдельный сервис: она не может подняться раньше первой
        // TCP-ноги сессии (см. `SessionManager::register_datagram_session`).
        // Бинд может не удаться (например, порт занят другим процессом под
        // UDP, или платформа режет UDP отдельно от TCP) — это не должно
        // ронять сервер целиком, только оставлять всех клиентов на TCP.
        match UdpSocket::bind(&addr).await {
            Ok(udp_socket) => {
                let udp_session_manager = session_manager.clone();
                let udp_token = token.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        run_datagram_listener(udp_socket, udp_session_manager, udp_token).await
                    {
                        warn!(error = %e, "UDP datagram leg listener stopped");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "UDP datagram leg listener failed to bind, continuing TCP-only");
            }
        }

        // QUIC is reserved for authenticated node-to-node sessions. Keep it
        // on a separate UDP port: the public ingress UDP socket above carries
        // the existing quiceng datagram transport and cannot share Quinn's
        // socket safely.
        if self.mesh_enabled {
            let quic_addr = format!("{}:{}", self.host, self.mesh_quic_port);
            let bind_addr = tokio::net::lookup_host(&quic_addr)
                .await
                .ok()
                .and_then(|mut addrs| addrs.next());
            match bind_addr
                .and_then(|addr| netrunner_core::net::mesh_quic_server_endpoint(addr).ok())
            {
                Some(endpoint) => {
                    let listener_token = token.clone();
                    let session_manager = session_manager.clone();
                    let decoy_host = self.decoy_host.clone();
                    let auth = self.auth.clone();
                    let identity = self.identity.clone();
                    let cover_flight = self.cover_flight.clone();
                    let honor_requested_sni = self.honor_requested_sni;
                    let require_auth = self.require_auth;
                    let mesh = self.mesh.clone();
                    tokio::spawn(async move {
                        run_mesh_quic_listener(
                            endpoint,
                            session_manager,
                            decoy_host,
                            auth,
                            identity,
                            cover_flight,
                            honor_requested_sni,
                            require_auth,
                            mesh,
                            listener_token,
                        )
                        .await;
                    });
                }
                None => warn!(
                    port = self.mesh_quic_port,
                    "Mesh QUIC listener failed to bind; peer links will use TCP fallback"
                ),
            }
        }

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
                        let cover_flight = self.cover_flight.clone();
                        let handler = ServerHandler::new(
                            conn,
                            session_manager.clone(),
                            self.decoy_host.clone(),
                            self.auth.clone(),
                            self.identity.clone(),
                            cover_flight,
                            self.honor_requested_sni,
                        )
                        .with_mesh_policy(
                            self.require_auth,
                            self.mesh_enabled,
                            self.mesh.clone(),
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

#[allow(clippy::too_many_arguments)]
async fn run_mesh_quic_listener(
    endpoint: quinn::Endpoint,
    session_manager: Arc<SessionManager>,
    decoy_host: Arc<str>,
    auth: Option<Arc<dyn AuthValidator>>,
    identity: Option<Identity>,
    cover_flight: Arc<[usize]>,
    honor_requested_sni: bool,
    require_auth: bool,
    mesh: Option<Arc<NodeMesh>>,
    token: CancellationToken,
) {
    info!("Authenticated mesh QUIC listener ready");
    let connection_slots = Arc::new(Semaphore::new(MAX_MESH_QUIC_CONNECTIONS));
    loop {
        let incoming = tokio::select! {
            _ = token.cancelled() => break,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            }
        };

        let Some(connection_permit) = try_acquire_mesh_quic_slot(&connection_slots) else {
            incoming.refuse();
            metrics::counter!("netrunner_mesh_quic_admission_rejected_total").increment(1);
            continue;
        };

        let session_manager = session_manager.clone();
        let decoy_host = decoy_host.clone();
        let auth = auth.clone();
        let identity = identity.clone();
        let cover_flight = cover_flight.clone();
        let mesh = mesh.clone();
        let token = token.clone();
        tokio::spawn(async move {
            // Keep the slot until the transport and its NRXP session are
            // closed, including while the initial handshake is in progress.
            let _connection_permit = connection_permit;
            let connection = tokio::select! {
                _ = token.cancelled() => return,
                connection = incoming => match connection {
                    Ok(connection) => connection,
                    Err(_) => {
                        metrics::counter!("netrunner_mesh_quic_handshake_failures_total").increment(1);
                        return;
                    }
                }
            };

            // One authenticated NRXP session owns a QUIC connection. Its
            // logical streams are multiplexed by the existing MeshPeerSession.
            let streams =
                tokio::time::timeout(Duration::from_secs(8), connection.accept_bi()).await;
            let (send, recv) = match streams {
                Ok(Ok(streams)) => streams,
                _ => {
                    connection.close(0u32.into(), b"mesh stream timeout");
                    return;
                }
            };
            metrics::counter!("netrunner_mesh_quic_sessions_accepted_total").increment(1);

            let handler = ServerHandler::new(
                Connection::new_quic(recv, send),
                session_manager,
                decoy_host,
                auth,
                identity,
                cover_flight,
                honor_requested_sni,
            )
            .with_mesh_policy(require_auth, true, mesh)
            .with_mesh_quic_connection(connection.clone());
            let exit = supervise_mesh_quic_handler(
                async move {
                    let _ = handler.run().await;
                },
                connection.closed(),
                token.cancelled(),
            )
            .await;
            match exit {
                MeshHandlerExit::Shutdown => connection.close(0u32.into(), b"server shutdown"),
                MeshHandlerExit::ConnectionClosed => {}
                MeshHandlerExit::HandlerFinished => {
                    connection.close(0u32.into(), b"mesh session ended")
                }
            }
        });
    }
    endpoint.close(0u32.into(), b"server shutdown");
    endpoint.wait_idle().await;
}

fn try_acquire_mesh_quic_slot(slots: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    slots.clone().try_acquire_owned().ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeshHandlerExit {
    Shutdown,
    ConnectionClosed,
    HandlerFinished,
}

async fn supervise_mesh_quic_handler<H, C, S>(
    handler: H,
    connection_closed: C,
    shutdown: S,
) -> MeshHandlerExit
where
    H: Future<Output = ()>,
    C: Future,
    S: Future,
{
    tokio::pin!(handler);
    tokio::select! {
        _ = shutdown => MeshHandlerExit::Shutdown,
        _ = connection_closed => MeshHandlerExit::ConnectionClosed,
        _ = &mut handler => MeshHandlerExit::HandlerFinished,
    }
}

#[cfg(test)]
mod mesh_quic_admission_tests {
    use super::{
        supervise_mesh_quic_handler, try_acquire_mesh_quic_slot, MeshHandlerExit, Semaphore,
    };
    use std::{
        future::pending,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    use tokio::task::yield_now;

    #[test]
    fn mesh_quic_admission_is_bounded_and_releases_slots() {
        let slots = Arc::new(Semaphore::new(2));
        let first = try_acquire_mesh_quic_slot(&slots).unwrap();
        let second = try_acquire_mesh_quic_slot(&slots).unwrap();
        assert!(try_acquire_mesh_quic_slot(&slots).is_none());

        drop(first);
        assert!(try_acquire_mesh_quic_slot(&slots).is_some());
        drop(second);
    }

    #[tokio::test]
    async fn quic_handler_is_dropped_when_transport_closes_or_server_stops() {
        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        for shutdown in [false, true] {
            let dropped = Arc::new(AtomicBool::new(false));
            let marker = DropMarker(dropped.clone());
            let handler = async move {
                let _marker = marker;
                pending::<()>().await;
            };
            let close = async {
                if !shutdown {
                    yield_now().await;
                } else {
                    pending::<()>().await;
                }
            };
            let stop = async {
                if shutdown {
                    yield_now().await;
                } else {
                    pending::<()>().await;
                }
            };

            let result = supervise_mesh_quic_handler(handler, close, stop).await;
            assert_eq!(
                result,
                if shutdown {
                    MeshHandlerExit::Shutdown
                } else {
                    MeshHandlerExit::ConnectionClosed
                }
            );
            assert!(dropped.load(Ordering::SeqCst));
        }
    }
}
