//! # netrunner-server — серверная часть прокси
//!
//! Тонкая обвязка вокруг ядра ([`netrunner_core`]): парсит аргументы, поднимает
//! логгер и tokio-рантайм и запускает [`Network`](crate::network::Network),
//! которая слушает TCP, принимает замаскированные TLS-соединения и отдаёт каждое
//! в `ServerHandler` ядра (хендшейк → аутентификация → проксирование или
//! stealth-fallback). Бизнес-логика целиком в ядре; здесь — точка входа и
//! серверная диагностика ([`diagnostics`](crate::diagnostics)).

// Workaround for rustc 1.94 ICE in check_mod_deathness (dead-code MIR pass).
#![allow(dead_code)]

mod backend_client;
mod decoy_site;
mod diagnostics;
mod health;
mod metrics_server;
mod network;
use clap::Parser;
use netrunner_core::net::AuthValidator;
use netrunner_core::{Identity, LocalIdentity};
use netrunner_logger::{error, info, Logger};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::backend_client::BackendClient;
use crate::network::Network;

/// reqwest enables AWS-LC while Quinn enables Ring in this binary. Rustls
/// therefore cannot infer which process-wide provider to use from features.
/// Select Ring before any tokio task can build a TLS or QUIC config.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Ждёт SIGTERM (docker stop/systemctl stop) или SIGINT (Ctrl+C) и отменяет
/// токен — раньше этой функции не было вообще: сервер получал сигнал прямо
/// от ОС мимо CancellationToken'а, и вся drain-логика в `Network::run` была
/// мертва, ни разу не срабатывая на реальном шатдауне.
async fn shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Не удалось установить обработчик Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Не удалось установить обработчик SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("🛑 Получен SIGINT (Ctrl+C). Останавливаемся..."),
        _ = terminate => info!("🛑 Получен SIGTERM. Останавливаемся..."),
    }
    token.cancel();
}

/// Аргументы командной строки сервера.
#[derive(Parser, Debug)]
#[command(author, version, about = "Netrunner Proxy Server")]
struct Args {
    /// Порт прослушивания.
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Адрес привязки.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Домен-декой: под кого притворяется этот узел для «не наших» подключений
    /// (stealth-fallback прозрачно проксирует туда трафик сканеров/чужих
    /// клиентов). Раньше было жёстко зашито на `ubuntu.com` в коде ядра — теперь
    /// атрибут ноды, можно задавать разный на каждом развёртывании.
    #[arg(long, default_value = netrunner_core::net::DEFAULT_DECOY_HOST)]
    decoy_host: String,

    /// Имя витрины-пресета, под которую маскируется узел (`clipforge`,
    /// `hauler`, `logdrain`). SNI пресета обязан входить в каталог доменов
    /// узла (`NETRUNNER_DECOY_DOMAINS`) — иначе узел не поднимется: под домен,
    /// которым он не владеет, нет валидного сертификата. Не задан — узел
    /// работает как раньше (сборка витрины пропускается).
    #[arg(long)]
    decoy_preset: Option<String>,

    /// Режим маскировки: `relay` (REALITY-style — ретрансляция на чужой
    /// реальный сайт, историческое поведение по умолчанию) или `self-hosted`
    /// (узел сам обслуживает свою витрину под своим доменом). Не задан —
    /// `relay`, обратная совместимость.
    #[arg(long, default_value = "relay")]
    decoy_mode: String,

    /// Только для `--decoy-mode self-hosted`: адрес локального TLS-терминатора
    /// (co-located nginx/caddy с сертификатом своего домена), который отдаёт
    /// собранную витрину. Fallback ретранслируется СЮДА, а не на внешний сайт.
    #[arg(long, default_value = "127.0.0.1:8443")]
    decoy_local_site: String,

    /// Только для `--decoy-mode self-hosted`: домен узла (SNI и CN сертификата).
    /// Обязан входить в каталог `NETRUNNER_DECOY_DOMAINS`. Не задан — берётся
    /// SNI из самого пресета. Именно этот домен, а не захардкоженный в пресете,
    /// делает витрину «своей» для конкретного узла.
    #[arg(long)]
    decoy_sni: Option<String>,

    /// Длины TLS-записей первого flight'а узла (`EncryptedExtensions`,
    /// `Certificate`, `CertificateVerify`, `Finished`): список через запятую
    /// (`27,4342,537,69`) либо путь к JSON-файлу, который пишет
    /// `netrunner-client profile record --flight-out`. Снимите их с настоящего
    /// ответа своего домена — тогда cover-flight совпадает с тем, что отдаёт
    /// сайт узла, а не со «средней» цепочкой. Не задан — типовая цепочка.
    #[arg(long, env = "NETRUNNER_COVER_FLIGHT")]
    cover_flight: Option<String>,

    /// JSON-профиль браузера с блоком `shape` (его пишет
    /// `netrunner-client profile record`): длины TLS-записей узла
    /// (направление сервер → клиент) выравниваются по наблюдавшимся у браузера.
    /// Остальное содержимое файла узлом не используется. Не задан —
    /// синтетическое распределение длин.
    #[arg(long, env = "NETRUNNER_SHAPE_PROFILE")]
    shape_profile: Option<String>,

    /// Требовать валидный Bearer-токен (выданный `netrunner-backend`) от
    /// каждого клиента и отчитываться о расходе трафика для динамических
    /// лимитов. Выключено по умолчанию — включается по инстансу, не меняя
    /// поведение уже развёрнутых нод без этого флага.
    #[arg(long, default_value_t = false)]
    require_auth: bool,

    /// Enable authenticated peer routing. This node can accept mesh traffic
    /// and route local client streams according to --mesh-max-hops.
    #[arg(long, default_value_t = false)]
    mesh_enabled: bool,

    /// Maximum proxy-node count in a route: 1 = direct, 2 = RTT-weighted
    /// rotating healthy egress, 3..=8 = per-flow random length up to the limit
    /// with a pinned healthy egress.
    #[arg(long, default_value_t = 2)]
    mesh_max_hops: u8,

    /// UDP port for real QUIC between proxy nodes. Clients still connect to
    /// ingress through the existing quiceng datagram transport on --port.
    #[arg(
        long,
        env = "MESH_QUIC_PORT",
        default_value_t = netrunner_core::net::DEFAULT_MESH_QUIC_PORT
    )]
    mesh_quic_port: u16,

    /// URL control-plane бэкенда для проверки токенов/отчётов о трафике.
    /// Обязателен, если включён `--require-auth` или `--mesh-enabled`.
    #[arg(long)]
    backend_url: Option<String>,

    /// Порт для внутреннего HTTP `/health` (биндится только на 127.0.0.1 —
    /// не для публичного доступа, только supervisor/docker healthcheck на
    /// этой же машине). Не задан — health-эндпоинт выключен.
    #[arg(long)]
    health_port: Option<u16>,

    /// Порт для `/metrics` (Prometheus text exposition) — в отличие от
    /// `--health-port`, биндится на 0.0.0.0 (нужен для скрейпа удалённым
    /// центральным Prometheus), ОБЯЗАТЕЛЬНО зафайрволить на IP
    /// observability-VPS. Не задан — метрики выключены.
    #[arg(long)]
    metrics_port: Option<u16>,
}

fn main() {
    install_crypto_provider();

    // Приватность/стабильность: НЕ пишем JSON-лог на диск ноды — раньше это
    // (`Some("./logs")`) дважды забивало диск и вешало прокси (см. историю
    // инцидентов на proxy-fr1). JSON уходит в stdout — виден через
    // `docker logs`, централизованный сбор состояния тоннеля идёт отдельным
    // push-каналом на control-plane (см. `report_node_health` в network.rs).
    Logger::init(None, true);
    Logger::global().set_level("info");
    let args = Args::parse();

    if !(1..=netrunner_core::net::MAX_MESH_HOPS).contains(&args.mesh_max_hops) {
        panic!(
            "--mesh-max-hops must be between 1 and {}",
            netrunner_core::net::MAX_MESH_HOPS
        );
    }

    let auth_required_by_node = args.require_auth || args.mesh_enabled;
    let backend_url = if auth_required_by_node {
        Some(
            args.backend_url
                .clone()
                .expect("--require-auth/--mesh-enabled требуют --backend-url"),
        )
    } else {
        None
    };
    let internal_secret = if auth_required_by_node {
        Some(
            std::env::var("PROXY_INTERNAL_SECRET")
                .expect("--require-auth/--mesh-enabled требуют PROXY_INTERNAL_SECRET"),
        )
    } else {
        None
    };
    let auth: Option<Arc<dyn AuthValidator>> = if auth_required_by_node {
        let backend_url = backend_url.expect("backend URL checked above");
        let internal_secret = internal_secret.as_ref().expect("secret checked above");
        Some(Arc::new(BackendClient::new(
            backend_url,
            internal_secret.clone(),
        )))
    } else {
        None
    };

    let mesh = if args.mesh_enabled {
        let node_id = std::env::var("PROXY_NODE_ID")
            .expect("--mesh-enabled requires PROXY_NODE_ID from netrunner-backend");
        let node_secret = internal_secret
            .as_ref()
            .expect("mesh requires PROXY_INTERNAL_SECRET")
            .clone();
        Some(Arc::new(
            netrunner_core::net::NodeMesh::with_max_hops_and_quic_port(
                node_id,
                node_secret,
                args.mesh_max_hops,
                args.mesh_quic_port,
            ),
        ))
    } else {
        None
    };

    // Долговременные учётные данные ноды: секрет входа и приватная половина
    // статической пары X25519. Заводятся в админке бэкенда, сюда приезжают
    // провижинингом рядом с PROXY_INTERNAL_SECRET — но это РАЗНЫЕ секреты с
    // разным уровнем доступа: internal_secret пускает в control-plane и
    // клиентам не отдаётся никогда, а публичная половина статической пары,
    // наоборот, раздаётся каждому клиенту (см. crypto::identity).
    //
    // Обе переменные либо заданы вместе, либо не заданы вовсе: нода с одной
    // половиной конфигурации — это тихо сломанная нода, поэтому падаем на
    // старте, а не на каждом хендшейке.
    //
    // Флаги для метрик: сам `Identity` их наружу не отдаёт, а видеть, с чем
    // РЕАЛЬНО поднята нода, нужно — строка в БД бэкенда может от неё отстать
    // (например, `.env` уехал не тот). Расхождение видно сравнением
    // `netrunner_nrxp_*` с ноды и `node_nrxp_*` с бэкенда.
    let mut nrxp_strict_flag = false;
    let identity = match (
        std::env::var("PROXY_NRXP_SECRET").ok(),
        std::env::var("PROXY_NRXP_PRIVATE_KEY").ok(),
    ) {
        (Some(secret), Some(private_key)) => {
            // Пока false, нода принимает и клиентов старой анонимной схемы —
            // это нужно ровно на время раскатки, пока бэкенд не раздал ключи
            // всем приложениям. Оставлять так навсегда нельзя: активному
            // посреднику достаточно переписать заявленную версию в
            // ClientHello, чтобы увести соединение на неаутентифицированную
            // схему. Финальный шаг раскатки — PROXY_NRXP_STRICT=true.
            let strict = std::env::var("PROXY_NRXP_STRICT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            let local = LocalIdentity::from_hex(&secret, &private_key, strict)
                .expect("PROXY_NRXP_SECRET/PROXY_NRXP_PRIVATE_KEY: 32 байта hex каждый");

            // Публичную половину печатаем при старте: оператор сверяет её с
            // тем, что показывает админка для этой ноды. Разошлись — клиенты
            // не подключатся, и увидеть это в логе старта дешевле, чем в
            // графике неудачных хендшейков через сутки.
            netrunner_logger::info!(
                nrxp_public_key = %local.public_key_hex(),
                strict,
                "NRXP identity loaded"
            );
            nrxp_strict_flag = strict;
            Some(Identity::Local(local))
        }
        (None, None) => {
            netrunner_logger::warn!(
                "NRXP identity not configured: анонимный хендшейк, аутентификации сервера нет"
            );
            None
        }
        _ => panic!(
            "PROXY_NRXP_SECRET и PROXY_NRXP_PRIVATE_KEY задаются только вместе: \
             нода с половиной учётных данных не сможет аутентифицировать себя клиентам"
        ),
    };

    if args.mesh_enabled && identity.is_none() {
        panic!("--mesh-enabled requires PROXY_NRXP_SECRET and PROXY_NRXP_PRIVATE_KEY");
    }
    if let (Some(mesh), Some(Identity::Local(local))) = (mesh.as_ref(), identity.as_ref()) {
        mesh.set_onion_identity(local.clone());
    }

    // Регистрируется один раз, до первого metrics::counter!/gauge!/histogram! —
    // если --metrics-port не задан, вызовы макросов молча уходят в
    // no-op recorder по умолчанию (штатное поведение крейта metrics).
    let nrxp_configured_flag = identity.is_some();

    let metrics_handle = args
        .metrics_port
        .map(|_| metrics_server::install_recorder());

    // Только после install_recorder: до него макросы metrics! уходят в
    // no-op-рекордер по умолчанию и значение бы потерялось.
    metrics::gauge!("netrunner_nrxp_identity_configured").set(nrxp_configured_flag as u8 as f64);
    metrics::gauge!("netrunner_nrxp_strict").set(nrxp_strict_flag as u8 as f64);

    // ── Витрина узла и допустимые SNI ──────────────────────────────────────
    //
    // Каталог доменов приходит из окружения (тот же список, что и у админки).
    // Если задан --decoy-preset, собираем его страницу ОДИН РАЗ здесь, на
    // старте, и на этом же шаге проверяем, что SNI пресета принадлежит узлу:
    // это и есть барьер «нельзя указать любой SNI» — валидный сертификат есть
    // только под свой домен.
    // ── Режим маскировки ──────────────────────────────────────────────────
    //
    // Два взаимоисключающих режима (см. DecoyMode). Relay — исторический
    // REALITY-style: ретрансляция «не наших» соединений на чужой реальный
    // сайт (--decoy-host). SelfHosted — узел сам обслуживает витрину под своим
    // доменом: fallback ведёт на ЛОКАЛЬНЫЙ сайт (--decoy-local-site), витрина
    // собирается здесь один раз, а SNI обязан принадлежать узлу.
    let decoy_mode = netrunner_core::decoy::DecoyMode::parse(&args.decoy_mode)
        .unwrap_or_else(|e| panic!("--decoy-mode: {e}"));
    let decoy_catalog = netrunner_core::decoy::DecoyCatalog::from_env();

    // Куда ретранслируется fallback и учитывать ли запрошенный SNI — зависит
    // от режима. Дефолт (Relay + внешний decoy_host + honor=true) идентичен
    // прежнему поведению узла.
    let (fallback_host, honor_requested_sni): (String, bool) = match decoy_mode {
        netrunner_core::decoy::DecoyMode::Relay => {
            // Собрать витрину всё равно можно (например, узел и владеет
            // доменом, и одновременно одалживает чужой) — но по умолчанию в
            // Relay витрина не нужна: сайт отдаёт заимствованный decoy_host.
            if args.decoy_preset.is_some() {
                info!("ℹ️  --decoy-preset в режиме relay игнорируется: fallback идёт на внешний --decoy-host");
            } else if decoy_catalog.is_empty() {
                info!(
                    "ℹ️  режим relay (REALITY-style): маскировка под внешний --decoy-host {}",
                    args.decoy_host
                );
            }
            (args.decoy_host.clone(), decoy_mode.honor_requested_sni())
        }
        netrunner_core::decoy::DecoyMode::SelfHosted => {
            // SelfHosted требует пресет витрины и владение его SNI: собрать и
            // проверить здесь, на старте, иначе узел не поднимется.
            let preset_name = args.decoy_preset.as_deref().unwrap_or_else(|| {
                panic!(
                    "--decoy-mode self-hosted требует --decoy-preset (какую витрину обслуживать)"
                )
            });
            let preset = decoy_site::preset::Preset::load(preset_name)
                .unwrap_or_else(|e| panic!("не удалось загрузить пресет '{preset_name}': {e}"));
            // SNI узла: явный --decoy-sni (домен ЭТОГО узла) важнее захардкоженного
            // в пресете. Пресет даёт только КОНТЕНТ витрины; под каким доменом её
            // показывать — атрибут узла. Домен обязан принадлежать узлу (каталог).
            let sni_str = args.decoy_sni.as_deref().unwrap_or(&preset.sni);
            let sni = decoy_catalog.validate(sni_str).unwrap_or_else(|e| {
                panic!(
                    "self-hosted: домен '{sni_str}' которым узел не владеет: {e}. \
                     Добавьте его в {}",
                    netrunner_core::decoy::DECOY_DOMAINS_ENV
                )
            });
            let decoy = netrunner_core::decoy::Decoy {
                sni,
                elements: preset.elements.clone(),
            };
            let page = preset
                .render()
                .unwrap_or_else(|e| panic!("сборка витрины '{preset_name}': {e}"));

            // Витрина отдаётся локальным TLS-терминатором своего домена;
            // публикуем собранную страницу туда, где его конфиг её заберёт.
            // Один раз при деплое, не на каждый запрос.
            let out = std::env::var("NETRUNNER_DECOY_SITE_OUT")
                .unwrap_or_else(|_| "/var/www/netrunner-decoy/index.html".to_string());
            if let Some(parent) = std::path::Path::new(&out).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&out, &page) {
                Ok(()) => info!(
                    preset = preset_name, sni = %decoy.sni, blocks = decoy.elements.len(),
                    bytes = page.len(), out = %out,
                    "🪧 SelfHosted: витрина собрана, SNI подтверждён, страница опубликована"
                ),
                Err(e) => info!(
                    error = %e, out = %out,
                    "⚠️  SelfHosted: не удалось записать витрину (локальный сайт отдаст своё содержимое); продолжаю"
                ),
            }
            // Fallback — на локальный сайт узла; запрошенный SNI игнорируется.
            (
                args.decoy_local_site.clone(),
                decoy_mode.honor_requested_sni(),
            )
        }
    };

    // Форма трафика: узел отправляет направление `down`.
    netrunner_core::nrxp::shape::set_server_role(true);
    if let Some(path) = &args.shape_profile {
        match netrunner_core::browser_profile::load_shape_file(path) {
            Ok((up, down)) => info!("shape-profile: {path}: клиент→сервер {up}, сервер→клиент {down} значений"),
            Err(e) => panic!("--shape-profile: {e}"),
        }
    }

    // Cover-flight — один на весь узел, детерминированный (см. ServerHandler).
    // Измеренный (--cover-flight) либо типовая цепочка Let's Encrypt.
    let cover_flight: std::sync::Arc<[usize]> = match args.cover_flight.as_deref() {
        Some(spec) => {
            let text = if std::path::Path::new(spec).is_file() {
                std::fs::read_to_string(spec)
                    .unwrap_or_else(|e| panic!("--cover-flight: не удалось прочитать {spec}: {e}"))
            } else {
                spec.to_owned()
            };
            let (flight, warnings) = netrunner_core::decoy::CoverFlight::parse(&text)
                .unwrap_or_else(|e| panic!("--cover-flight: {e}"));
            for w in warnings {
                netrunner_logger::warn!("cover-flight: {w}");
            }
            info!("cover-flight: измеренный, записи {:?}", flight.as_records());
            flight.as_records().to_vec().into()
        }
        None => netrunner_core::decoy::CoverFlight::node_default()
            .as_records()
            .to_vec()
            .into(),
    };

    let net = Network::new(
        args.host.clone(),
        args.port,
        fallback_host,
        auth,
        args.require_auth,
        args.mesh_enabled,
        mesh,
        args.mesh_quic_port,
        args.health_port,
        identity,
        cover_flight,
        honor_requested_sni,
    );

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        let token = CancellationToken::new();
        let run_token = token.clone();
        // net.run() спавним отдельной задачей и дожидаемся её ПОСЛЕ сигнала —
        // tokio::select! между сигналом и run() тут не подходит: select
        // дропает недовершившуюся ветку целиком, оборвав drain-фазу в
        // Network::run в момент получения самого сигнала, вместо того чтобы
        // дать ей отработать.
        let run_handle = tokio::spawn(async move {
            net.run(run_token).await;
        });

        if let (Some(port), Some(handle)) = (args.metrics_port, metrics_handle) {
            let metrics_token = token.clone();
            tokio::spawn(metrics_server::run(
                "0.0.0.0".to_string(),
                port,
                handle,
                metrics_token,
            ));
        }

        shutdown_signal(token).await;
        if let Err(e) = run_handle.await {
            error!(error = ?e, "Задача сервера завершилась с паникой при остановке");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::install_crypto_provider;

    #[test]
    fn rustls_builder_works_with_both_ring_and_aws_lc_enabled() {
        install_crypto_provider();

        let _client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }
}
