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

    /// Требовать валидный Bearer-токен (выданный `netrunner-backend`) от
    /// каждого клиента и отчитываться о расходе трафика для динамических
    /// лимитов. Выключено по умолчанию — включается по инстансу, не меняя
    /// поведение уже развёрнутых нод без этого флага.
    #[arg(long, default_value_t = false)]
    require_auth: bool,

    /// URL control-plane бэкенда для проверки токенов/отчётов о трафике.
    /// Обязателен, только если передан `--require-auth`.
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
    // Приватность/стабильность: НЕ пишем JSON-лог на диск ноды — раньше это
    // (`Some("./logs")`) дважды забивало диск и вешало прокси (см. историю
    // инцидентов на proxy-fr1). JSON уходит в stdout — виден через
    // `docker logs`, централизованный сбор состояния тоннеля идёт отдельным
    // push-каналом на control-plane (см. `report_node_health` в network.rs).
    Logger::init(None, true);
    Logger::global().set_level("info");
    let args = Args::parse();

    let auth: Option<Arc<dyn AuthValidator>> = if args.require_auth {
        let backend_url = args
            .backend_url
            .expect("--require-auth требует --backend-url");
        let internal_secret = std::env::var("PROXY_INTERNAL_SECRET")
            .expect("--require-auth требует переменную окружения PROXY_INTERNAL_SECRET");
        Some(Arc::new(BackendClient::new(backend_url, internal_secret)))
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

    let net = Network::new(
        args.host.clone(),
        args.port,
        args.decoy_host,
        auth,
        args.health_port,
        identity,
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
