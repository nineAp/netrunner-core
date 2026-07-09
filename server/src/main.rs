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
mod network;
use clap::Parser;
use netrunner_core::net::AuthValidator;
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
}

fn main() {
    Logger::init("./logs".into(), true);
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

    let net = Network::new(
        args.host,
        args.port,
        args.decoy_host,
        auth,
        args.health_port,
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

        shutdown_signal(token).await;
        if let Err(e) = run_handle.await {
            error!(error = ?e, "Задача сервера завершилась с паникой при остановке");
        }
    });
}
