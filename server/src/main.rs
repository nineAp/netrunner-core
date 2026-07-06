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
mod network;
use clap::Parser;
use netrunner_core::net::AuthValidator;
use netrunner_logger::Logger;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::backend_client::BackendClient;
use crate::network::Network;

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

    let net = Network::new(args.host, args.port, args.decoy_host, auth);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        net.run(CancellationToken::new()).await;
    });
}
