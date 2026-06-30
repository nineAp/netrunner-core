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

mod diagnostics;
mod network;
use clap::Parser;
use netrunner_logger::Logger;
use tokio_util::sync::CancellationToken;

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
}

fn main() {
    Logger::init("./logs".into(), true);
    Logger::global().set_level("info");
    let args = Args::parse();
    let net = Network::new(args.host, args.port);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        net.run(CancellationToken::new()).await;
    });
}
