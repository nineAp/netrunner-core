use std::sync::Arc;

use netrunner_common::proxy::{
    connection::handler::{netr2tcp::Netr2Tcp, tcp2netr::Tcp2Netr},
    network::Network,
};

use clap::Parser;
#[derive(Parser, Debug)]
#[command(author, version, about = "Netrunner Proxy Server")]
struct Args {
    /// Порт, который будет слушать сервер
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// IP адрес для привязки
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

fn main() {
    let args = Args::parse();
    let inbound_handler = Arc::new(Netr2Tcp); //change here to Netr2tcp
    let outbound_handler = Arc::new(Tcp2Netr);
    let net = Network::new(inbound_handler, outbound_handler, args.port);

    // Создаем движок (Runtime)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // "Блокируем" основной поток, пока работает асинхронный код
    rt.block_on(async {
        net.run().await;
    });
}
