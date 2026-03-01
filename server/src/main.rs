use netrunner_common::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
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
    logger_init();
    let args = Args::parse();
    let net = Network::new(args.port, ConnectionRole::Server, None);

    // Создаем движок (Runtime)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // "Блокируем" основной поток, пока работает асинхронный код
    rt.block_on(async {
        net.run().await;
    });
}
