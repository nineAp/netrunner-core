use std::sync::Arc;

use netrunner_common::proxy::{
    connection::handler::{socks2netr::Socks2Netr, tcp2netr::Tcp2Netr},
    network::Network,
};
fn main() {
    println!("Подготовка конфигов...");
    let inbound_handler = Arc::new(Socks2Netr); //change here to Netr2tcp
    let outbound_handler = Arc::new(Tcp2Netr);
    let net = Network::new(inbound_handler, outbound_handler, 8080);

    // Создаем движок (Runtime)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // "Блокируем" основной поток, пока работает асинхронный код
    rt.block_on(async {
        net.run().await;
    });
}
