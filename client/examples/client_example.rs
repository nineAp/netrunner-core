use std::sync::Arc;

use netrunner_common::proxy::{
    connection::handler::{netr2tcp::Netr2Tcp, tcp2netr::Tcp2Netr},
    network::Network,
};
fn main() {
    let inbound_handler = Arc::new(Tcp2Netr::new(true, String::from("127.0.0.1:4443")));
    let outbound_handler = Arc::new(Netr2Tcp);
    let net = Network::new(inbound_handler, outbound_handler, 8080);

    // Создаем движок (Runtime)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // "Блокируем" основной поток, пока работает асинхронный код
    rt.block_on(async {
        net.run().await;
    });
}
