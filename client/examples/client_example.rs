use netrunner_common::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
fn main() {
    logger_init();
    //todo normal address
    let net = Network::new(8080, ConnectionRole::Client, Some("0.0.0.0:4443".into()));

    // Создаем движок (Runtime)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // "Блокируем" основной поток, пока работает асинхронный код
    rt.block_on(async {
        net.run().await;
    });
}
