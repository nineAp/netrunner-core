use netrunner_client::{tun::engine::Engine, tun::tun::Tun};
use netrunner_common::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
use smoltcp::{iface::Config, phy::DeviceCapabilities};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // 1. Инициализируем систему логирования
    logger_init();
    info!("Initializing NetRunner Stack...");
    let tun_device = Tun::create(|config| {
        config
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .up();
    })
    .expect("Failed to initialize TUN device");

    info!("TUN interface is UP: 10.0.0.1/24");

    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);

    let mut caps = DeviceCapabilities::default();
    let remote_address: String = "127.0.0.1:4443".into();
    caps.max_transmission_unit = 1500;
    caps.medium = smoltcp::phy::Medium::Ip;

    let network = Network::new(8080, ConnectionRole::Client, Some(remote_address));

    let socks_addr = network.get_self_local_address();

    // 2. ВЫНОСИМ СЕТЬ В ОТДЕЛЬНЫЙ ЦИКЛ
    // Это запустит SOCKS5 сервер и TLS туннель параллельно движку
    tokio::spawn(async move {
        info!("Network thread started");
        network.run().await;
    });

    let mut engine = Engine::new(config, caps, socks_addr);

    engine.add_address(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::v4(10, 0, 0, 2),
        24,
    ));

    info!("Stack IP initialized: 10.0.0.2");

    // 5. Запуск
    info!("Engine starting process loop...");
    engine.run(tun_device).await;
}
