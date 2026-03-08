use std::net::Ipv4Addr;

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
            .tun_name("tun0")
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 2))
            .up();
    })
    .expect("Failed to initialize TUN device");

    tun_device.setup_routing();
    tun_device.setup_dns_redirection();

    info!("TUN interface is UP: 10.0.0.1/24");

    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);

    let mut caps = DeviceCapabilities::default();
    let remote_address: String = "62.60.244.156:443".into();
    caps.max_transmission_unit = 1500;
    caps.medium = smoltcp::phy::Medium::Ip;

    let network = Network::new(
        "0.0.0.0".into(),
        8080,
        ConnectionRole::Client,
        Some(remote_address),
    );

    let proxy_ip = network.get_self_local_address();

    // 2. ВЫНОСИМ СЕТЬ В ОТДЕЛЬНЫЙ ЦИКЛ
    // Это запустит SOCKS5 сервер и TLS туннель параллельно движку
    tokio::spawn(async move {
        info!("Network thread started");
        network.run().await;
    });

    let mut engine = Engine::new(config, caps, proxy_ip);
    engine.set_any_ip(true);
    engine.set_transparent_mode();
    engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2)); // to smoltcp
    engine.activate();
    info!("Stack IP initialized: 10.0.0.2");

    // 5. Запуск
    info!("Engine starting process loop...");
    engine.run(tun_device).await;
}
