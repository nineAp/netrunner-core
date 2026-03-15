use std::net::Ipv4Addr;

use netrunner_client::tun::{
    engine::Engine,
    routing::{reset_platform_routing, setup_platform_routing},
    tun::Tun,
};
use netrunner_core::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
use smoltcp::{iface::Config, phy::DeviceCapabilities};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    logger_init();
    info!("Initializing NetRunner Stack...");
    let tun_device = Tun::create(|config| {
        config
            .tun_name("netr0")
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 2))
            .up();
    })
    .expect("Failed to initialize TUN device");
    let remote_address: String = "62.60.244.156:443".into();
    setup_platform_routing(&remote_address).expect("Failed to setup routing");

    info!("TUN interface is UP: 10.0.0.1/24");

    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);

    let mut caps = DeviceCapabilities::default();

    caps.max_transmission_unit = 1500;
    caps.medium = smoltcp::phy::Medium::Ip;

    let network = Network::new(
        "0.0.0.0".into(),
        8080,
        ConnectionRole::Client,
        Some(remote_address),
    );

    let proxy_ip = network.get_self_local_address();

    tokio::spawn(async move {
        info!("Network thread started");
        network.run().await;
    });

    let mut engine = Engine::new(config, caps, proxy_ip);
    engine.set_any_ip(true);
    engine.set_transparent_mode();
    engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
    engine.activate();
    info!("Stack IP initialized: 10.0.0.2");

    info!("Engine starting process loop...");

    // 3. Используем select для перехвата сигнала завершения
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        res = engine.run(tun_device) => {
            error!("Engine loop error: {:?}", res);
        },
        _ = ctrl_c => {
            info!("Ctrl+C received, shutting down...");
        }
    }

    // 4. ГАРАНТИРОВАННЫЙ СБРОС
    info!("Restoring system routing...");
    if let Err(e) = reset_platform_routing() {
        error!("Failed to reset routing: {}", e);
    } else {
        info!("System routing restored successfully.");
    }
}
