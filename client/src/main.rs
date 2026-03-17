use std::net::Ipv4Addr;

use netrunner_client::{
    connections::dns::DnsHandler,
    tun::{
        engine::Engine,
        routing::{reset_platform_routing, setup_platform_routing},
        tun::Tun,
    },
};
use netrunner_core::proxy::{connection::connection::ConnectionRole, network::Network};
use netrunner_logger::{error, info};
use smoltcp::{iface::Config, phy::DeviceCapabilities};
use tokio_util::sync::CancellationToken;
// Убираем макрос #[tokio::main]
fn main() -> anyhow::Result<()> {
    netrunner_logger::Logger::init();
    info!("Initializing NetRunner Stack...");

    // 1. СИНХРОННАЯ ЧАСТЬ
    // Здесь reqwest::blocking может спокойно создавать и удалять свои ресурсы
    let mut dns_handler = DnsHandler::new();
    if let Err(e) = dns_handler.init() {
        error!("Failed to initialize DNS blocklist: {}", e);
    }

    // 2. АСИНХРОННАЯ ЧАСТЬ
    // Создаем рантайм вручную
    let rt = tokio::runtime::Runtime::new()?;

    // Передаем управление в асинхронный блок
    rt.block_on(async move {
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
        setup_platform_routing(&remote_address);

        info!("TUN interface is UP: 10.0.0.1/24");

        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1280;
        caps.medium = smoltcp::phy::Medium::Ip;

        let network = Network::new(
            "0.0.0.0".into(),
            8080,
            ConnectionRole::Client,
            Some(remote_address.clone()),
        );

        let proxy_ip = network.get_self_local_address();

        // Запускаем сетевой поток
        let network_token = CancellationToken::new();
        tokio::spawn(async move {
            info!("Network thread started");
            network.run(network_token).await;
        });

        // Создаем Engine и передаем уже готовый dns_handler
        let mut engine = Engine::new(config, caps, proxy_ip, dns_handler);
        engine.set_any_ip(true);
        engine.set_transparent_mode();
        engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
        engine.activate();

        info!("Stack IP initialized: 10.0.0.2");
        info!("Engine starting process loop...");

        let ctrl_c = tokio::signal::ctrl_c();

        tokio::select! {
            res = engine.run(tun_device) => {
                error!("Engine loop error: {:?}", res);
            },
            _ = ctrl_c => {
                info!("Ctrl+C received, shutting down...");
            }
        }

        // Очистка при выходе
        info!("Restoring system routing...");
        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let p_ip = addr.ip().to_string();
        if let Err(e) = reset_platform_routing(Some(&p_ip)) {
            error!("Failed to reset routing: {}", e);
        } else {
            info!("System routing restored successfully.");
        }

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}
