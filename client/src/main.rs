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
use std::net::Ipv4Addr;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netrunner_logger::Logger::init();
    info!("Initializing NetRunner Stack...");

    let mut dns_handler = DnsHandler::new(".");
    if let Err(e) = dns_handler.init().await {
        error!("Failed to initialize DNS blocklist: {}", e);
    }

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

    let network_token = CancellationToken::new();
    let net_token_for_spawn = network_token.clone();
    tokio::spawn(async move {
        info!("Network thread started");
        network.run(net_token_for_spawn).await;
    });

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

    network_token.cancel();
    info!("Restoring system routing...");
    let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
    let p_ip = addr.ip().to_string();

    if let Err(e) = reset_platform_routing(Some(&p_ip)) {
        error!("Failed to restore routing: {}", e);
    } else {
        info!("System routing restored successfully.");
    }

    Ok(())
}
