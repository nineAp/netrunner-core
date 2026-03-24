use netrunner_client::{
    connections::dns::DnsHandler,
    tun::{
        engine::Engine,
        routing::{reset_platform_routing, setup_platform_routing},
        tun::Tun,
    },
};
use netrunner_core::proxy::connection::connection::ClientHandler;
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

    let remote_address: String = "147.45.43.70:443".into();
    let _ = setup_platform_routing(&remote_address);

    info!("TUN interface is UP: 10.0.0.1/24");

    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
    let mut caps = DeviceCapabilities::default();
    caps.max_transmission_unit = 1350;
    caps.medium = smoltcp::phy::Medium::Ip;

    let network_token = CancellationToken::new();

    info!("Establishing secure tunnel to proxy server...");

    let muxer = match ClientHandler::connect(&remote_address).await {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to establish secure tunnel to server: {}", e);
            return Err(anyhow::anyhow!("Failed to establish secure tunnel: {}", e));
        }
    };
    info!("Secure tunnel established, Muxer is ready.");

    let mut engine = Engine::new(config, caps, dns_handler, muxer);
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
    };

    Ok(())
}
