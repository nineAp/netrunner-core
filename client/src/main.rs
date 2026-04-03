use netrunner_logger::{error, info};
mod net;
mod tun;

use crate::tun::{routing::reset_platform_routing, tun::Tun};
use net::engine::{EngineBuilder, EngineConfig};

use netrunner_core::net::NetworkConfig;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netrunner_logger::Logger::init(None);
    netrunner_logger::Logger::global().set_level("error");
    info!("Initializing NetRunner Stack...");

    let remote_address = "147.45.43.70:443".to_string();
    let cancel_token = CancellationToken::new();

    let config = EngineConfig::new(&remote_address)
        .with_cache_path(".")
        .with_mtu(1500);

    NetworkConfig::init_global(config.mtu);

    let tun_device = Tun::create(|tun_cfg| {
        tun_cfg
            .tun_name("netr0")
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 2))
            .mtu(config.mtu as u16)
            .up();
    })
    .expect("Failed to initialize TUN device");

    info!("TUN interface is UP: 10.0.0.1/24 (MTU: {})", config.mtu);

    let builder_result = EngineBuilder::new(config)
        .with_tun(tun_device)
        .build()
        .await;

    match builder_result {
        Ok((mut engine, tun)) => {
            info!("Engine starting process loop...");

            tokio::select! {
                _res = engine.run(tun) => {
                    info!("Engine loop finished");
                },
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down...");
                    cancel_token.cancel();
                }
            }
        }
        Err(e) => {
            error!("Failed to build VPN Engine: {}", e);
            cancel_token.cancel();
        }
    }

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
