#[cfg(feature = "desktop")]
pub mod desktop;

#[cfg(feature = "mobile")]
pub mod mobile;

use crate::{
    Session, get_runtime,
    tun::{
        engine::Engine,
        routing::{reset_platform_routing, setup_platform_routing},
        tun::Tun,
    },
};
use netrunner_core::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
use smoltcp::{iface::Config, phy::DeviceCapabilities};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info};

#[derive(uniffi::Object)]
pub struct SessionManager;

#[uniffi::export]
impl SessionManager {
    #[uniffi::constructor]
    pub fn new() -> Self {
        logger_init();
        info!("SessionManager initialized");
        Self
    }
}

impl SessionManager {
    pub(crate) fn spawn_session(
        &self,
        remote_address: String,
        tun_fd: Option<i32>,
    ) -> Arc<Session> {
        let (tx, rx) = oneshot::channel();
        let runtime = get_runtime();

        let shutdown_signal = signal::ctrl_c();

        runtime.spawn(async move {
            info!("Starting VPN session thread...");

            let tun_device = {
                #[cfg(feature = "mobile")]
                {
                    Tun::from_fd(tun_fd.expect("TUN FD required on mobile"))
                        .expect("Failed to init TUN from FD")
                }
                #[cfg(feature = "desktop")]
                {
                    Tun::create(|config| {
                        config
                            .tun_name("netr0")
                            .address((10, 0, 0, 1))
                            .netmask((255, 255, 255, 0))
                            .up();
                    })
                    .expect("Failed to init TUN")
                }
            };

            setup_platform_routing(&remote_address).expect("Failed to setup routing");

            let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1500;
            caps.medium = smoltcp::phy::Medium::Ip;

            let network = Network::new(
                "0.0.0.0".into(),
                8080,
                ConnectionRole::Client,
                Some(remote_address.clone()),
            );
            let proxy_ip = network.get_self_local_address();

            let net_handle = tokio::spawn(async move {
                network.run().await;
            });

            let mut engine = Engine::new(config, caps, proxy_ip);
            engine.set_any_ip(true);
            engine.set_transparent_mode();
            engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
            engine.activate();

            tokio::select! {
                res = engine.run(tun_device) => error!("Engine loop error: {:?}", res),
                _ = rx => {
                    info!("Shutdown signal received");
                    let _ = reset_platform_routing(); // Очистка при сигнале
                },
                _ = shutdown_signal => {
                    info!("Ctrl+C detected, shutting down gracefully...");
                    info!("Restoring routing...");
                    let _ = reset_platform_routing();
                    net_handle.abort();
                }
            }
        });

        Arc::new(Session {
            shutdown_tx: Mutex::new(Some(tx)),
        })
    }
}
