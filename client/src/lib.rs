uniffi::setup_scaffolding!();
pub mod connections;
pub mod tun;
use std::sync::{Arc, Mutex};

use netrunner_core::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
use smoltcp::{iface::Config, phy::DeviceCapabilities};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tracing::{error, info};
pub mod platform;

use crate::{
    platform::setup_platform_routing,
    tun::{engine::Engine, tun::Tun},
};
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

#[derive(uniffi::Object)]
pub struct Session {
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Session {
    pub fn stop(&self) {
        let mut guard = self.shutdown_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }
}

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

    pub fn start(&self, remote_address: String, tun_fd: Option<i32>) -> Arc<Session> {
        let (tx, rx) = oneshot::channel();
        let runtime = get_runtime();
        runtime.spawn(async move {
            info!("Starting VPN session thread...");

            let tun_device = if let Some(fd) = tun_fd {
                info!("Using provided FD for TUN: {}", fd);
                Tun::from_android_fd(fd).expect("Failed to init TUN from FD")
            } else {
                info!("Creating TUN device manually");
                Tun::create(|config| {
                    config.tun_name("tun0").address((10, 0, 0, 1)).up();
                })
                .expect("Failed to init TUN")
            };

            setup_platform_routing(&tun_device, &remote_address);

            let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1500;
            caps.medium = smoltcp::phy::Medium::Ip;

            info!("Initializing Network with remote: {}", remote_address);
            let network = Network::new(
                "0.0.0.0".into(),
                8080,
                ConnectionRole::Client,
                Some(remote_address),
            );

            let proxy_ip = network.get_self_local_address();
            info!("Proxy self address: {:?}", proxy_ip);

            let net_handle = tokio::spawn(async move {
                network.run().await;
            });

            info!("Configuring Engine...");

            let mut engine = Engine::new(config, caps, proxy_ip);
            engine.set_any_ip(true);
            engine.set_transparent_mode();
            engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
            engine.activate();

            info!("Engine activated");

            tokio::select! {
                res = engine.run(tun_device) => {
                    error!("Engine loop terminated unexpectedly: {:?}", res);
                }
                _ = rx => {
                    info!("Shutdown signal received. Cleaning up...");
                }
            }

            net_handle.abort();
            info!("VPN session fully stopped.");
        });

        Arc::new(Session {
            shutdown_tx: Mutex::new(Some(tx)),
        })
    }
}
