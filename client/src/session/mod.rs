#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod desktop;

#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod mobile;

use crate::{
    RUNTIME, Session,
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
use std::sync::Arc;
use tokio::{runtime::Runtime, signal};
use tokio_util::sync::CancellationToken;

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

#[derive(uniffi::Object)]
pub struct SessionManager;

#[uniffi::export]
impl SessionManager {
    #[uniffi::constructor]
    pub fn new() -> Self {
        netrunner_logger::Logger::init();
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
        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let sesison_token = cancel_token.clone();
        let net_token = cancel_token.clone();
        let shutdown_signal = signal::ctrl_c();

        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let remote_proxy_ip = addr.ip().to_string();
        let proxy_ip_for_thread = remote_proxy_ip.clone();

        runtime.spawn(async move {
            info!("Starting VPN session thread...");

            let tun_device = {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    Tun::from_fd(tun_fd.expect("TUN FD required on mobile"))
                        .expect("Failed to init TUN from FD")
                }
                #[cfg(target_os = "linux")]
                {
                    Tun::create(|config| {
                        config
                            .tun_name("netr0")
                            .address((10, 0, 0, 1))
                            .netmask((255, 255, 255, 0))
                            .mtu(1200)
                            .up();
                    })
                    .expect("Failed to init TUN")
                }
                #[cfg(target_os = "windows")]
                {
                    Tun::create(|config| {
                        config.tun_name("netr0");
                    })
                    .expect("Failed to init TUN")
                }
            };

            setup_platform_routing(&remote_address);

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

            tokio::spawn(async move {
                network.run(net_token).await;
            });

            let mut engine = Engine::new(config, caps, proxy_ip);
            engine.set_any_ip(true);
            engine.set_transparent_mode();
            engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
            engine.activate();

            tokio::select! {
                res = engine.run(tun_device) => error!("Engine loop error: {:?}", res),
                _ = cancel_token.cancelled() => {
                    info!("Shutdown signal received");

                    let _ = reset_platform_routing(Some(&proxy_ip_for_thread));
                },
                _ = shutdown_signal => {
                    cancel_token.cancel();
                }
            }
        });

        Arc::new(Session {
            cancel_token: sesison_token,
            proxy_ip: remote_proxy_ip,
        })
    }
}
