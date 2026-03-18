#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod desktop;

#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod mobile;

use crate::{
    RUNTIME, Session,
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
        #[cfg(any(target_os = "android", target_os = "ios"))] // Путь обязателен для мобилок
        tun_fd: Option<i32>,
        #[cfg(any(target_os = "android", target_os = "ios"))] cache_dir: String,
    ) -> Arc<Session> {
        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let sesison_token = cancel_token.clone();
        let net_token = cancel_token.clone();

        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let remote_proxy_ip = addr.ip().to_string();

        runtime.spawn(async move {
            info!("Starting VPN session thread...");

            let cache_path = {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    cache_dir
                } // Используем путь из мобильного приложения
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    ".".to_string()
                } // На ПК пишем в локальную папку
            };

            let mut dns_handler = DnsHandler::new(&cache_path);
            if let Err(e) = dns_handler.init().await {
                error!("Failed to initialize DNS blocklist: {}", e);
            }

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
            caps.max_transmission_unit = 1280;
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

            let mut engine = Engine::new(config, caps, proxy_ip, dns_handler);
            engine.set_any_ip(true);
            engine.set_transparent_mode();
            engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
            engine.activate();

            let cancel_token_for_engine = cancel_token.clone();
            std::thread::spawn(move || {
                info!("Dedicated OS thread started for Engine");

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    tokio::select! {
                        res = engine.run(tun_device) => {
                            error!("Engine loop error: {:?}", res);
                        },
                        _ = cancel_token_for_engine.cancelled() => {
                            info!("Engine thread shutting down via token");
                        }
                    }
                });
            });
        });

        Arc::new(Session {
            cancel_token: sesison_token,
            proxy_ip: remote_proxy_ip,
        })
    }
}
