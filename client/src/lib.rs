use uniffi;
uniffi::setup_scaffolding!();

mod net;
mod tun;
pub use crate::tun::{routing, tun::Tun};

use crate::{
    net::engine::{EngineBuilder, EngineConfig},
    tun::routing::reset_platform_routing,
};
use netrunner_core::net::ConnectionRole;
use netrunner_core::net::network::Network;
use netrunner_logger::{error, info};
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

pub static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

// ==========================================
// SESSION
// ==========================================

#[derive(uniffi::Object)]
pub struct Session {
    pub(crate) cancel_token: CancellationToken,
    pub(crate) proxy_ip: String,
}

#[uniffi::export]
impl Session {
    pub fn stop(&self) {
        info!("Stopping session...");
        self.cancel_token.cancel();
        let _ = reset_platform_routing(Some(&self.proxy_ip));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        info!("Session dropped, stopping all tasks...");
        self.cancel_token.cancel();
        let _ = reset_platform_routing(Some(&self.proxy_ip));
    }
}

// ==========================================
// SESSION MANAGER
// ==========================================

#[derive(uniffi::Object)]
pub struct SessionManager;

#[uniffi::export]
impl SessionManager {
    pub(crate) fn spawn_session(
        &self,
        remote_address: String,
        tun_fd: Option<i32>,
        cache_dir: String,
    ) -> Arc<Session> {
        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let session_token = cancel_token.clone();

        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let remote_proxy_ip = addr.ip().to_string();

        let mut config = EngineConfig::new(&remote_address).with_cache_path(&cache_dir);

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            config = config.disable_routing().with_mtu(1280);
        }

        #[cfg(target_os = "linux")]
        {
            config = config.with_mtu(1350);
        }

        // --- 1. ЗАПУСК ЛОКАЛЬНОГО ПРОКСИ (NETWORK) ---
        let local_proxy_port = 8080;
        let local_proxy_host = "127.0.0.1".to_string();
        let proxy_token = cancel_token.clone();
        let remote_addr_clone = remote_address.clone();

        runtime.spawn(async move {
            info!(
                "Starting Local Proxy (Network) on {}:{}",
                local_proxy_host, local_proxy_port
            );

            let network = Network::new(
                local_proxy_host,
                local_proxy_port,
                ConnectionRole::Client,
                Some(remote_addr_clone),
            );

            // Оборачиваем в tokio::select! для жесткой отмены
            tokio::select! {
                _ = network.run(proxy_token.clone()) => {
                    info!("Local Proxy (Network) task finished normally.");
                }
                _ = proxy_token.cancelled() => {
                    info!("Local Proxy (Network) task forcefully stopped via CancellationToken.");
                }
            }
        });

        // Даем прокси немного времени на бинд порта
        std::thread::sleep(std::time::Duration::from_millis(100));

        // --- 2. ЗАПУСК ENGINE И TUN ---
        let engine_token = cancel_token.clone();
        runtime.spawn(async move {
            info!("Starting VPN Engine thread...");

            let tun_device = {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    Tun::from_fd(tun_fd.expect("TUN FD required on mobile"))
                        .expect("Failed to init TUN from FD")
                }
                #[cfg(target_os = "linux")]
                {
                    Tun::create(|tun_cfg| {
                        tun_cfg
                            .tun_name("netr0")
                            .address((10, 0, 0, 1))
                            .netmask((255, 255, 255, 0))
                            .mtu(config.mtu as u16)
                            .up();
                    })
                    .expect("Failed to init TUN")
                }
                #[cfg(target_os = "windows")]
                {
                    Tun::create(|tun_cfg| {
                        tun_cfg.tun_name("netr0");
                    })
                    .expect("Failed to init TUN")
                }
            };

            let builder_result = EngineBuilder::new(config)
                .with_tun(tun_device)
                .build()
                .await;

            match builder_result {
                Ok((mut engine, tun)) => {
                    info!("Engine async task started");
                    tokio::select! {
                        res = engine.run(tun) => {
                            info!("Engine loop finished: {:?}", res);
                        },
                        _ = engine_token.cancelled() => {
                            info!("Engine task shutting down via token");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to build VPN Engine: {}", e);
                }
            }
        });

        Arc::new(Session {
            cancel_token: session_token,
            proxy_ip: remote_proxy_ip,
        })
    }
}
