use crate::{
    RUNTIME,
    tun::{engine::EngineBuilder, routing::reset_platform_routing, tun::Tun},
};
use netrunner_logger::{error, info};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod desktop;

#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod mobile;

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
        #[cfg(any(target_os = "android", target_os = "ios"))] tun_fd: Option<i32>,
        #[cfg(any(target_os = "android", target_os = "ios"))] cache_dir: String,
    ) -> Arc<Session> {
        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let session_token = cancel_token.clone();

        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let remote_proxy_ip = addr.ip().to_string();

        runtime.spawn(async move {
            info!("Starting VPN session thread...");

            let cache_path = {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    cache_dir
                }
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    ".".to_string()
                }
            };

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
                            .mtu(1350)
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

            let builder_result = EngineBuilder::new(&remote_address)
                .with_cache_path(&cache_path)
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
                        _ = cancel_token.cancelled() => {
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
