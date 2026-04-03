use netrunner_core::net::NetworkConfig;
use uniffi;
uniffi::setup_scaffolding!();

mod net;
mod tun;
pub use crate::tun::{routing, tun::Tun};

use crate::{
    net::engine::{EngineBuilder, EngineConfig},
    tun::{
        device::{GLOBAL_RX_BYTES, GLOBAL_RX_PACKETS, GLOBAL_TX_BYTES, GLOBAL_TX_PACKETS},
        routing::reset_platform_routing,
    },
};
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

#[derive(uniffi::Record)]
pub struct VpnTrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
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
    pub fn new() -> Arc<Self> {
        Arc::new(SessionManager)
    }

    pub fn spawn_session(
        &self,
        remote_address: String,
        tun_fd: Option<i32>,
        cache_dir: String,
    ) -> Arc<Session> {
        netrunner_logger::Logger::init(None);
        netrunner_logger::Logger::global().set_level("info");

        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let session_token = cancel_token.clone();

        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let remote_proxy_ip = addr.ip().to_string();

        let mut config = EngineConfig::new(&remote_address).with_cache_path(&cache_dir);

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            config = config.disable_routing().with_mtu(1380);
        }

        #[cfg(target_os = "linux")]
        {
            config = config.with_mtu(1380);
        }

        NetworkConfig::init_global(config.mtu);

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
                    info!("Engine built successfully, starting loop...");

                    tokio::select! {
                        _ = engine.run(tun) => {
                            info!("Engine loop finished normally.");
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
    pub fn get_traffic_stats(&self) -> VpnTrafficStats {
        VpnTrafficStats {
            rx_bytes: GLOBAL_RX_BYTES.load(std::sync::atomic::Ordering::Relaxed),
            tx_bytes: GLOBAL_TX_BYTES.load(std::sync::atomic::Ordering::Relaxed),
            rx_packets: GLOBAL_RX_PACKETS.load(std::sync::atomic::Ordering::Relaxed),
            tx_packets: GLOBAL_TX_PACKETS.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}
