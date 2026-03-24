use uniffi;
uniffi::setup_scaffolding!();

mod net;
mod tun;
pub use crate::tun::{routing, tun::Tun}; //for desktop test in main.rs

use crate::{
    net::engine::{EngineBuilder, EngineConfig},
    tun::routing::reset_platform_routing,
};
use netrunner_logger::{error, info};
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

pub static RUNTIME: OnceLock<Runtime> = OnceLock::new();

// Инициализация Tokio Runtime
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
// SESSION MANAGER (Публичный API UniFFI)
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

        // 1. Создаем базовый конфиг
        let mut config = EngineConfig::new(&remote_address).with_cache_path(&cache_dir);

        // 2. Тонкая настройка под платформу
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // На мобилках роутингом обычно управляет VpnService (Android) или NEPacketTunnelProvider (iOS)
            // Поэтому отключаем попытки движка менять системные таблицы роутинга напрямую
            config = config.disable_routing().with_mtu(1280);
        }

        #[cfg(target_os = "linux")]
        {
            config = config.with_mtu(1350);
        }

        runtime.spawn(async move {
            info!("Starting VPN session thread...");

            // 3. Инициализация TUN устройства (специфично для платформ)
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
                            .mtu(config.mtu as u16) // Используем MTU из нашего конфига
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

            // 4. Используем обновленный билдер
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
