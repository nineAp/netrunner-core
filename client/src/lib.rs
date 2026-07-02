//! # netrunner-client — клиент VPN и FFI-фасад для приложений
//!
//! Крейт собирается двумя способами: как библиотека (`.so`) для мобильных
//! приложений через **UniFFI** (этот файл) и как самостоятельный бинарь для
//! Linux ([`main.rs`](crate)). Вся реальная логика — в подмодулях:
//!
//! - [`net`] — userspace TCP/IP-стек на smoltcp и мост в туннель ядра;
//! - [`tun`] — TUN-устройство, smoltcp-`Device` и системная маршрутизация.
//!
//! ## FFI-поверхность (что видит Kotlin/Swift)
//!
//! - [`SessionManager`] — фабрика сессий: [`spawn_session`](SessionManager::spawn_session)
//!   поднимает движок в фоне и возвращает управляемую [`Session`]; [`get_traffic_stats`](SessionManager::get_traffic_stats)
//!   отдаёт счётчики.
//! - [`Session`] — ручка живого VPN; [`stop`](Session::stop) (и `Drop`) гасит
//!   задачи и откатывает маршрутизацию.
//! - [`VpnTrafficStats`] — снимок трафика для UI.
//!
//! Токио-рантайм создаётся один раз ([`RUNTIME`]) и переживёт все сессии.

// Workaround for rustc 1.94 ICE in check_mod_deathness (dead-code MIR pass).
#![allow(dead_code)]

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

/// Глобальный многопоточный tokio-рантайм, общий для всех сессий.
pub static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Ленивая инициализация общего рантайма (создаётся при первом обращении).
fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

/// Снимок счётчиков трафика для отображения в приложении.
#[derive(uniffi::Record)]
pub struct VpnTrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Ручка одной живой VPN-сессии (передаётся в приложение как объект UniFFI).
///
/// Хранит токен отмены и данные для отката маршрутизации. Останавливается явно
/// ([`stop`](Session::stop)) или автоматически при `Drop`.
#[derive(uniffi::Object)]
pub struct Session {
    pub(crate) cancel_token: CancellationToken,
    pub(crate) proxy_ip: String,
    pub(crate) killswitch_enabled: bool,
}

#[uniffi::export]
impl Session {
    pub fn stop(&self) {
        info!("Stopping session...");
        self.cancel_token.cancel();
        let _ = reset_platform_routing(Some(&self.proxy_ip), self.killswitch_enabled);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        info!("Session dropped, stopping all tasks...");
        self.cancel_token.cancel();
        let _ = reset_platform_routing(Some(&self.proxy_ip), self.killswitch_enabled);
    }
}

/// Фабрика VPN-сессий — главная точка входа FFI.
#[derive(uniffi::Object)]
pub struct SessionManager;

#[uniffi::export]
impl SessionManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(SessionManager)
    }

    /// Поднимает VPN-сессию в фоне и возвращает управляющую [`Session`].
    ///
    /// Создаёт TUN (из переданного `_tun_fd` на мобильных или сам на Linux),
    /// конфигурирует движок (MTU, kill-switch, исключения) и запускает его в
    /// общем рантайме под токеном отмены. Не блокирует вызывающий поток.
    pub fn spawn_session(
        &self,
        remote_address: String,
        _tun_fd: Option<i32>,
        cache_dir: String,
        killswitch_enabled: bool,
        excluded_apps: Vec<String>,
        excluded_domains: Vec<String>,
    ) -> Arc<Session> {
        netrunner_logger::Logger::init(None, false);
        netrunner_logger::Logger::global().set_level("error");

        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let session_token = cancel_token.clone();

        let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
        let remote_proxy_ip = addr.ip().to_string();

        let mut config = EngineConfig::new(&remote_address)
            .with_cache_path(&cache_dir)
            .with_killswitch(killswitch_enabled)
            .with_excluded_apps(excluded_apps)
            .with_excluded_domains(excluded_domains);

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            config = config.disable_routing().with_mtu(1450);
        }

        #[cfg(target_os = "linux")]
        {
            config = config.with_mtu(1450);
        }

        NetworkConfig::init_global(config.mtu);

        let engine_token = cancel_token.clone();
        runtime.spawn(async move {
            info!("Starting VPN Engine thread...");

            let tun_device = {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    Tun::from_fd(_tun_fd.expect("TUN FD required on mobile"))
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
            killswitch_enabled: killswitch_enabled,
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
