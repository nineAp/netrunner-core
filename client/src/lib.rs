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
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU8, Ordering},
};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

/// Числовые коды состояния подключения (см. [`CONNECTION_STATE`]).
pub const CONN_IDLE: u8 = 0;
pub const CONN_CONNECTING: u8 = 1;
pub const CONN_CONNECTED: u8 = 2;
pub const CONN_FAILED: u8 = 3;

/// Состояние текущей/последней попытки подключения.
///
/// Движок поднимается в отдельной tokio-задаче ([`SessionManager::spawn_session`]),
/// поэтому её отказ (нет прав на TUN, не удалось поднять туннель и т.п.) раньше
/// «терялся»: приложение оптимистично показывало `connected`, а из-за
/// `panic = "abort"` в release-профиле приложения любой `panic` в этой задаче
/// вообще ронял процесс. Теперь задача не паникует, а публикует сюда исход,
/// который desktop-плагин опрашивает и превращает в статус UI.
pub static CONNECTION_STATE: AtomicU8 = AtomicU8::new(CONN_IDLE);

/// Снимок [`CONNECTION_STATE`] для приложения/плагина.
pub fn connection_state() -> u8 {
    CONNECTION_STATE.load(Ordering::Relaxed)
}

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
    ///
    /// `sni` — домен-декой для `ClientHello` этого сервера; приложение берёт
    /// его из [`known_servers`] по выбранному `remote_address` (в будущем —
    /// из бэкенда вместе с остальными полями узла).
    pub fn spawn_session(
        &self,
        remote_address: String,
        sni: String,
        _tun_fd: Option<i32>,
        cache_dir: String,
        killswitch_enabled: bool,
        excluded_apps: Vec<String>,
        excluded_domains: Vec<String>,
        auth_token: Option<String>,
    ) -> Arc<Session> {
        netrunner_logger::Logger::init(None, false);
        netrunner_logger::Logger::global().set_level("error");

        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let session_token = cancel_token.clone();

        // Начинаем попытку подключения — сбрасываем прошлый исход.
        CONNECTION_STATE.store(CONN_CONNECTING, Ordering::Relaxed);

        let remote_proxy_ip = match remote_address.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr.ip().to_string(),
            Err(e) => {
                // Раньше был `.expect(...)` в вызывающем потоке — с panic=abort
                // это ронял всё приложение. Отдаём неактивную сессию и failed.
                error!("Invalid remote address '{}': {}", remote_address, e);
                CONNECTION_STATE.store(CONN_FAILED, Ordering::Relaxed);
                return Arc::new(Session {
                    cancel_token: session_token,
                    proxy_ip: String::new(),
                    killswitch_enabled,
                });
            }
        };

        let mut config = EngineConfig::new(&remote_address)
            .with_cache_path(&cache_dir)
            .with_killswitch(killswitch_enabled)
            .with_excluded_apps(excluded_apps)
            .with_excluded_domains(excluded_domains)
            .with_decoy_sni(sni)
            .with_auth_token(auth_token);

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

            // TUN создаётся привилегированной операцией (TUNSETIFF, нужен
            // CAP_NET_ADMIN/root). Раньше здесь стоял `.expect(...)`, и на
            // десктопе без прав он паниковал → panic=abort → всё приложение
            // падало ровно «при попытке подключиться». Теперь обрабатываем
            // отказ штатно и публикуем CONN_FAILED.
            let tun_result: std::io::Result<Tun> = {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    match _tun_fd {
                        Some(fd) => Tun::from_fd(fd),
                        None => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "TUN FD required on mobile",
                        )),
                    }
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
                }
                #[cfg(target_os = "windows")]
                {
                    Tun::create(|tun_cfg| {
                        tun_cfg.tun_name("netr0");
                    })
                }
            };

            let tun_device = match tun_result {
                Ok(tun) => tun,
                Err(e) => {
                    error!(
                        "Failed to create TUN device (нужны права CAP_NET_ADMIN/root?): {}",
                        e
                    );
                    CONNECTION_STATE.store(CONN_FAILED, Ordering::Relaxed);
                    return;
                }
            };

            let builder_result = EngineBuilder::new(config)
                .with_tun(tun_device)
                .build()
                .await;

            match builder_result {
                Ok((mut engine, tun)) => {
                    info!("Engine built successfully, starting loop...");
                    CONNECTION_STATE.store(CONN_CONNECTED, Ordering::Relaxed);

                    tokio::select! {
                        _ = engine.run(tun) => {
                            info!("Engine loop finished normally.");
                        },
                        _ = engine_token.cancelled() => {
                            info!("Engine task shutting down via token");
                        }
                    }
                    // Цикл завершился (штатно или по отмене) — больше не connected.
                    CONNECTION_STATE.store(CONN_IDLE, Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed to build VPN Engine: {}", e);
                    CONNECTION_STATE.store(CONN_FAILED, Ordering::Relaxed);
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
