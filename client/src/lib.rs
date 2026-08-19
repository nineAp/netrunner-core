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
uniffi::setup_scaffolding!();

mod net;
mod tun;
pub use crate::tun::{routing, tun::Tun};

use crate::{
    net::engine::{EngineBuilder, EngineConfig},
    tun::{
        device::{GLOBAL_RX_BYTES, GLOBAL_RX_PACKETS, GLOBAL_TX_BYTES, GLOBAL_TX_PACKETS},
        routing::{TunnelMode, reset_platform_routing},
    },
};
use netrunner_logger::{error, info};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU8, AtomicU64, Ordering},
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

/// Номер последней запущенной сессии. [`CONNECTION_STATE`] — глобальное
/// состояние процесса, а сессий за время жизни процесса много, и они
/// ПЕРЕСЕКАЮТСЯ во времени: приложение поднимает новую (переподключение,
/// смена ноды, рестарт сервиса системой) раньше, чем задача старой успела
/// доработать после отмены.
///
/// Без этого счётчика доигрывающая старая задача записывала свой финальный
/// `CONN_IDLE` поверх `CONN_CONNECTED` уже работающей новой сессии. На
/// Android это не косметика: сервис глушит туннель на любом статусе, кроме
/// рабочего (см. `startStatsLoop` в VpnPlugin.kt), — то есть живой туннель
/// убивал себя сам через какое-то время после переподключения.
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Публикует состояние, только если сессия `generation` всё ещё актуальна.
///
/// Возвращает `true`, если запись состоялась (нужно тестам и логам: «моя
/// сессия уже не последняя» — штатная ситуация, а не ошибка).
fn publish_state(generation: u64, state: u8) -> bool {
    if SESSION_GENERATION.load(Ordering::SeqCst) != generation {
        return false;
    }
    CONNECTION_STATE.store(state, Ordering::Relaxed);
    true
}

/// Снимок [`CONNECTION_STATE`] для приложения/плагина.
pub fn connection_state() -> u8 {
    CONNECTION_STATE.load(Ordering::Relaxed)
}

/// То же самое, но экспортировано через UniFFI для Kotlin/Swift (десктопный
/// плагин — тот же Rust-крейт, поэтому дёргает [`connection_state`] напрямую;
/// мобильным приложениям через FFI-границу нужна явно экспортированная
/// функция). Возвращает строку вместо магических чисел, чтобы не дублировать
/// маппинг `CONN_*` в каждом биндинге — тот же набор строк, что и в
/// `desktop.rs`: "idle" | "connecting" | "connected" | "failed".
#[uniffi::export]
pub fn connection_status_string() -> String {
    match connection_state() {
        CONN_CONNECTED => "connected",
        CONN_CONNECTING => "connecting",
        CONN_FAILED => "failed",
        _ => "idle",
    }
    .to_string()
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
/// Строка политики организации → [`TunnelMode`].
///
/// Неизвестное и отсутствующее значение — [`TunnelMode::All`], то есть прежнее
/// поведение. Это не «на всякий случай»: приложение старее бэкенда увидит
/// режим, которого не знает, и должно повести себя как обычный VPN, а не
/// оставить сотрудника без сети, отказавшись подключаться.
fn parse_tunnel_mode(raw: Option<&str>) -> TunnelMode {
    match raw {
        Some("resources") => TunnelMode::Resources,
        Some("bypass_lan") => TunnelMode::BypassLan,
        Some("all") | None => TunnelMode::All,
        Some(other) => {
            netrunner_logger::warn!("Неизвестный режим туннеля {:?} — работаем как all", other);
            TunnelMode::All
        }
    }
}

#[cfg(test)]
mod session_state_tests {
    use super::*;

    /// Ровно тот сценарий, из-за которого туннель умирал «сам собой» через
    /// время: приложение подняло новую сессию, а задача предыдущей (уже
    /// отменённой) доигрывает и публикует свой финальный статус.
    ///
    /// Тест один на весь модуль сознательно: состояние здесь глобальное на
    /// процесс, и два таких теста в параллельном раннере мешали бы друг другу.
    #[test]
    fn stale_session_cannot_overwrite_a_newer_one() {
        let old = SESSION_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(publish_state(old, CONN_CONNECTED));

        // Переподключение: приложение стартует новую сессию.
        let current = SESSION_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(publish_state(current, CONN_CONNECTED));

        // Старая задача просыпается по отмене и хочет записать свой исход.
        assert!(
            !publish_state(old, CONN_IDLE),
            "устаревшая сессия не должна публиковать статус"
        );
        assert_eq!(
            connection_state(),
            CONN_CONNECTED,
            "живая сессия осталась подключённой"
        );

        // А актуальная — может.
        assert!(publish_state(current, CONN_IDLE));
        assert_eq!(connection_state(), CONN_IDLE);
    }
}

#[cfg(test)]
mod tunnel_mode_tests {
    use super::*;

    #[test]
    fn known_modes_map_directly() {
        assert_eq!(parse_tunnel_mode(Some("resources")), TunnelMode::Resources);
        assert_eq!(parse_tunnel_mode(Some("bypass_lan")), TunnelMode::BypassLan);
        assert_eq!(parse_tunnel_mode(Some("all")), TunnelMode::All);
    }

    /// Главное свойство: клиент старее бэкенда не должен ломаться о режим,
    /// про который он ещё не знает.
    #[test]
    fn unknown_and_missing_fall_back_to_full_tunnel() {
        assert_eq!(parse_tunnel_mode(None), TunnelMode::All);
        assert_eq!(parse_tunnel_mode(Some("")), TunnelMode::All);
        assert_eq!(parse_tunnel_mode(Some("site_to_site")), TunnelMode::All);
    }
}

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
    ///
    /// `node_secret` и `node_public_key` — учётные данные выбранной ноды из
    /// списка серверов, который приложение получило от бэкенда (поля
    /// `nrxp_secret` и `nrxp_public_key`, hex по 64 символа). Переданы оба —
    /// хендшейк аутентифицированный: клиент проверяемо отличает свою ноду от
    /// чужой. Не переданы — старый анонимный хендшейк, для нод, которым в
    /// админке ещё не завели ключи.
    #[allow(clippy::too_many_arguments)]
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
        node_secret: Option<String>,
        node_public_key: Option<String>,
        tunnel_mode: Option<String>,
        routed_cidrs: Vec<String>,
    ) -> Arc<Session> {
        // На мобильных Logger::init здесь — первый и единственный вызов (нет
        // отдельного main.rs), поэтому production-флаг должен зависеть от
        // профиля сборки, а не быть жёстко `false` (иначе релизная сборка
        // печатала дев-баннер "Mode: DEBUG" вместо тихого JSON-лога).
        netrunner_logger::Logger::init(None, !cfg!(debug_assertions));
        netrunner_logger::Logger::global().set_level("error");

        let runtime = get_runtime();
        let cancel_token = CancellationToken::new();
        let session_token = cancel_token.clone();

        // Начинаем попытку подключения — сбрасываем прошлый исход. Заодно
        // объявляем себя последней сессией: всё, что успеет дописать
        // предыдущая (она могла быть отменена мгновение назад и ещё
        // доигрывает), с этого момента отбрасывается — см. SESSION_GENERATION.
        let generation = SESSION_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        publish_state(generation, CONN_CONNECTING);

        let remote_proxy_ip = match remote_address.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr.ip().to_string(),
            Err(e) => {
                // Раньше был `.expect(...)` в вызывающем потоке — с panic=abort
                // это ронял всё приложение. Отдаём неактивную сессию и failed.
                error!("Invalid remote address '{}': {}", remote_address, e);
                publish_state(generation, CONN_FAILED);
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
            .with_auth_token(auth_token)
            .with_node_credentials(node_secret, node_public_key)
            .with_tunnel_mode(parse_tunnel_mode(tunnel_mode.as_deref()), routed_cidrs);

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
                    // См. docstring cleanup_stale_adapter: без этого падаем на
                    // "WintunStartSession failed ... уже проведена (0x4DF)",
                    // если предыдущий процесс убили без штатного завершения.
                    crate::tun::tun::cleanup_stale_adapter("netr0");
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
                    publish_state(generation, CONN_FAILED);
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
                    publish_state(generation, CONN_CONNECTED);

                    // Исход цикла различается по причине, и это важно: движок,
                    // завершившийся САМ, — это отказ (мёртвый туннель, отвергнутый
                    // токен), а не штатная остановка. Раньше оба случая давали
                    // CONN_IDLE, и Android-сервис, который глушит VPN только на
                    // "failed", в первом случае продолжал держать интерфейс и
                    // показывать «подключено» (см. startStatsLoop в VpnPlugin.kt).
                    let mut engine_failed = false;
                    tokio::select! {
                        _ = engine.run(tun) => {
                            error!("Engine loop finished on its own — tunnel is dead");
                            engine_failed = true;
                        },
                        _ = engine_token.cancelled() => {
                            info!("Engine task shutting down via token");
                        }
                    }
                    let outcome = if engine_failed { CONN_FAILED } else { CONN_IDLE };
                    // Только если эта сессия всё ещё последняя: иначе мы бы
                    // погасили статус УЖЕ РАБОТАЮЩЕЙ новой сессии, а Android
                    // на этом глушит живой туннель (см. SESSION_GENERATION).
                    if !publish_state(generation, outcome) {
                        info!(
                            "Session generation {generation} finished after a newer one started — статус не трогаем"
                        );
                    }
                }
                Err(e) => {
                    error!("Failed to build VPN Engine: {}", e);
                    publish_state(generation, CONN_FAILED);
                }
            }
        });

        Arc::new(Session {
            cancel_token: session_token,
            proxy_ip: remote_proxy_ip,
            killswitch_enabled,
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
