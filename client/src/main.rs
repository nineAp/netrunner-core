//! Headless-клиент Netrunner для Linux/OpenWrt.
//!
//! Desktop-приложение запускает то же ядро через UniFFI/Tauri, а этот бинарь
//! предназначен для системного сервиса: читает TOML-конфиг, корректно
//! обрабатывает SIGTERM и умеет перехватывать транзитный трафик LAN роутера.

// Workaround for rustc 1.94 ICE in check_mod_deathness (dead-code MIR pass).
#![allow(dead_code)]

mod net;
mod profile_cmd;
mod tun;

use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use net::engine::{EngineBuilder, EngineConfig};
use netrunner_core::net::NetworkConfig;
use netrunner_logger::{Logger, error, info};
use serde::Deserialize;
use tun::{routing::TunnelMode, routing::reset_platform_routing, tun::Tun};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum TunnelModeArg {
    All,
    BypassLan,
    Resources,
}

impl From<TunnelModeArg> for TunnelMode {
    fn from(value: TunnelModeArg) -> Self {
        match value {
            TunnelModeArg::All => Self::All,
            TunnelModeArg::BypassLan => Self::BypassLan,
            TunnelModeArg::Resources => Self::Resources,
        }
    }
}

/// Значения из TOML. Все поля необязательны: CLI может переопределить каждое
/// из них, а безопасные несекретные значения имеют встроенные defaults.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    remote_address: Option<String>,
    sni: Option<String>,
    auth_token: Option<String>,
    node_secret: Option<String>,
    node_public_key: Option<String>,
    cache_dir: Option<PathBuf>,
    mtu: Option<usize>,
    killswitch_enabled: Option<bool>,
    excluded_uids: Vec<String>,
    excluded_domains: Vec<String>,
    tunnel_mode: Option<TunnelModeArg>,
    routed_cidrs: Vec<String>,
    router_mode: Option<bool>,
    lan_interfaces: Vec<String>,
    strong_privacy: Option<bool>,
    log_level: Option<String>,
    /// JSON-профиль браузера (см. `netrunner-client profile record`).
    browser_profile: Option<PathBuf>,
}

/// Аргументы headless-клиента. Секреты лучше хранить в root-only TOML или
/// переменных окружения: переданные напрямую аргументы видны через `ps`.
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Netrunner headless VPN client for Linux/OpenWrt",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// TOML-конфиг (для OpenWrt: /etc/netrunner/client.toml).
    #[arg(long, env = "NETRUNNER_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// IPv4-адрес VPN-ноды с портом, например 203.0.113.10:443.
    #[arg(long, env = "NETRUNNER_REMOTE_ADDRESS")]
    remote_address: Option<String>,

    /// SNI домена-декоя.
    #[arg(long, env = "NETRUNNER_SNI")]
    sni: Option<String>,

    /// Bearer/JWT токен. Предпочтительнее TOML или environment.
    #[arg(long, env = "NETRUNNER_AUTH_TOKEN", hide_env_values = true)]
    auth_token: Option<String>,

    /// Секретный ключ выбранной ноды (hex).
    #[arg(long, env = "NETRUNNER_NODE_SECRET", hide_env_values = true)]
    node_secret: Option<String>,

    /// Публичный ключ выбранной ноды (hex).
    #[arg(long, env = "NETRUNNER_NODE_PUBLIC_KEY")]
    node_public_key: Option<String>,

    #[arg(long, env = "NETRUNNER_CACHE_DIR")]
    cache_dir: Option<PathBuf>,

    #[arg(long, env = "NETRUNNER_MTU")]
    mtu: Option<usize>,

    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_killswitch")]
    killswitch: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    no_killswitch: bool,

    /// UID Linux-процесса, который должен идти мимо VPN. Можно повторять.
    #[arg(long, value_delimiter = ',')]
    excluded_uid: Vec<String>,

    /// Домен в обход VPN. Можно повторять или перечислять через запятую.
    #[arg(long, value_delimiter = ',')]
    excluded_domain: Vec<String>,

    #[arg(long, value_enum)]
    tunnel_mode: Option<TunnelModeArg>,

    #[arg(long, value_delimiter = ',')]
    routed_cidr: Vec<String>,

    /// Перехватывать трафик устройств из LAN, а не только самого хоста.
    #[arg(long, action = ArgAction::SetTrue)]
    router_mode: bool,

    /// LAN-интерфейс OpenWrt. По умолчанию в router mode: br-lan.
    #[arg(long, value_delimiter = ',')]
    lan_interface: Vec<String>,

    /// Включает onion-маршрут с перемешиванием потоков и фоновой набивкой.
    #[arg(long, env = "NETRUNNER_STRONG_PRIVACY", action = ArgAction::SetTrue)]
    strong_privacy: bool,

    #[arg(long, env = "RUST_LOG")]
    log_level: Option<String>,

    /// JSON-профиль браузера для маскировки ClientHello вместо встроенного
    /// (получить: `netrunner-client profile record --out chrome.json`).
    #[arg(long, env = "NETRUNNER_BROWSER_PROFILE", value_name = "PATH")]
    browser_profile: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Браузерные профили: запись трафика браузера и сборка JSON-профиля.
    Profile {
        #[command(subcommand)]
        action: profile_cmd::ProfileAction,
    },
}

struct EffectiveConfig {
    remote_address: String,
    proxy_address: SocketAddr,
    sni: String,
    auth_token: Option<String>,
    node_secret: Option<String>,
    node_public_key: Option<String>,
    cache_dir: PathBuf,
    mtu: usize,
    killswitch_enabled: bool,
    excluded_uids: Vec<String>,
    excluded_domains: Vec<String>,
    tunnel_mode: TunnelModeArg,
    routed_cidrs: Vec<String>,
    router_mode: bool,
    lan_interfaces: Vec<String>,
    strong_privacy: bool,
    log_level: String,
    browser_profile: Option<PathBuf>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn prefer_cli_list(cli: Vec<String>, file: Vec<String>) -> Vec<String> {
    let selected = if cli.is_empty() { file } else { cli };
    selected
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn read_file_config(path: Option<&PathBuf>) -> Result<FileConfig> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };
    let raw = fs::read_to_string(path)
        .with_context(|| format!("не удалось прочитать конфиг {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("невалидный TOML в конфиге {}", path.display()))
}

fn build_config(cli: Cli, file: FileConfig) -> Result<EffectiveConfig> {
    let remote_address = non_empty(cli.remote_address.or(file.remote_address))
        .context("укажите remote_address в TOML или --remote-address")?;
    let proxy_address: SocketAddr = remote_address
        .parse()
        .with_context(|| format!("remote_address должен иметь вид IPv4:port: {remote_address}"))?;
    if !proxy_address.is_ipv4() {
        bail!("пока поддерживается только IPv4-адрес VPN-ноды");
    }

    let node_secret = non_empty(cli.node_secret.or(file.node_secret));
    let node_public_key = non_empty(cli.node_public_key.or(file.node_public_key));
    if node_secret.is_some() != node_public_key.is_some() {
        bail!("node_secret и node_public_key должны быть заданы вместе");
    }

    let mtu = cli.mtu.or(file.mtu).unwrap_or(1450);
    if !(576..=9000).contains(&mtu) {
        bail!("mtu должен быть в диапазоне 576..=9000");
    }

    let tunnel_mode = cli
        .tunnel_mode
        .or(file.tunnel_mode)
        .unwrap_or(TunnelModeArg::All);
    let router_mode = cli.router_mode || file.router_mode.unwrap_or(false);
    if router_mode && tunnel_mode == TunnelModeArg::Resources {
        bail!("router_mode пока поддерживает tunnel_mode all или bypass_lan");
    }

    let mut lan_interfaces = prefer_cli_list(cli.lan_interface, file.lan_interfaces);
    if router_mode && lan_interfaces.is_empty() {
        lan_interfaces.push("br-lan".to_owned());
    }

    let killswitch_enabled = if cli.killswitch {
        true
    } else if cli.no_killswitch {
        false
    } else {
        file.killswitch_enabled.unwrap_or(true)
    };

    Ok(EffectiveConfig {
        remote_address,
        proxy_address,
        sni: non_empty(cli.sni.or(file.sni))
            .unwrap_or_else(|| netrunner_core::net::DEFAULT_DECOY_HOST.to_owned()),
        auth_token: non_empty(cli.auth_token.or(file.auth_token)),
        node_secret,
        node_public_key,
        cache_dir: cli
            .cache_dir
            .or(file.cache_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp/netrunner")),
        mtu,
        killswitch_enabled,
        excluded_uids: prefer_cli_list(cli.excluded_uid, file.excluded_uids),
        excluded_domains: prefer_cli_list(cli.excluded_domain, file.excluded_domains),
        tunnel_mode,
        routed_cidrs: prefer_cli_list(cli.routed_cidr, file.routed_cidrs),
        router_mode,
        lan_interfaces,
        strong_privacy: cli.strong_privacy || file.strong_privacy.unwrap_or(false),
        log_level: non_empty(cli.log_level.or(file.log_level)).unwrap_or_else(|| "info".to_owned()),
        browser_profile: cli.browser_profile.or(file.browser_profile),
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Получен SIGINT, останавливаем клиент"),
        _ = terminate => info!("Получен SIGTERM, останавливаем клиент"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if let Some(Command::Profile { action }) = cli.command.take() {
        return profile_cmd::run(action).await;
    }
    let file = read_file_config(cli.config.as_ref())?;
    let config = build_config(cli, file)?;

    fs::create_dir_all(&config.cache_dir).with_context(|| {
        format!(
            "не удалось создать cache_dir {}",
            config.cache_dir.display()
        )
    })?;

    Logger::init(None, true);
    Logger::global().set_level(&config.log_level);
    info!(
        router_mode = config.router_mode,
        lan_interfaces = ?config.lan_interfaces,
        "Запускаем headless Netrunner client"
    );

    if let Some(path) = &config.browser_profile {
        let report = netrunner_core::browser_profile::load_file(path)
            .with_context(|| format!("не удалось загрузить browser_profile {}", path.display()))?;
        info!(profiles = ?report.names, "Загружен пользовательский профиль браузера");
        if report.shape_samples != (0, 0) {
            info!(
                up = report.shape_samples.0,
                down = report.shape_samples.1,
                "Форма трафика из профиля: длины TLS-записей выравниваются по браузерным"
            );
        }
        for w in &report.warnings {
            tracing::warn!("browser_profile: {w}");
        }
    }

    NetworkConfig::init_global(config.mtu);
    let tun_device = Tun::create(|tun_cfg| {
        tun_cfg
            .tun_name("netr0")
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .mtu(config.mtu as u16)
            .up();
    })
    .context("не удалось создать TUN netr0 (нужны root/CAP_NET_ADMIN и /dev/net/tun)")?;

    let engine_config = EngineConfig::new(&config.remote_address)
        .with_cache_path(config.cache_dir.to_string_lossy())
        .with_mtu(config.mtu)
        .with_killswitch(config.killswitch_enabled)
        .with_excluded_apps(config.excluded_uids)
        .with_excluded_domains(config.excluded_domains)
        .with_decoy_sni(config.sni)
        .with_auth_token(config.auth_token)
        .with_node_credentials(config.node_secret, config.node_public_key)
        .with_tunnel_mode(config.tunnel_mode.into(), config.routed_cidrs)
        .with_router_mode(config.router_mode, config.lan_interfaces)
        .with_strong_privacy(config.strong_privacy);

    let build_result = EngineBuilder::new(engine_config)
        .with_tun(tun_device)
        .build()
        .await;

    let stopped_by_signal = match build_result {
        Ok((mut engine, tun)) => {
            tokio::select! {
                _ = engine.run(tun) => false,
                _ = shutdown_signal() => true,
            }
        }
        Err(message) => {
            error!(error = %message, "Не удалось запустить VPN-движок");
            let _ = reset_platform_routing(
                Some(&config.proxy_address.ip().to_string()),
                config.killswitch_enabled,
            );
            bail!(message);
        }
    };

    reset_platform_routing(
        Some(&config.proxy_address.ip().to_string()),
        config.killswitch_enabled,
    )
    .context("не удалось полностью очистить маршрутизацию")?;

    if !stopped_by_signal {
        bail!("VPN-движок неожиданно завершил работу");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_file_and_router_defaults_to_br_lan() {
        let cli = Cli::try_parse_from([
            "netrunner-client",
            "--remote-address",
            "198.51.100.10:443",
            "--router-mode",
            "--mtu",
            "1380",
            "--no-killswitch",
        ])
        .unwrap();
        let file = FileConfig {
            remote_address: Some("203.0.113.10:443".to_owned()),
            mtu: Some(1450),
            killswitch_enabled: Some(true),
            ..FileConfig::default()
        };

        let config = build_config(cli, file).unwrap();
        assert_eq!(config.remote_address, "198.51.100.10:443");
        assert_eq!(config.mtu, 1380);
        assert!(!config.killswitch_enabled);
        assert_eq!(config.lan_interfaces, ["br-lan"]);
    }

    #[test]
    fn node_credentials_must_be_a_pair() {
        let cli = Cli::try_parse_from([
            "netrunner-client",
            "--remote-address",
            "198.51.100.10:443",
            "--node-secret",
            "abcd",
        ])
        .unwrap();

        let error = build_config(cli, FileConfig::default()).err().unwrap();
        assert!(error.to_string().contains("должны быть заданы вместе"));
    }

    #[test]
    fn router_mode_rejects_resources_mode() {
        let cli = Cli::try_parse_from([
            "netrunner-client",
            "--remote-address",
            "198.51.100.10:443",
            "--router-mode",
            "--tunnel-mode",
            "resources",
        ])
        .unwrap();

        let error = build_config(cli, FileConfig::default()).err().unwrap();
        assert!(error.to_string().contains("router_mode"));
    }
}
