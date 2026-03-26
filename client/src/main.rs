use netrunner_logger::{error, info};
mod net;
mod tun;

// Импортируем Билдер, Конфиг и модули маршрутизации
use crate::tun::{routing::reset_platform_routing, tun::Tun};
use net::engine::{EngineBuilder, EngineConfig};

// Импортируем компоненты локального прокси
use netrunner_core::net::ConnectionRole;
use netrunner_core::net::network::Network;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netrunner_logger::Logger::init();
    info!("Initializing NetRunner Stack...");

    let remote_address = "147.45.43.70:443".to_string();
    let local_proxy_host = "127.0.0.1".to_string();
    let local_proxy_port = 8080; // Локальный порт прокси

    // Токен для управления жизненным циклом фоновых задач
    let cancel_token = CancellationToken::new();

    // ==================================================
    // 1. ЗАПУСК ЛОКАЛЬНОГО ПРОКСИ (NETWORK)
    // ==================================================
    let proxy_token = cancel_token.clone();
    let remote_addr_clone = remote_address.clone();

    tokio::spawn(async move {
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

        // Эта функция заблокирует поток, пока не сработает proxy_token
        network.run(proxy_token).await;
        info!("Local Proxy (Network) task stopped.");
    });

    // Даем локальному прокси немного времени на бинд порта и установку соединения
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // ==================================================
    // 2. ИНИЦИАЛИЗАЦИЯ ДВИЖКА И TUN
    // ==================================================
    let config = EngineConfig::new(&remote_address)
        .with_cache_path(".")
        .with_mtu(1350);

    let tun_device = Tun::create(|tun_cfg| {
        tun_cfg
            .tun_name("netr0")
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 2))
            .mtu(config.mtu as u16)
            .up();
    })
    .expect("Failed to initialize TUN device");

    info!("TUN interface is UP: 10.0.0.1/24 (MTU: {})", config.mtu);

    let builder_result = EngineBuilder::new(config)
        .with_tun(tun_device)
        .build()
        .await;

    // ==================================================
    // 3. ГЛАВНЫЙ ЦИКЛ ENGINE
    // ==================================================
    match builder_result {
        Ok((mut engine, tun)) => {
            info!("Engine starting process loop...");

            tokio::select! {
                _res = engine.run(tun) => {
                    info!("Engine loop finished");
                },
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down...");
                    // Отменяем токен, чтобы Network.run завершился
                    cancel_token.cancel();
                }
            }
        }
        Err(e) => {
            error!("Failed to build VPN Engine: {}", e);
            cancel_token.cancel();
        }
    }

    // ==================================================
    // 4. ОЧИСТКА РОУТИНГА
    // ==================================================
    info!("Restoring system routing...");
    let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
    let p_ip = addr.ip().to_string();

    if let Err(e) = reset_platform_routing(Some(&p_ip)) {
        error!("Failed to restore routing: {}", e);
    } else {
        info!("System routing restored successfully.");
    }

    // Даем таске Network время на graceful shutdown (чтобы сокеты успели закрыться)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    Ok(())
}
