use netrunner_logger::{error, info};
mod net;
mod tun;

// Импортируем и Билдер, и Конфиг
use crate::tun::{routing::reset_platform_routing, tun::Tun};
use net::engine::{EngineBuilder, EngineConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netrunner_logger::Logger::init();
    info!("Initializing NetRunner Stack...");

    let remote_address = "147.45.43.70:443";

    // 1. Создаем конфигурацию движка
    // Здесь мы можем гибко настроить параметры, которые раньше были захардкожены
    let config = EngineConfig::new(remote_address)
        .with_cache_path(".")
        .with_mtu(1350); // Указываем MTU здесь, чтобы использовать его и для TUN, и для стека

    // 2. Создаем TUN интерфейс
    // Используем значение MTU из конфига, чтобы данные были синхронизированы
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

    // 3. Собираем движок, передавая объект конфигурации
    let builder_result = EngineBuilder::new(config)
        .with_tun(tun_device)
        .build()
        .await;

    // 4. Обрабатываем результат и запускаем цикл
    match builder_result {
        Ok((mut engine, tun)) => {
            info!("Engine starting process loop...");

            let ctrl_c = tokio::signal::ctrl_c();

            tokio::select! {
                _res = engine.run(tun) => {
                    info!("Engine loop finished");
                },
                _ = ctrl_c => {
                    info!("Ctrl+C received, shutting down...");
                }
            }
        }
        Err(e) => {
            error!("Failed to build VPN Engine: {}", e);
        }
    }

    // 5. Очистка системных роутов
    info!("Restoring system routing...");
    let addr: std::net::SocketAddr = remote_address.parse().expect("Invalid address format");
    let p_ip = addr.ip().to_string();

    if let Err(e) = reset_platform_routing(Some(&p_ip)) {
        error!("Failed to restore routing: {}", e);
    } else {
        info!("System routing restored successfully.");
    }

    Ok(())
}
