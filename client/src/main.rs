use netrunner_client::tun::{engine::EngineBuilder, routing::reset_platform_routing, tun::Tun};
use netrunner_logger::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    netrunner_logger::Logger::init();
    info!("Initializing NetRunner Stack...");

    let remote_address = "147.45.43.70:443";

    // 1. Создаем TUN интерфейс (зависит от платформы, поэтому делаем тут)
    let tun_device = Tun::create(|config| {
        config
            .tun_name("netr0")
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 2))
            .up();
    })
    .expect("Failed to initialize TUN device");

    info!("TUN interface is UP: 10.0.0.1/24");

    // 2. Собираем движок через наш новый Builder
    let builder_result = EngineBuilder::new(remote_address)
        .with_cache_path(".")
        .with_tun(tun_device)
        .build()
        .await;

    // 3. Обрабатываем результат и запускаем цикл
    match builder_result {
        Ok((mut engine, tun)) => {
            info!("Engine starting process loop...");

            let ctrl_c = tokio::signal::ctrl_c();

            tokio::select! {
                res = engine.run(tun) => {
                    error!("Engine loop error: {:?}", res);
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

    // 4. Очистка системных роутов при любом сценарии выхода (ошибка или Ctrl+C)
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
