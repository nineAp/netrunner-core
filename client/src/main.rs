mod stack;
mod tun;

use netrunner_common::{
    logger_init, proxy::connection::connection::ConnectionRole, proxy::network::Network,
};
use stack::interface::NetStack;
use tracing::{error, info};
use tun::{desktop::create_linux_tun, device::TunDevice};

#[tokio::main]
async fn main() {
    // 1. Инициализация логов
    logger_init();
    info!("Starting NetRunner VPN Bridge...");

    // 2. Настройка физического уровня (TUN)
    let tun_dev = create_linux_tun();
    let my_phy = TunDevice::new(tun_dev, 1500);

    // 3. Создаем объект Network
    let net = Network::new(8080, ConnectionRole::Client, Some("0.0.0.0:4443".into()));

    // 4. Инициализируем ЕДИНЫЙ туннель для всего приложения.
    // Этот метод внутри создает TLS-подключение, Muxer и запускает TunnelEngine.
    info!("Initializing global TLS tunnel to proxy...");
    let muxer = match net.initialize_client_tunnel().await {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize global tunnel: {}", e);
            return;
        }
    };

    // 5. Создаем стек, передавая ему РАБОЧИЙ муксер.
    // Теперь данные из TUN будут уходить в реальный TLS-туннель.
    let mut stack = NetStack::new(my_phy, muxer.clone());

    // 6. Запускаем SOCKS-сервер (Network), чтобы он слушал порт 8080
    // и использовал тот же самый муксер для обычных прокси-запросов.
    let net_handle = {
        let muxer_for_net = muxer.clone();
        tokio::spawn(async move {
            info!("SOCKS5 server starting on 127.0.0.1:8080");
            net.run_with_muxer(muxer_for_net).await;
        })
    };

    info!("VPN BRIDGE IS RUNNING");

    // 7. Запускаем цикл обработки стека (блокирующий поток)
    let stack_loop = tokio::task::spawn_blocking(move || loop {
        stack.poll();
    });

    // Ждем завершения (по сути бесконечно)
    tokio::select! {
        res = stack_loop => {
            if let Err(e) = res {
                error!("Stack loop panicked: {:?}", e);
            }
        }
        _ = net_handle => {
            error!("Network server stopped unexpectedly");
        }
    }
}
