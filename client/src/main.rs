use netrunner_client::{stack::NetStack, tun::tun_builder::TunBuilder};
use netrunner_common::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    let mut tun_result = TunBuilder::new().build().await;
    logger_init();

    let net = Network::new(8080, ConnectionRole::Client, Some("0.0.0.0:4443".into()));

    let Ok(tun) = tun_result else {
        error!("Tun creation error");
        return;
    };

    let muxer = match net.initialize_client_tunnel().await {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to initialize global tunnel: {}", e);
            return;
        }
    };

    let mut net_handle = {
        let muxer_for_net = muxer.clone();
        tokio::spawn(async move {
            info!("SOCKS5 server starting on 127.0.0.1:8080");
            net.run_with_muxer(muxer_for_net).await;
        })
    };

    let mut net_stack = NetStack::new(muxer);

    loop {
        net_stack.poll();

        let mut buf = [0u8; 1600];

        tokio::select! {
            // Читаем из реального мира (TUN) и закидываем в очередь стека
            tun_res = tun.read(&mut buf) => {
                if let Ok(n) = tun_res {
                    // Прямой вызов обработки (без лишних каналов, если это один поток)
                    // Или через твой метод, если логика разделена:
                    net_stack.process_tun_input(&buf[..n]);
                }
            }

            // Читаем из очереди стека и отдаем в реальный мир (TUN)
            Some(packet_to_tun) = net_stack.next_outbound_packet() => {
                let _ = tun.write_all(&packet_to_tun).await;
            }

            // Ждем, пока стек сам попросит проснуться (таймеры TCP)
            _ = net_stack.poll_delay() => {
                // Просто просыпаемся. На следующей итерации вызовется poll()
            }

            // Ошибка прокси
            net_res = &mut net_handle => {
                error!("SOCKS5 server stopped: {:?}", net_res);
                break;
            }
        }
    }
}
