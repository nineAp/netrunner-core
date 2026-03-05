use netrunner_client::{stack::NetStack, tun::TunBuilder};
use netrunner_common::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    logger_init();

    let net = Network::new(8080, ConnectionRole::Client, Some("0.0.0.0:4443".into()));

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

    loop {}
}
