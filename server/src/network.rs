use netrunner_core::net::{Connection, NetworkConfig, ServerHandler, TunnelHandler};
use netrunner_logger::{error, info};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct Network {
    host: String,
    port: u16,
}

impl Network {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    pub async fn run(&self, token: CancellationToken) {
        let addr = format!("{}:{}", self.host, self.port);

        // Инициализируем конфиг для сервера
        NetworkConfig::init_global(1500);

        info!("🌐 Netrunner Server: Listening on {}", addr);
        let listener = TcpListener::bind(&addr).await.expect("Server bind failed");

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("🛑 Shutdown signal received, stopping server.");
                    break;
                }
                res = listener.accept() => {
                    if let Ok((stream, client_addr)) = res {
                        info!("🔌 Connection from {}", client_addr);

                        // Создаем объект соединения (включает кодек)
                        let conn = Connection::new(stream, true);

                        // Создаем хэндлер. (Он сам разберется с SessionManager, если нужно)
                        let handler = ServerHandler::new(conn);

                        tokio::spawn(async move {
                            if let Err(e) = handler.run().await {
                                error!(client = %client_addr, error = %e, "⚠️ Server handler error");
                            }
                        });
                    }
                }
            }
        }
    }
}
