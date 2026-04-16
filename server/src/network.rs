use netrunner_core::net::{
    Connection, NetworkConfig, ServerHandler, SessionManager, TunnelHandler,
    TOPOLOGY_PRINT_INTERVAL,
};
use netrunner_logger::{error, info};
use std::sync::Arc;
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

        NetworkConfig::init_global(1380);

        // 🔥 CRITICAL FIX: Create ONE global session manager for multiplexing
        let session_manager = Arc::new(SessionManager::new());

        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                sm_clone.print_all_sessions();
            }
        });

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

                        let conn = Connection::new(stream);

                        // Pass the Arc clone down to the ServerHandler
                        let handler = ServerHandler::new(conn, session_manager.clone());

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
