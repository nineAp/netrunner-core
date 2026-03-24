use crate::proxy::connection::connection::{
    ClientHandler, Connection, ConnectionRole, ServerHandler, TunnelHandler,
};
use netrunner_logger::{error, info};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct Network {
    host: String,
    port: u16,
    role: ConnectionRole,
    remote_proxy_addr: Option<String>,
}

impl Network {
    pub fn new(
        host: String,
        port: u16,
        role: ConnectionRole,
        remote_proxy_addr: Option<String>,
    ) -> Self {
        Self {
            host,
            port,
            role,
            remote_proxy_addr,
        }
    }

    pub async fn run(&self, token: CancellationToken) {
        let addr = format!("{}:{}", self.host, self.port);

        match self.role {
            ConnectionRole::Client => {
                info!("Starting Client mode");
                let server_addr = self
                    .remote_proxy_addr
                    .as_ref()
                    .ok_or("No proxy addr")
                    .unwrap();
                let muxer = match ClientHandler::connect(server_addr).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!(error = %e, "Global tunnel failed.");
                        return;
                    }
                };

                let listener = TcpListener::bind(&addr).await.expect("SOCKS bind failed");
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        res = listener.accept() => {
                            if let Ok((stream, _client_addr)) = res {
                                let conn = Connection::new(stream, false);
                                let handler = ClientHandler{ conn, muxer: muxer.clone() };
                                tokio::spawn(async move {
                                    if let Err(e) = handler.run().await {
                                        error!(error = %e, "Client handler error");
                                    }
                                });
                            }
                        }
                    }
                }
            }
            ConnectionRole::Server => {
                let listener = TcpListener::bind(&addr).await.expect("Server bind failed");
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        res = listener.accept() => {
                            if let Ok((stream, client_addr)) = res {
                                let conn = Connection::new(stream, true);
                                let handler = ServerHandler { conn, token: token.clone() };
                                tokio::spawn(async move {
                                    if let Err(e) = handler.run().await {
                                        error!(client = %client_addr, error = %e, "Server handler error");
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}
