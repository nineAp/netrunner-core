use std::sync::Arc;

use crate::proxy::connection::{
    connection::Connection, handler::handler::ProxyHandler, state::ConnectionState,
};
use tokio::net::TcpListener;

pub struct Network {
    inbound_handler: Arc<dyn ProxyHandler + Send + Sync>,
    outbound_handler: Arc<dyn ProxyHandler + Send + Sync>,
    port: u16,
}

impl Network {
    pub fn new(
        inbound_handler: Arc<dyn ProxyHandler + Send + Sync>,
        outbound_handler: Arc<dyn ProxyHandler + Send + Sync>,
        port: u16,
    ) -> Self {
        Self {
            inbound_handler,
            outbound_handler,
            port,
        }
    }

    pub async fn run(&self) {
        let port = self.port;
        let listener: TcpListener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        println!("Server Listening on Port {}...", port);
        loop {
            let (stream, addr) = listener.accept().await.expect("Error on connection");
            let handler = self.inbound_handler.clone();
            tokio::spawn(async move {
                let mut conection: Connection = Connection::new(stream, addr);

                let res = conection.handle(handler).await;
                match res {
                    Ok(state) => match state {
                        ConnectionState::New => {
                            println!("New connection {}", addr)
                        }
                        ConnectionState::Handshake => {
                            println!("Connection {} handshaked", addr)
                        }
                        ConnectionState::Tunnel(stream) => {
                            println!("Connection {} tunnel", addr)
                        }
                        ConnectionState::Close => {
                            println!("Connection {} closed", addr)
                        }
                        ConnectionState::Disconnected => {
                            println!("Connection {} Disconnected", addr)
                        }
                    },
                    Err(e) => {
                        eprintln!("Ошибка соединения с {}: {}", conection.addr, e);
                    }
                };
            });
        }
    }
}
