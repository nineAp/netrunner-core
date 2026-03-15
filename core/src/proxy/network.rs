use crate::{
    protocol::errors::ErrorAction,
    proxy::connection::{
        connection::{Connection, ConnectionRole, BUF_SIZE},
        engine::TunnelEngine,
        muxer::Muxer,
    },
    tlseng::profile::BrowserProfile,
};
use bytes::BytesMut;
use netrunner_logger::{error, info, instrument};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
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
                info!("Starting Client mode: Initializing persistent tunnel to proxy...");

                let muxer = match self.initialize_client_tunnel(token.clone()).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!(error = %e, "Global tunnel failed. Exit.");
                        return;
                    }
                };

                let listener = TcpListener::bind(&addr).await.expect("SOCKS bind failed");
                info!(socks_addr = %addr, "SOCKS5 ready");

                loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            info!("SOCKS listener: Shutting down...");
                            break;
                        }
                        res = listener.accept() => {
                            if let Ok((stream, client_addr)) = listener.accept().await {
                                let current_muxer = muxer.clone();
                                tokio::spawn(async move {
                                    let connection = Connection::new(stream, client_addr, false);
                                    let _ = connection.handle_socks_client(current_muxer).await;
                                });
                            }
                        }
                    }
                }
            }

            ConnectionRole::Server => {
                let listener = TcpListener::bind(&addr)
                    .await
                    .expect("Failed to bind Server port");
                info!(listen_addr = %addr, "Proxy Server listening for incoming tunnels");

                loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            info!("Server listener: Shutting down...");
                            break;
                        }
                        res = listener.accept() => {
                            match res {
                                Ok((stream, client_addr)) => {
                                    let connection = Connection::new(stream, client_addr, true);
                                    let connection_token = token.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = connection.handle_server_tunnel(connection_token).await {
                                            error!(client = %client_addr, error = %e, "Tunnel error");
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to accept connection");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn initialize_client_tunnel(
        &self,
        token: CancellationToken,
    ) -> Result<Muxer, String> {
        let server_addr = self.remote_proxy_addr.as_ref().ok_or("No proxy addr")?;

        let stream = TcpStream::connect(server_addr)
            .await
            .map_err(|e| e.to_string())?;
        let (mut inbound, mut outbound) = stream.into_split();

        let mut codec = crate::protocol::codec::codec::Codec::new(false);

        let ch = codec
            .make_client_handshake(&BrowserProfile::CHROME_131, "google.com")
            .map_err(|e| format!("{:?}", e))?;
        outbound.write_all(&ch).await.map_err(|e| e.to_string())?;

        let mut sh_buf = BytesMut::with_capacity(2048);
        loop {
            match codec.process_handshake(&mut sh_buf) {
                Ok(_) => break,
                Err(e) if e.action == ErrorAction::Wait => {
                    let n = inbound
                        .read_buf(&mut sh_buf)
                        .await
                        .map_err(|e| e.to_string())?;
                    if n == 0 {
                        return Err("EOF during handshake".into());
                    }
                }
                Err(e) => return Err(format!("TLS error: {:?}", e)),
            }
        }

        let (mux_tx, mux_rx) = tokio::sync::mpsc::channel(BUF_SIZE);
        let muxer = Muxer::new(mux_tx, true);

        let handler = std::sync::Arc::new(crate::proxy::connection::handler::StreamHandler::new(
            muxer.clone(),
            ConnectionRole::Client,
        ));

        let engine = TunnelEngine {
            inbound,
            outbound,
            codec,
            read_buf: sh_buf,
            mux_rx,
            handler,
            token,
        };

        tokio::spawn(async move { engine.run().await });

        Ok(muxer)
    }

    pub fn get_self_local_address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}
