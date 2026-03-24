use crate::{
    protocol::codec::{frame::FRAME_HEADER_SIZE, MAX_PADDING_SIZE},
    proxy::connection::connection::{
        ClientHandler, Connection, ConnectionRole, ServerHandler, TunnelHandler,
    },
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

pub const IP_UDP_OVERHEAD: usize = 28;

pub struct NetworkConfig {
    pub mtu: usize,
    pub max_wire_frame_size: usize,
    pub safe_payload_size: usize,
    pub tcp_rx_buffer_size: usize,
    pub tcp_tx_buffer_size: usize,
    pub udp_rx_buffer_size: usize,
    pub udp_tx_buffer_size: usize,
    pub channel_capacity: usize,
}

impl NetworkConfig {
    pub fn new(system_mtu: usize) -> Self {
        let transport_overhead = 28; // IPv4 + UDP

        let max_wire_frame = system_mtu.saturating_sub(transport_overhead);

        let safe_payload = max_wire_frame
            .saturating_sub(FRAME_HEADER_SIZE as usize)
            .saturating_sub((MAX_PADDING_SIZE - 1) as usize);

        let tcp_chunks_count = 65536 / safe_payload;
        let tcp_buffer = safe_payload * tcp_chunks_count;

        let udp_chunks_count = 16384 / safe_payload;
        let udp_buffer = safe_payload * udp_chunks_count;

        let channel_cap = 1024;

        netrunner_logger::info!(
            mtu = system_mtu,
            payload = safe_payload,
            tcp_buf = tcp_buffer,
            "Network Optimizer: Calculations complete for current MTU"
        );

        Self {
            mtu: system_mtu,
            max_wire_frame_size: max_wire_frame,
            safe_payload_size: safe_payload,
            tcp_rx_buffer_size: tcp_buffer,
            tcp_tx_buffer_size: tcp_buffer,
            udp_rx_buffer_size: udp_buffer,
            udp_tx_buffer_size: udp_buffer,
            channel_capacity: channel_cap,
        }
    }
}
