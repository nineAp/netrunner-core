use std::sync::OnceLock;

use crate::{
    net::connection::{Connection, ConnectionRole, ServerHandler, TunnelHandler},
    nrxp::{FRAME_HEADER_SIZE, MAX_PADDING_SIZE},
};
use netrunner_logger::{error, info, warn};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct Network {
    host: String,
    port: u16,
    role: ConnectionRole,
}

impl Network {
    pub fn new(host: String, port: u16, role: ConnectionRole) -> Self {
        Self { host, port, role }
    }

    pub async fn run(&self, token: CancellationToken) {
        let addr = format!("{}:{}", self.host, self.port);

        // Инициализируем глобальный конфиг сети (MTU, размеры буферов)
        NetworkConfig::init_global(1500);

        match self.role {
            ConnectionRole::Client => {
                // В новой архитектуре клиент запускается через EngineBuilder + TUN.
                // Структура Network теперь используется только для запуска Сервера.
                error!("Client mode cannot be run via Network::run anymore.");
                error!("Please use EngineBuilder to initialize the TUN client.");
                panic!("Legacy SOCKS5 client mode has been removed.");
            }
            ConnectionRole::Server => {
                info!("Starting Server mode on {}", addr);
                let listener = TcpListener::bind(&addr).await.expect("Server bind failed");

                loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            info!("Shutdown signal received, stopping server.");
                            break;
                        }
                        res = listener.accept() => {
                            if let Ok((stream, client_addr)) = res {
                                info!("New connection from {}", client_addr);

                                // Создаем соединение (init = true для сервера)
                                let conn = Connection::new(stream, true);
                                let handler = ServerHandler::new(conn);

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

pub static GLOBAL_NET_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

pub struct NetworkConfig {
    pub mtu: usize,
    pub max_wire_frame_size: usize,
    pub safe_payload_size: usize,

    // --- ИЗМЕНЕНИЯ ЗДЕСЬ ---
    pub tcp_buffer_size: usize, // Размер буфера для системного tokio::TcpStream
    pub udp_buffer_size: usize,
    pub muxer_capacity: usize,      // Глобальные каналы (Muxer <-> Engine)
    pub tcp_stream_capacity: usize, // Локальные каналы 1 сокета (Engine <-> Muxer)
    pub udp_stream_capacity: usize, // Локальные каналы 1 сокета (Engine <-> Muxer)

    pub smoltcp_socket_buf: usize,
    pub tcp_chunk_size: usize,
}

impl NetworkConfig {
    pub fn new(system_mtu: usize) -> Self {
        let transport_overhead = 48;
        let max_wire_frame = system_mtu.saturating_sub(transport_overhead);
        let safe_payload = max_wire_frame.saturating_sub(64);

        Self {
            mtu: system_mtu,
            max_wire_frame_size: max_wire_frame,
            safe_payload_size: safe_payload,

            // Буферы ОС/Tokio (держим с запасом под быстрые всплески)
            tcp_buffer_size: 2 * 1024 * 1024,
            udp_buffer_size: 512 * 1024,

            // Глобальная очередь. 4096 * 16KB = ~65 MB в памяти (безопасно)
            // Это спасет от заторов, если 10 сокетов решат отправить данные одновременно
            muxer_capacity: 1024,

            tcp_stream_capacity: 64,
            udp_stream_capacity: 64,

            // Настройки smoltcp
            smoltcp_socket_buf: 1024 * 1024,
            tcp_chunk_size: 16 * 1024,
        }
    }

    pub fn init_global(system_mtu: usize) {
        let config = Self::new(system_mtu);
        if GLOBAL_NET_CONFIG.set(config).is_err() {
            warn!("Global network config was already initialized!");
        }
    }

    pub fn global() -> &'static Self {
        GLOBAL_NET_CONFIG
            .get()
            .expect("Global NetworkConfig is not initialized! Call init_global() first.")
    }
}
