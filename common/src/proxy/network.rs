use crate::{
    protocol::errors::ErrorAction,
    proxy::connection::{
        connection::{Connection, ConnectionRole},
        engine::TunnelEngine,
        muxer::{MuxMessage, Muxer},
    },
    tlseng::profile::BrowserProfile,
};
use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, instrument}; // Импортируем макросы

pub struct Network {
    port: u16,
    role: ConnectionRole,
    remote_proxy_addr: Option<String>,
}

impl Network {
    pub fn new(port: u16, role: ConnectionRole, remote_proxy_addr: Option<String>) -> Self {
        Self {
            port,
            role,
            remote_proxy_addr,
        }
    }

    // Добавляем инструмент, чтобы видеть параметры запуска сети в логах
    #[instrument(skip(self), fields(role = ?self.role, port = self.port))]
    pub async fn run(&self) {
        let addr = format!("127.0.0.1:{}", self.port);

        match self.role {
            ConnectionRole::Client => {
                // --- ЛОГИКА КЛИЕНТА ---
                // 1. Создаем ОДИН туннель до прокси-сервера при старте
                info!("Starting Client mode: Initializing persistent tunnel to proxy...");

                let muxer = match self.initialize_client_tunnel().await {
                    Ok(m) => m,
                    Err(e) => {
                        error!(error = %e, "Failed to initialize global tunnel. Exiting.");
                        return;
                    }
                };

                // 2. Теперь слушаем SOCKS-запросы от браузера
                let listener = TcpListener::bind(&addr)
                    .await
                    .expect("Failed to bind SOCKS port");
                info!(socks_addr = %addr, "SOCKS5 server ready for browser connections");

                loop {
                    if let Ok((stream, client_addr)) = listener.accept().await {
                        let current_muxer = muxer.clone();

                        tokio::spawn(async move {
                            // Используем новый метод handle_socks_client
                            let connection = Connection::new(stream, client_addr, false);
                            if let Err(e) = connection.handle_socks_client(current_muxer).await {
                                error!(client = %client_addr, error = %e, "SOCKS stream error");
                            }
                        });
                    }
                }
            }

            ConnectionRole::Server => {
                // --- ЛОГИКА СЕРВЕРА ---
                let listener = TcpListener::bind(&addr)
                    .await
                    .expect("Failed to bind Server port");
                info!(listen_addr = %addr, "Proxy Server listening for incoming tunnels");

                loop {
                    if let Ok((stream, client_addr)) = listener.accept().await {
                        tokio::spawn(async move {
                            // Сервер использует handle_server_tunnel
                            let connection = Connection::new(stream, client_addr, true);
                            if let Err(e) = connection.handle_server_tunnel().await {
                                error!(client = %client_addr, error = %e, "Tunnel error");
                            }
                        });
                    }
                }
            }
        }
    }

    /// Вспомогательный метод для Клиента: создает TLS туннель и запускает TunnelEngine
    async fn initialize_client_tunnel(&self) -> Result<Muxer, String> {
        let server_addr = self
            .remote_proxy_addr
            .as_ref()
            .ok_or("Remote proxy address not configured")?;

        // 1. Устанавливаем TCP соединение с сервером
        let stream = TcpStream::connect(server_addr)
            .await
            .map_err(|e| format!("Connect to proxy failed: {}", e))?;

        // 2. Создаем временный Connection
        let dummy_addr = server_addr.parse().unwrap_or("0.0.0.0:0".parse().unwrap());
        // Передаем stream (Connection сам сделает into_split внутри, если у тебя так написано в new)
        let mut conn = Connection::new(stream, dummy_addr, false);

        // 3. TLS Handshake (Клиентская часть)
        debug!("Starting persistent TLS handshake with proxy");
        let ch = conn
            .codec
            .make_client_handshake(&BrowserProfile::CHROME_131, "proxy.server")
            .map_err(|e| format!("{:?}", e))?;

        conn.outbound
            .write_all(&ch)
            .await
            .map_err(|e| e.to_string())?;

        let mut sh_buf = BytesMut::with_capacity(2048);
        while let Err(e) = conn.codec.process_handshake(&mut sh_buf) {
            if e.action != ErrorAction::Wait {
                return Err(format!("Fatal handshake error: {:?}", e));
            }
            // Теперь read_buf найдется, так как мы импортировали AsyncReadExt
            let n = conn
                .inbound
                .read_buf(&mut sh_buf)
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("Server closed connection during handshake".into());
            }
        }
        info!("Persistent TLS Tunnel established successfully!");

        // 4. Инициализируем Muxer и TunnelEngine
        // Явно указываем тип сообщения для канала, чтобы убрать "cannot infer type"
        let (mux_tx, mux_rx) = tokio::sync::mpsc::channel::<MuxMessage>(1024);
        let muxer = Muxer::new(mux_tx, true);

        // 5. Запускаем TunnelEngine в фоне.
        let engine = TunnelEngine {
            inbound: conn.inbound,
            outbound: conn.outbound,
            codec: conn.codec,
            buffers: conn.buffers,
            mux_rx,
            muxer: muxer.clone(),
            role: ConnectionRole::Client,
        };

        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                error!("Main TunnelEngine died: {}", e);
            }
        });

        Ok(muxer)
    }
}
