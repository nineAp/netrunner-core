use netrunner_logger::warn;
use std::sync::OnceLock;

pub static GLOBAL_NET_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mtu: usize,
    pub tcp_buffer_size: usize,
    pub udp_buffer_size: usize,

    // --- Очереди MPSC (Разделенные) ---
    // Для Клиента (мобильный интернет)
    pub client_muxer_capacity: usize,  // Подушка для 10 ног
    pub client_tun_capacity: usize,    // Стык TUN <-> Engine
    pub client_stream_capacity: usize, // Быстрый Backpressure для сокета
    pub client_virtual_stream_capacity: usize,

    // Для Сервера (Дата-центр)
    pub server_muxer_capacity: usize, // Огромная очередь для входящего трафика
    pub server_stream_capacity: usize, // Чтобы сервер не тормозил на отдачу

    pub tcp_chunk_size: usize,

    // Буферы сокетов smoltcp
    pub tcp_rx_heavy: usize,
    pub tcp_tx_heavy: usize,
    pub tcp_rx_light: usize,
    pub tcp_tx_light: usize,

    pub udp_buf_heavy: usize,
    pub udp_meta_heavy: usize,
    pub udp_buf_light: usize,
    pub udp_meta_light: usize,
}

impl NetworkConfig {

    pub fn new(system_mtu: usize) -> Self {
        Self {
            mtu: system_mtu,
            tcp_buffer_size: 64 * 1024,  // Для чтения из физического сокета (нормально)
            udp_buffer_size: 64 * 1024,

            tcp_chunk_size: 4 * 1024,  // Оставляем 16 КБ

            // 🔥 Зажимаем программные очереди (Убиваем Hidden Bloat)

            client_muxer_capacity: 8,
            client_tun_capacity: 16,
            client_stream_capacity: 16,
            client_virtual_stream_capacity: 8,

            server_muxer_capacity: 64,  // Кардинально режем
            server_stream_capacity: 32,

            // 🔥 Расширяем TCP окна под BBR (Разблокируем Gigabit на дальние дистанции)
            tcp_rx_heavy: 64 * 1024, //64KB
            tcp_tx_heavy: 1 * 1024 * 1024, // 1 MB

            tcp_rx_light: 16 * 1024,
            tcp_tx_light: 64 * 1024,

            udp_buf_heavy: 256 * 1024,
            udp_meta_heavy: 512,
            udp_buf_light: 16 * 1024,
            udp_meta_light: 32,
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
