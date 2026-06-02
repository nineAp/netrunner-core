use netrunner_logger::warn;
use std::sync::OnceLock;

pub static GLOBAL_NET_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mtu: usize,
    pub connection_buf_size: usize,
    pub tcp_buffer_size: usize,
    pub udp_buffer_size: usize,
    pub tcp_chunk_size: usize,

    // 🔥 Единый конфиг для всех каналов Tokio
    pub channel_capacity: usize,

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
            // Для сервера 64KB ок, для клиента поднимем до 256KB, чтобы не тормозить чтение с TUN
            connection_buf_size: 256 * 1024,

            // 256KB — это золотая середина. Позволяет держать ~10Мбит на стрим при пинге 200мс.
            tcp_buffer_size: 256 * 1024,
            udp_buffer_size: 128 * 1024,
            tcp_chunk_size: system_mtu - 100,

            // Емкость каналов: 512 пакетов (~700КБ).
            // Этого достаточно, чтобы сгладить лаги радио-эфира на телефоне.
            channel_capacity: 8192,

            // Окна smoltcp (важно для Download)
            // Увеличиваем до 512KB для тяжелых профилей
            tcp_rx_heavy: 256 * 1024,
            tcp_tx_heavy: 256 * 1024,

            tcp_rx_light: 64 * 1024,
            tcp_tx_light: 64 * 1024,

            udp_buf_heavy: 256 * 1024,
            udp_meta_heavy: 1024, // Больше метаданных для мелких UDP пакетов
            udp_buf_light: 32 * 1024,
            udp_meta_light: 64,
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
