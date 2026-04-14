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
            connection_buf_size: 1024 * 1024 * 4,
            tcp_buffer_size: 1024 * 1024,
            udp_buffer_size: 64 * 1024,
            tcp_chunk_size: system_mtu - 100,

            // 🔥 Канал расширен для сглаживания микро-обрывов связи
            channel_capacity: 2048,

            // Расширяем TCP окна под BBR
            tcp_rx_heavy: 256 * 1024,
            tcp_tx_heavy: 256 * 1024,

            tcp_rx_light: 32 * 1024,
            tcp_tx_light: 32 * 1024,

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
