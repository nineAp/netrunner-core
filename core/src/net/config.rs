use netrunner_logger::warn;
use std::sync::OnceLock;

pub static GLOBAL_NET_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mtu: usize,

    pub tcp_buffer_size: usize,
    pub udp_buffer_size: usize,

    // Очереди MPSC
    pub muxer_capacity: usize,
    pub tcp_stream_capacity: usize,
    pub udp_stream_capacity: usize,

    pub tcp_chunk_size: usize,

    // 👈 Разделяем буферы на RX (Чтение/Download) и TX (Запись/Upload)
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

            tcp_buffer_size: 8 * 1024,
            udp_buffer_size: 64 * 1024,

            // 1. Убиваем лаги Муксера: меньше сообщений в очереди
            muxer_capacity: 256, // Было 32
            tcp_stream_capacity: 16,
            udp_stream_capacity: 32,

            // 2. Делаем чанки меньше для более быстрого срабатывания Backpressure
            tcp_chunk_size: 4 * 1024, // Было 16KB

            // 3. АСИММЕТРИЧНЫЕ БУФЕРЫ TCP (Магия хорошего Upload)
            tcp_rx_heavy: 256 * 1024, // 1 МБ! Качаем на все бабки (Быстрый Download)
            tcp_tx_heavy: 32 * 1024,  // 64 КБ! Микро-буфер отдачи (Убивает Bufferbloat на Upload)

            tcp_rx_light: 16 * 1024,
            tcp_tx_light: 16 * 1024,

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
