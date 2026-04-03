use std::sync::OnceLock;

use netrunner_logger::warn;

pub static GLOBAL_NET_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mtu: usize,
    pub max_wire_frame_size: usize,
    pub safe_payload_size: usize,

    pub tcp_buffer_size: usize,
    pub udp_buffer_size: usize,
    pub muxer_capacity: usize,
    pub tcp_stream_capacity: usize,
    pub udp_stream_capacity: usize,

    pub smoltcp_socket_buf: usize,
    pub tcp_chunk_size: usize,

    pub tcp_buf_heavy: usize,
    pub tcp_buf_light: usize,

    pub udp_buf_heavy: usize,
    pub udp_meta_heavy: usize,
    pub udp_buf_light: usize,
    pub udp_meta_light: usize,
}
impl NetworkConfig {
    pub fn new(system_mtu: usize) -> Self {
        let transport_overhead = 48;
        let max_wire_frame = system_mtu.saturating_sub(transport_overhead);
        let safe_payload = max_wire_frame.saturating_sub(64);

        let chunk_size = 16 * 1024;
        let heavy_buf = 256 * 1024;

        Self {
            mtu: system_mtu,
            max_wire_frame_size: max_wire_frame,
            safe_payload_size: safe_payload,

            tcp_buffer_size: 8 * 1024,
            udp_buffer_size: 64 * 1024,

            muxer_capacity: 256,
            tcp_stream_capacity: 32,
            udp_stream_capacity: 128,

            smoltcp_socket_buf: heavy_buf,
            tcp_chunk_size: chunk_size,

            tcp_buf_heavy: heavy_buf,
            tcp_buf_light: 32 * 1024,

            udp_buf_heavy: heavy_buf,
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
