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

/// MTU-aware defaults.
///
/// TCP socket buffers scale with the MTU so that the initial smoltcp window
/// always fits at least `WINDOW_SEGMENTS` back-to-back segments.  Channel
/// capacity is sized to hold at most `CHANNEL_PACKETS` MTU-sized packets.
impl NetworkConfig {
    pub fn new(system_mtu: usize) -> Self {
        // Keep a minimum useful MTU even if the caller supplies something tiny.
        let mtu = system_mtu.max(576);

        // Minimum number of segments that must fit in a full TCP RX/TX buffer.
        const BULK_WINDOW_SEGMENTS: usize = 128;
        const LIGHT_WINDOW_SEGMENTS: usize = 32;

        // How many messages the Tokio mpsc channels hold.
        //
        // 🔥 ANTI-BUFFERBLOAT: this is the dominant app-layer queue on every
        // tunnel leg. A single server→leg data message can be up to one read
        // buffer (~180 KB), so 128 slots meant up to ~23 MB of in-flight data
        // QUEUED per leg. After a speedtest that reservoir is full of data for
        // streams the app already closed; the downlink wastes seconds draining
        // it (observed: mux_dispatch no_stream ≫ ok, RTT → 1.3 s, tunnel "dies").
        // 16 slots bounds the per-leg queue ~8× lower so it drains in ~1 s and
        // RTT stays low, while still keeping the writer fed for full throughput.
        const CHANNEL_PACKETS: usize = 16;

        // Payload bytes per segment (no IP/TCP headers in the smoltcp buffer).
        let seg = mtu.saturating_sub(40).max(512); // subtract typical IP+TCP overhead

        // Round up to the nearest 4 KB for alignment.
        let round = |n: usize| ((n + 4095) / 4096) * 4096;

        let tcp_heavy = round(seg * BULK_WINDOW_SEGMENTS);
        let tcp_light = round(seg * LIGHT_WINDOW_SEGMENTS);

        Self {
            mtu,
            connection_buf_size: tcp_heavy,
            tcp_buffer_size: tcp_heavy,
            udp_buffer_size: tcp_light,
            // Read chunks up to one smoltcp frame payload; larger values just
            // add latency without improving throughput.
            tcp_chunk_size: 64 * 1024,

            channel_capacity: CHANNEL_PACKETS,

            tcp_rx_heavy: tcp_heavy,
            tcp_tx_heavy: tcp_heavy,
            tcp_rx_light: tcp_light,
            tcp_tx_light: tcp_light,

            udp_buf_heavy: tcp_heavy,
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
