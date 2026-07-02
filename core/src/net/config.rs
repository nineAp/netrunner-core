//! Глобальная сетевая конфигурация, выводимая из MTU.
//!
//! Все размеры буферов и ёмкости каналов считаются один раз из системного MTU
//! ([`NetworkConfig::new`]) и кладутся в глобальный [`OnceLock`]. Логика проста:
//! буферы TCP-сокетов smoltcp масштабируются так, чтобы окно вмещало нужное число
//! сегментов подряд, а ёмкость mpsc-каналов держится **намеренно маленькой** —
//! это главный рычаг против bufferbloat (см. комментарий к `CHANNEL_PACKETS`).
//!
//! Деление буферов на `heavy`/`light` — это «толстые» потоки (bulk download) против
//! «тонких» (DNS, интерактив): первым нужен большой буфер для throughput, вторым —
//! маленький для низкой задержки.

use netrunner_logger::warn;
use std::sync::OnceLock;

/// Глобально инициализируемая сетевая конфигурация (одна на процесс).
pub static GLOBAL_NET_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

/// Набор размеров буферов и каналов, выведенных из MTU.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Эффективный MTU (не ниже 576).
    pub mtu: usize,
    /// Размер буфера чтения соединения туннеля.
    pub connection_buf_size: usize,
    /// Базовый размер TCP-буфера (для «толстых» потоков).
    pub tcp_buffer_size: usize,
    /// Базовый размер UDP-буфера.
    pub udp_buffer_size: usize,
    /// Сколько байт читать из локального TCP-сокета за один проход.
    pub tcp_chunk_size: usize,

    /// Единая ёмкость всех Tokio-каналов (в пакетах). Маленькая — против bufferbloat.
    pub channel_capacity: usize,

    // ── Буферы TCP-сокетов smoltcp: heavy (bulk) и light (интерактив) ──
    /// RX-буфер «толстого» TCP-сокета.
    pub tcp_rx_heavy: usize,
    /// TX-буфер «толстого» TCP-сокета.
    pub tcp_tx_heavy: usize,
    /// RX-буфер «тонкого» TCP-сокета.
    pub tcp_rx_light: usize,
    /// TX-буфер «тонкого» TCP-сокета.
    pub tcp_tx_light: usize,

    // ── Буферы UDP-сокетов smoltcp: данные + слоты метаданных датаграмм ──
    /// Буфер данных «толстого» UDP-сокета.
    pub udp_buf_heavy: usize,
    /// Слотов метаданных датаграмм у «толстого» UDP-сокета.
    pub udp_meta_heavy: usize,
    /// Буфер данных «тонкого» UDP-сокета.
    pub udp_buf_light: usize,
    /// Слотов метаданных датаграмм у «тонкого» UDP-сокета.
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
        // 🔥 ANTI-BUFFERBLOAT vs HIGH-RTT THROUGHPUT TRADE-OFF:
        // At low RTT (50 ms), 16 slots = ~3 MB queue drains fast. At high RTT
        // (300+ ms), BDP = 300 Mbps × 0.35s ≈ 13 MB required for full throughput.
        // Increased to 64: provides ~11 MB per leg (64 × ~180 KB), matching BDP
        // at high RTT while still preventing pathological post-speedtest queuing.
        // Anti-bufferbloat protection remains via per-stream dispatch backpressure
        // and read-chunk sizing in dispatch_to_local (byte-bounded backlog closes
        // genuinely stalled streams — see STREAM_BACKLOG_MAX_BYTES).
        const CHANNEL_PACKETS: usize = 64;

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

    /// Инициализирует глобальный конфиг из MTU. Повторный вызов безвреден, но
    /// логирует предупреждение (конфиг неизменяем после первой установки).
    pub fn init_global(system_mtu: usize) {
        let config = Self::new(system_mtu);
        if GLOBAL_NET_CONFIG.set(config).is_err() {
            warn!("Global network config was already initialized!");
        }
    }

    /// Доступ к глобальному конфигу. Паникует, если [`init_global`](Self::init_global)
    /// ещё не вызывали — это ошибка порядка инициализации, а не рантайм-ситуация.
    pub fn global() -> &'static Self {
        GLOBAL_NET_CONFIG
            .get()
            .expect("Global NetworkConfig is not initialized! Call init_global() first.")
    }
}
