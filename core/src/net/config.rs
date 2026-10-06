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

    /// Ёмкость Tokio-каналов потоков (в сообщениях). Маленькая — против bufferbloat.
    pub channel_capacity: usize,
    /// Ёмкость каналов control/data ОДНОЙ ноги туннеля (в сообщениях).
    ///
    /// Канал ноги — общая FIFO для всех потоков на ней, перед честной очередью
    /// писателя. Раньше он был `channel_capacity` (64 сообщения по ≤64 КБ = 4 МБ):
    /// мелкий поток стоял в конце очереди из чужих массивных сообщений и под нагрузкой
    /// получал +100…400 мс задержки. Глубину «в полёте» (BDP) держит буфер сокета ноги
    /// (`buftune`), а не этот канал, поэтому он может быть коротким без потери скорости.
    pub leg_channel_capacity: usize,

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

        // How many messages the per-STREAM Tokio mpsc channels hold (each message is up
        // to `BRIDGE_READ_CHUNK` = 64 KB).
        //
        // 🔥 ANTI-BUFFERBLOAT: this used to be 64 on the theory that the channel has to
        // hold a BDP at high RTT. It does not: the depth that fills a long fat pipe is
        // the leg socket's buffer (`buftune`, ~2×BDP) and, for downloads, the credit
        // window. A deep per-stream channel only lets the app run ahead of the real
        // network: 64 slots = 4 MB per channel, so 8 parallel uploads parked ~60 MB
        // inside the client, kept the engine saturated with bulk packets and added
        // 100+ ms to every other flow. Measured in the netns stand (8 parallel uploads,
        // 1 Gbit): UDP echo p50 113 ms at 64 → 60 ms at 16; TCP small-request p50
        // 134 → 89 ms; aggregate throughput, CPU per GB and 200 ms-RTT throughput
        // unchanged; 2 Gbit downloads unchanged.
        const CHANNEL_PACKETS: usize = 16;

        // Messages queued in FRONT OF a leg's fair writer, shared by every stream on
        // the leg. Measured in the netns stand (8 parallel uploads, 1 Gbit): UDP echo
        // p50 121 ms at 64, 70 ms at 16, 61 ms at 8; TCP small-request p50 156 → 89 →
        // 81 ms, aggregate throughput unchanged (also at 200 ms RTT / 300 Mbit, where
        // the kernel socket buffer — not this channel — carries the BDP).
        const LEG_CHANNEL_MESSAGES: usize = 16;

        // Payload bytes per segment (no IP/TCP headers in the smoltcp buffer).
        let seg = mtu.saturating_sub(40).max(512); // subtract typical IP+TCP overhead

        // Round up to the nearest 4 KB for alignment.
        let round = |n: usize| n.div_ceil(4096) * 4096;

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
            leg_channel_capacity: LEG_CHANNEL_MESSAGES,

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
