use std::{
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant as StdInstant,
};

use bytes::BytesMut;
use netrunner_logger::info;
use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};
use tokio::sync::mpsc;

const TOKEN_BUFFER_LIST_MAX_SIZE: usize = 1024;
static TOKEN_BUFFER_LIST: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

pub static GLOBAL_RX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_RX_PACKETS: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TX_PACKETS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_speed_mb_s: f64,
    pub tx_speed_mb_s: f64,
}

pub struct TokenBuffer {
    buffer: BytesMut,
}

impl Drop for TokenBuffer {
    fn drop(&mut self) {
        let mut list = TOKEN_BUFFER_LIST.lock().unwrap();
        if list.len() >= TOKEN_BUFFER_LIST_MAX_SIZE {
            return;
        }
        let empty_buffer = BytesMut::new();
        let mut buffer = mem::replace(&mut self.buffer, empty_buffer);
        buffer.clear();
        list.push(buffer);
    }
}

impl TokenBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        let mut list = TOKEN_BUFFER_LIST.lock().unwrap();
        if let Some(mut buffer) = list.pop() {
            buffer.reserve(cap);
            return Self { buffer };
        }
        Self {
            buffer: BytesMut::with_capacity(cap),
        }
    }
}

impl Deref for TokenBuffer {
    type Target = BytesMut;
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}
impl DerefMut for TokenBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

pub struct VirtTunDevice {
    capabilities: DeviceCapabilities,
    rx_queue: mpsc::Receiver<TokenBuffer>, // Входящие из TUN оставляем ограниченными (Backpressure)
    tx_queue: mpsc::UnboundedSender<TokenBuffer>, // 🔥 ФИКС: Исходящие в TUN делаем БЕЗЛИМИТНЫМИ
    rx_avail: Arc<AtomicBool>,

    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,

    last_speed_calc: StdInstant,
    last_rx_bytes: u64,
    last_tx_bytes: u64,
    cached_rx_speed: f64,
    cached_tx_speed: f64,

    last_log_time: StdInstant,
}

impl VirtTunDevice {
    pub fn new(
        capabilities: DeviceCapabilities,
    ) -> (
        Self,
        mpsc::Sender<TokenBuffer>,
        mpsc::UnboundedReceiver<TokenBuffer>,
        Arc<AtomicBool>,
    ) {
        let (to_smoltcp_tx, to_smoltcp_rx) = mpsc::channel(128);
        let (from_smoltcp_tx, from_smoltcp_rx) = mpsc::unbounded_channel(); // 🔥 Безлимитный канал
        let rx_avail = Arc::new(AtomicBool::new(false));

        let now = StdInstant::now();
        let device = Self {
            capabilities,
            rx_queue: to_smoltcp_rx,
            tx_queue: from_smoltcp_tx,
            rx_avail: rx_avail.clone(),

            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,

            last_speed_calc: now,
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            cached_rx_speed: 0.0,
            cached_tx_speed: 0.0,

            last_log_time: now,
        };
        (device, to_smoltcp_tx, from_smoltcp_rx, rx_avail)
    }

    #[inline]
    pub fn mark_rx_available(&self) {
        self.rx_avail.store(true, Ordering::Release);
    }

    pub fn get_stats(&mut self) -> TrafficStats {
        let now = StdInstant::now();
        let elapsed_speed = now.duration_since(self.last_speed_calc).as_secs_f64();

        if elapsed_speed >= 1.0 {
            let rx_diff = self.rx_bytes.saturating_sub(self.last_rx_bytes);
            let tx_diff = self.tx_bytes.saturating_sub(self.last_tx_bytes);

            self.cached_rx_speed = (rx_diff as f64 / 1_048_576.0) / elapsed_speed;
            self.cached_tx_speed = (tx_diff as f64 / 1_048_576.0) / elapsed_speed;

            self.last_rx_bytes = self.rx_bytes;
            self.last_tx_bytes = self.tx_bytes;
            self.last_speed_calc = now;
        }

        TrafficStats {
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
            rx_packets: self.rx_packets,
            tx_packets: self.tx_packets,
            rx_speed_mb_s: self.cached_rx_speed,
            tx_speed_mb_s: self.cached_tx_speed,
        }
    }

    fn check_and_log_stats(&mut self) {
        let now = StdInstant::now();
        if now.duration_since(self.last_log_time).as_secs() >= 5 {
            let stats = self.get_stats();
            info!(
                "TunDevice Traffic: RX: {:.2} MB ({} pkts) | TX: {:.2} MB ({} pkts) | Speed: ↓{:.2} MB/s, ↑{:.2} MB/s",
                stats.rx_bytes as f64 / 1_048_576.0,
                stats.rx_packets,
                stats.tx_bytes as f64 / 1_048_576.0,
                stats.tx_packets,
                stats.rx_speed_mb_s,
                stats.tx_speed_mb_s
            );
            self.last_log_time = now;
        }
    }
}

impl Device for VirtTunDevice {
    type RxToken<'a> = VirtRxToken<'a>;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.check_and_log_stats();
        if let Ok(buffer) = self.rx_queue.try_recv() {
            let len = buffer.len() as u64;
            self.rx_bytes += buffer.len() as u64;
            self.rx_packets += 1;

            GLOBAL_TX_BYTES.fetch_add(len as u64, Ordering::Relaxed);
            GLOBAL_TX_PACKETS.fetch_add(1, Ordering::Relaxed);
            let rx = Self::RxToken {
                buffer,
                phantom_device: PhantomData,
            };
            let tx = VirtTxToken(self);
            return Some((rx, tx));
        }
        self.rx_avail.store(false, Ordering::Release);
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct VirtRxToken<'a> {
    buffer: TokenBuffer,
    phantom_device: PhantomData<&'a VirtTunDevice>,
}

impl phy::RxToken for VirtRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct VirtTxToken<'a>(&'a mut VirtTunDevice);
impl phy::TxToken for VirtTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = TokenBuffer::with_capacity(len);
        unsafe {
            buffer.set_len(len);
        }

        let result = f(&mut buffer);

        self.0.tx_bytes += len as u64;
        self.0.tx_packets += 1;

        GLOBAL_RX_BYTES.fetch_add(len as u64, Ordering::Relaxed);
        GLOBAL_RX_PACKETS.fetch_add(1, Ordering::Relaxed);

        // 🔥 ФИКС: Отправляем в безлимитный канал. Никаких дропов внутри локальной машины!
        let _ = self.0.tx_queue.send(buffer);
        result
    }
}