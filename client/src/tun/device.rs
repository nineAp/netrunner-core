use std::{
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::BytesMut;
use smoltcp::{
    phy::{self, Device, DeviceCapabilities},
    time::Instant,
};
use tokio::sync::mpsc;

// --- TokenBuffer (без изменений, он у тебя отличный) ---
const TOKEN_BUFFER_LIST_MAX_SIZE: usize = 64;
static TOKEN_BUFFER_LIST: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

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

// --- VirtTunDevice ---
pub struct VirtTunDevice {
    capabilities: DeviceCapabilities,
    rx_queue: mpsc::UnboundedReceiver<TokenBuffer>, // smoltcp читает отсюда
    tx_queue: mpsc::UnboundedSender<TokenBuffer>,   // smoltcp пишет сюда
    rx_avail: Arc<AtomicBool>,
}

impl VirtTunDevice {
    pub fn new(
        capabilities: DeviceCapabilities,
    ) -> (
        Self,
        mpsc::UnboundedSender<TokenBuffer>, // Канал, чтобы закидывать пакеты в smoltcp
        mpsc::UnboundedReceiver<TokenBuffer>, // Канал, чтобы забирать готовые пакеты из smoltcp
        Arc<AtomicBool>,
    ) {
        let (to_smoltcp_tx, to_smoltcp_rx) = mpsc::unbounded_channel();
        let (from_smoltcp_tx, from_smoltcp_rx) = mpsc::unbounded_channel();
        let rx_avail = Arc::new(AtomicBool::new(false));

        let device = Self {
            capabilities,
            rx_queue: to_smoltcp_rx,
            tx_queue: from_smoltcp_tx,
            rx_avail: rx_avail.clone(),
        };

        (device, to_smoltcp_tx, from_smoltcp_rx, rx_avail)
    }

    #[inline]
    pub fn mark_rx_available(&self) {
        self.rx_avail.store(true, Ordering::Release);
    }
}

impl Device for VirtTunDevice {
    type RxToken<'a> = VirtRxToken<'a>;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Ok(buffer) = self.rx_queue.try_recv() {
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
        let _ = self.0.tx_queue.send(buffer);
        result
    }
}
