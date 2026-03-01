use crate::protocol::codec::frame::FrameType;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tracing::error;

pub struct IdGenerator {
    counter: AtomicU32,
}

impl IdGenerator {
    pub fn new(is_client: bool) -> Self {
        let start = if is_client { 1 } else { 2 };
        Self {
            counter: AtomicU32::new(start),
        }
    }

    pub fn next(&self) -> u32 {
        self.counter.fetch_add(2, Ordering::Relaxed)
    }
}

pub struct MuxMessage {
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub data: Bytes,
}

#[derive(Clone)]
pub struct Muxer {
    pub to_network: Sender<MuxMessage>,
    streams: Arc<RwLock<HashMap<u32, Sender<Bytes>>>>,
    id_gen: Arc<IdGenerator>,
}

impl Muxer {
    pub fn new(to_network: Sender<MuxMessage>, is_client: bool) -> Self {
        Self {
            to_network,
            streams: Arc::new(RwLock::new(HashMap::new())),
            id_gen: Arc::new(IdGenerator::new(is_client)),
        }
    }

    // Прокси-метод для получения ID
    pub fn next_id(&self) -> u32 {
        self.id_gen.next()
    }

    pub async fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) {
        let mut lock = self.streams.write().await;
        lock.insert(stream_id, tx);
        // ДОБАВЬ ЭТО:
        tracing::debug!(
            stream_id,
            total_active = lock.len(),
            "STREAMS_MAP_UPDATE: Registered new stream"
        );
    }
    pub async fn remove_stream(&self, stream_id: u32) {
        self.streams.write().await.remove(&stream_id);
    }

    /// Отправляет входящие данные конкретному локальному обработчику
    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        // Асинхронный лок сам умеет корректно работать с .await
        let tx = self.streams.read().await.get(&stream_id).cloned();

        if let Some(tx) = tx {
            if tx.send(data).await.is_err() {
                self.remove_stream(stream_id).await;
            }
        } else {
            error!(stream_id, "MUXER: Received data for UNKNOWN stream_id");
        }
    }
}
