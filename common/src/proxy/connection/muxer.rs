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

    pub fn next_id(&self) -> u32 {
        self.id_gen.next()
    }

    pub fn try_register_stream(&self, id: u32, tx: tokio::sync::mpsc::Sender<Bytes>) -> bool {
        // 1. Исправлено имя поля: streams вместо active_streams
        // 2. Добавлена аннотация типа для guard, чтобы Rust понимал, что внутри HashMap
        if let Ok(mut guard) = self.streams.try_write() {
            let guard: &mut HashMap<u32, Sender<Bytes>> = &mut *guard;
            guard.insert(id, tx);
            true
        } else {
            false
        }
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

    pub async fn send_control(
        &self,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), String> {
        self.to_network
            .send(MuxMessage {
                stream_id,
                frame_type: f_type,
                data,
            })
            .await
            .map_err(|e| e.to_string())
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
