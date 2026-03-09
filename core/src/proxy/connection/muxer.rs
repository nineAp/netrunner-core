use crate::protocol::codec::frame::FrameType;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tracing::{debug, error};

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

    pub async fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) {
        let mut lock = self.streams.write().await;
        lock.insert(stream_id, tx);
        tracing::debug!(
            stream_id,
            total_active = lock.len(),
            "MUXER: [REGISTER] Stream added"
        );
    }

    pub async fn remove_stream(&self, stream_id: u32) {
        let mut lock = self.streams.write().await;
        lock.remove(&stream_id); // Просто удаляем, если есть
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

    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        let tx = {
            let lock = self.streams.read().await;
            lock.get(&stream_id).cloned()
        };

        if let Some(tx) = tx {
            if data.is_empty() {
                tracing::debug!(stream_id, "MUXER: [EOF] Forwarding EOF to local handler");
            } else {
                tracing::trace!(
                    stream_id,
                    len = data.len(),
                    "MUXER: [DISPATCH] Sending data"
                );
            }

            if let Err(_e) = tx.send(data).await {
                tracing::debug!(
                    stream_id,
                    "MUXER: [WARN] Local channel closed, dropping packet"
                );
                self.remove_stream(stream_id).await;
            }
        } else {
            tracing::trace!(
                stream_id,
                "MUXER: [IGNORE] Packet for already closed stream"
            );
        }
    }
}
