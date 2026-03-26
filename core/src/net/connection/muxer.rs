use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{error::SendError, Sender};

use crate::nrxp::FrameType;

struct IdGenerator {
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
    control_tx: Sender<MuxMessage>,
    data_tx: Sender<MuxMessage>,
    streams: Arc<DashMap<u32, Sender<Bytes>>>,
    id_gen: Arc<IdGenerator>,
}

impl Muxer {
    pub fn new(
        control_tx: Sender<MuxMessage>,
        data_tx: Sender<MuxMessage>,
        is_client: bool,
    ) -> Self {
        Self {
            control_tx,
            data_tx,
            streams: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
        }
    }

    pub fn next_id(&self) -> u32 {
        self.id_gen.next()
    }

    pub async fn send_to_network(&self, message: MuxMessage) -> Result<(), SendError<MuxMessage>> {
        self.data_tx.send(message).await
    }

    pub async fn send_data_safe(&self, stream_id: u32, mut data: Bytes) -> Result<(), String> {
        // Лимит полезной нагрузки, чтобы вместе с заголовком и паддингом
        // пакет оставался в пределах ~1400-1450 байт.
        const MAX_PAYLOAD_CHUNK: usize = 1300;

        if data.len() <= MAX_PAYLOAD_CHUNK {
            return self
                .send_to_network(MuxMessage {
                    stream_id,
                    frame_type: FrameType::Data,
                    data,
                })
                .await
                .map_err(|e| e.to_string());
        }

        // Если данных много (например, те самые 4096 байт), режем их на куски
        while !data.is_empty() {
            let chunk_size = std::cmp::min(data.len(), MAX_PAYLOAD_CHUNK);
            let chunk = data.split_to(chunk_size);

            self.send_to_network(MuxMessage {
                stream_id,
                frame_type: FrameType::Data,
                data: chunk,
            })
            .await
            .map_err(|e| e.to_string())?;

            // Небольшая уступка планировщику, чтобы не забить канал мгновенно
            tokio::task::yield_now().await;
        }

        Ok(())
    }

    pub async fn send_control(
        &self,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), String> {
        self.control_tx
            .send(MuxMessage {
                stream_id,
                frame_type: f_type,
                data,
            })
            .await
            .map_err(|e| e.to_string())
    }

    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) {
        self.streams.insert(stream_id, tx);
    }

    pub fn remove_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        let tx = self.streams.get(&stream_id).map(|r| r.value().clone());

        if let Some(tx) = tx {
            if let Err(_e) = tx.send(data).await {
                netrunner_logger::warn!(
                    stream_id,
                    "MUXER: [INBOUND_ERR] Local channel closed, dropping packet"
                );
                self.remove_stream(stream_id);
            }
        } else {
            netrunner_logger::trace!(
                stream_id,
                len = data.len(),
                "MUXER: [IGNORE] Received data for already closed stream (draining pipe)"
            );
        }
    }
}
