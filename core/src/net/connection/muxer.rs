use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use crate::net::network::NetworkConfig;
use crate::nrxp::FrameType;

// Вспомогательная структура для отдельного TLS-соединения
#[derive(Clone)]
struct MuxLeg {
    control_tx: Sender<MuxMessage>,
    data_tx: Sender<MuxMessage>,
}

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
    legs: Arc<DashMap<u32, MuxLeg>>,
    streams: Arc<DashMap<u32, Sender<Bytes>>>,
    id_gen: Arc<IdGenerator>,
    leg_selector: Arc<AtomicU32>,
}

impl Muxer {
    pub fn new(is_client: bool) -> Self {
        Self {
            legs: Arc::new(DashMap::new()),
            streams: Arc::new(DashMap::new()),
            id_gen: Arc::new(IdGenerator::new(is_client)),
            leg_selector: Arc::new(AtomicU32::new(0)),
            // leg_id_gen удален!
        }
    }

    // ТЕПЕРЬ leg_id ПЕРЕДАЕТСЯ СНАРУЖИ
    pub fn add_leg(
        &self,
        leg_id: u32,
        control_tx: Sender<MuxMessage>,
        data_tx: Sender<MuxMessage>,
    ) {
        self.legs.insert(
            leg_id,
            MuxLeg {
                control_tx,
                data_tx,
            },
        );
        netrunner_logger::info!(leg_id, "MUXER: Leg registered");
    }

    pub fn remove_leg(&self, leg_id: u32) {
        self.legs.remove(&leg_id);
        netrunner_logger::info!(leg_id, "MUXER: Leg removed");
    }

    pub fn active_legs_count(&self) -> usize {
        self.legs.len()
    }

    // Возвращаем кортеж (leg_id, MuxLeg), чтобы знать, кого удалять в случае ошибки
    fn select_leg(&self, frame_type: &FrameType) -> Option<(u32, MuxLeg)> {
        if self.legs.is_empty() {
            return None;
        }

        match frame_type {
            FrameType::UdpData | FrameType::UdpConnect => {
                // Пытаемся взять UDP ногу (1), если её нет — берем TCP (0) как фоллбэк
                if let Some(leg) = self.legs.get(&1) {
                    Some((1, leg.clone()))
                } else if let Some(leg) = self.legs.get(&0) {
                    Some((0, leg.clone()))
                } else {
                    None
                }
            }
            _ => {
                // Пытаемся взять TCP ногу (0), фоллбэк на UDP (1)
                if let Some(leg) = self.legs.get(&0) {
                    Some((0, leg.clone()))
                } else if let Some(leg) = self.legs.get(&1) {
                    Some((1, leg.clone()))
                } else {
                    None
                }
            }
        }
    }

    pub async fn send_to_network(&self, message: MuxMessage) -> Result<(), String> {
        let (leg_id, leg) = self
            .select_leg(&message.frame_type)
            .ok_or_else(|| "MUXER: No active legs available".to_string())?;

        let target_tx = match message.frame_type {
            FrameType::Connect
            | FrameType::Close
            | FrameType::UdpConnect
            | FrameType::Handshake => &leg.control_tx,
            _ => &leg.data_tx,
        };

        // Если канал мертв (TunnelEngine упал), удаляем ногу из роутинга!
        if let Err(e) = target_tx.send(message).await {
            self.remove_leg(leg_id);
            return Err(format!("MUXER: Leg {} died during send: {}", leg_id, e));
        }

        Ok(())
    }

    pub async fn send_data_safe(
        &self,
        stream_id: u32,
        mut data: Bytes,
        is_udp: bool,
    ) -> Result<(), String> {
        const MAX_PAYLOAD_CHUNK: usize = 1300;
        let frame_type = if is_udp {
            FrameType::UdpData
        } else {
            FrameType::Data
        };

        while !data.is_empty() {
            let chunk_size = std::cmp::min(data.len(), MAX_PAYLOAD_CHUNK);
            let chunk = data.split_to(chunk_size);

            self.send_to_network(MuxMessage {
                stream_id,
                frame_type,
                data: chunk,
            })
            .await?;

            if !data.is_empty() {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }

    pub async fn send_control(
        &self,
        stream_id: u32,
        f_type: FrameType,
        data: Bytes,
    ) -> Result<(), String> {
        self.send_to_network(MuxMessage {
            stream_id,
            frame_type: f_type,
            data,
        })
        .await
    }

    pub fn register_stream(&self, stream_id: u32, tx: Sender<Bytes>) {
        self.streams.insert(stream_id, tx);
    }

    pub fn remove_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    pub async fn dispatch_to_local(&self, stream_id: u32, data: Bytes) {
        if let Some(tx) = self.streams.get(&stream_id) {
            if let Err(_) = tx.send(data).await {
                self.remove_stream(stream_id);
            }
        }
    }
}
