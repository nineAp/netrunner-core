use crate::{
    protocol::{
        codec::{
            codec::Codec,
            frame::{Frame, FrameType},
        },
        errors::ErrorAction,
    },
    proxy::connection::{
        buf_pair::BufPair,
        connection::ConnectionRole,
        handler::spawn_server_target_handler,
        muxer::{MuxMessage, Muxer},
    },
};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::Receiver;
use tracing::{debug, error, info, trace, warn};

pub struct TunnelEngine {
    pub inbound: OwnedReadHalf,
    pub outbound: OwnedWriteHalf,
    pub codec: Codec,
    pub buffers: BufPair,
    pub mux_rx: Receiver<MuxMessage>,
    pub muxer: Muxer,
    pub role: ConnectionRole,
}

impl TunnelEngine {
    pub async fn run(mut self) -> Result<(), String> {
        info!(role = ?self.role, "TunnelEngine spinning up");

        loop {
            tokio::select! {
                // 1. Физический Inbound (Сеть -> Muxer)
                // Теперь возвращает Vec<Frame>, чтобы обработать всё накопленное
                res = Self::process_inbound(&mut self.inbound, &mut self.codec, &mut self.buffers) => {
                    match res {
                        Ok(frames) => {
                            for frame in frames {
                                self.handle_incoming_frame(frame).await;
                            }
                        }
                        Err(e) => {
                            if e == "EOF" {
                                info!("Physical connection closed by remote (EOF)");
                            } else {
                                error!(error = %e, "Critical error in process_inbound");
                            }
                            return Err(e);
                        }
                    }
                }

                // 2. Физический Outbound (Muxer -> Сеть)
                Some(msg) = self.mux_rx.recv() => {
                    if let Err(e) = self.handle_outbound_msg(msg).await {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Логика обработки конкретного фрейма (разгружаем основной loop)
    async fn handle_incoming_frame(&mut self, frame: Frame) {
        let stream_id = frame.header.stream_id;
        let frame_type = frame.header.frame_type;

        trace!(stream_id = frame.header.stream_id, f_type = ?frame.header.frame_type, len = frame.payload.len(), "Engine received frame from network");
        match frame_type {
            FrameType::Connect => {
                match self.role {
                    ConnectionRole::Server => {
                        let target = String::from_utf8_lossy(&frame.payload);
                        info!(stream_id, target = %target, "New Connect request received");
                        spawn_server_target_handler(stream_id, frame.payload, self.muxer.clone())
                            .await;
                    }
                    ConnectionRole::Client => {
                        // Тот самый фикс: клиент получает Connect как подтверждение (ACK)
                        debug!(stream_id, "Connection confirmed by server");
                        self.muxer.dispatch_to_local(stream_id, frame.payload).await;
                    }
                }
            }
            FrameType::Data => {
                self.muxer.dispatch_to_local(stream_id, frame.payload).await;
            }
            FrameType::Close => {
                info!(stream_id, "Received Close frame, tearing down stream");
                // Важно: muxer должен не просто удалить, а послать EOF в локальный канал
                self.muxer.dispatch_to_local(stream_id, Bytes::new()).await;
                self.muxer.remove_stream(stream_id).await;
            }
            _ => debug!(stream_id, ?frame_type, "Received unhandled frame type"),
        }
    }

    /// Вспомогательная функция для чтения из сети
    async fn process_inbound(
        inbound: &mut OwnedReadHalf,
        codec: &mut Codec,
        buffers: &mut BufPair,
    ) -> Result<Vec<Frame>, String> {
        let mut frames = Vec::new();

        // Сначала читаем данные из сокета в буфер
        let n = inbound
            .read_buf(&mut buffers.read_buf)
            .await
            .map_err(|e| e.to_string())?;

        if n == 0 && buffers.read_buf.is_empty() {
            return Err("EOF".into());
        }

        // Теперь пытаемся достать столько фреймов, сколько получится
        loop {
            match codec.inbound(&mut buffers.read_buf) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break, // Больше полных фреймов нет
                Err(e) if e.action == ErrorAction::Wait => break,
                Err(e) => return Err(format!("Codec error: {:?}", e)),
            }
        }

        Ok(frames)
    }

    async fn handle_outbound_msg(&mut self, msg: MuxMessage) -> Result<(), String> {
        match self
            .codec
            .encrypt_data(msg.stream_id, msg.frame_type, msg.data)
        {
            Ok(pkt) => {
                self.outbound
                    .write_all(&pkt)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Err(e) => Err(format!("Encryption error: {:?}", e)),
        }
    }
}
