use std::sync::Arc;

use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc::Receiver,
};
use tracing::{debug, error};

use crate::{
    protocol::{codec::codec::Codec, errors::ErrorAction},
    proxy::connection::{handler::StreamHandler, muxer::MuxMessage},
};

pub struct TunnelEngine {
    pub inbound: OwnedReadHalf,
    pub outbound: OwnedWriteHalf,
    pub codec: Codec,
    pub read_buf: BytesMut,
    pub mux_rx: Receiver<MuxMessage>,
    pub handler: Arc<StreamHandler>, // Добавь это вместо прямого вызова логики
}

impl TunnelEngine {
    pub async fn run(self) -> Result<(), String> {
        let mut inbound = self.inbound;
        let mut outbound = self.outbound;
        let mut codec = self.codec;
        let mut read_buf = self.read_buf;
        let mut mux_rx = self.mux_rx;
        let handler = self.handler;
        loop {
            tokio::select! {
                res = Self::process_inbound(&mut inbound, &mut codec, &mut read_buf, &handler) => {
                    res?
                }

                // НУЖНО ОТПРАВИТЬ В СЕТЬ (В сторону удаленного прокси)
                Some(msg) = mux_rx.recv() => {
                    Self::handle_outbound( &mut outbound, &mut codec, msg).await?;
                }
            }
        }
    }

    async fn process_inbound(
        inbound: &mut OwnedReadHalf,
        codec: &mut Codec,
        read_buf: &mut BytesMut,
        handler: &Arc<StreamHandler>,
    ) -> Result<(), String> {
        let n = inbound
            .read_buf(read_buf)
            .await
            .map_err(|e| e.to_string())?;

        if n == 0 && read_buf.is_empty() {
            return Err("EOF".into());
        }

        loop {
            match codec.inbound(read_buf) {
                // 1. Успешно достали фрейм
                Ok(Some(frame)) => {
                    handler.handle(frame).await;
                }
                // 2. Данных в буфере недостаточно (нужно подождать еще)
                Ok(None) => break,

                // 3. Ошибка кодека
                Err(e) => {
                    // Если кодек говорит "подожди", выходим из цикла парсинга
                    if e.action == ErrorAction::Wait {
                        break;
                    }
                    // Иначе — это реальная проблема (кривой TLS и т.д.)
                    error!(error = ?e, "Codec inbound failed");
                    return Err(format!("Codec error: {:?}", e));
                }
            }
        }
        Ok(())
    }

    async fn handle_outbound(
        outbound: &mut OwnedWriteHalf,
        codec: &mut Codec,
        msg: MuxMessage,
    ) -> Result<(), String> {
        // 1. Шифруем данные, используя только кодек
        match codec.encrypt_data(msg.stream_id, msg.frame_type, msg.data) {
            Ok(pkt) => {
                // 2. Пишем в сокет, используя только outbound
                outbound
                    .write_all(&pkt)
                    .await
                    .map_err(|e| {
                        error!(stream_id = msg.stream_id, error = %e, "Failed to write encrypted data to network");
                        e.to_string()
                    })?;
                debug!(stream_id = msg.stream_id, "Outbound packet sent");
                Ok(())
            }
            Err(e) => {
                error!(stream_id = msg.stream_id, error = ?e, "Encryption failed for outbound message");
                Err(format!("Encryption error: {:?}", e))
            }
        }
    }
}
