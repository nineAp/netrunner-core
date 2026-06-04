use crate::crypto::{AeadPacker, ChaChaCipher, ChaChaStream, SessionAuth};
use crate::nrxp::bridge::TlsBridge;
use crate::nrxp::errors::{ErrorAction, ErrorStage, TlsError};
use crate::nrxp::frame::{Frame, FrameType};
use crate::parser::Parser;
use bytes::{Bytes, BytesMut};
use netrunner_logger::trace;

pub struct TxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
}

impl TxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth) -> Self {
        Self { crypto, auth }
    }

    pub(crate) fn encode_frame(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        let tag = self.auth.generate_current_tag();
        let frame = Frame::new(stream_id, frame_type, payload);

        // frame_bytes — это BytesMut. Выделяем и формируем заголовок.
        let mut frame_bytes = frame.into_bytes(&tag);

        // Шифруем In-Place. Массив frame_bytes мутирует и вырастает на 16 байт тега AEAD.
        self.crypto.encrypt(&mut frame_bytes).map_err(|e| {
            netrunner_logger::error!("Encryption failed: {:?}", e);
            TlsError::new(
                ErrorStage::Tls("Encryption failed"),
                ErrorAction::Drop,
                Bytes::new(),
            )
        })?;

        // Только в самом конце замораживаем буфер (Zero-Copy операция) для отправки
        Ok(TlsBridge::pack_app_data(frame_bytes.freeze()))
    }
}

pub struct RxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
    staging: BytesMut,
}

impl RxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth, staging: BytesMut) -> Self {
        Self {
            crypto,
            auth,
            staging,
        }
    }
    pub(crate) fn decode_inbound(
        &mut self,
        buffer: &mut BytesMut,
    ) -> Result<Option<Frame>, TlsError> {
        // Пытаемся распарсить из того, что уже в staging
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        // Подкачиваем новые данные из TLS Record
        while let Some(app_data) = TlsBridge::unpack_app_data(buffer).map_err(|e| e)? {
            let start_idx = self.staging.len();
            self.staging.extend_from_slice(&app_data.payload);

            let mut data_to_decrypt = self.staging.split_off(start_idx);

            // Шифрование In-Place
            if let Err(_) = self.crypto.decrypt(&mut data_to_decrypt) {
                // Сбрасываем только при ошибке крипто-аутентификации (tampering)
                self.staging.clear();
                return Err(TlsError::new(
                    ErrorStage::Tls("AEAD Decrypt Failed"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            self.staging.unsplit(data_to_decrypt);

            // ИСПРАВЛЕНО: try_parse_frame теперь не сбрасывает буфер при ошибке парсинга
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        Ok(None)
    }

    fn try_parse_frame(&mut self) -> Result<Option<Frame>, TlsError> {
        match Frame::parse(&mut self.staging) {
            Ok(Some(frame)) => Ok(Some(frame)),
            Ok(None) => Ok(None),
            Err(e) => {
                // ИСПРАВЛЕНО: Убрали self.staging.clear().
                // Если парсинг не удался (например, неполный заголовок),
                // мы оставляем staging как есть и ждем новых данных.
                trace!("Frame parse incomplete or waiting for more data: {}", e);
                Ok(None)
            }
        }
    }
}

pub struct Codec {
    tx: Option<TxCodec>,
    rx: Option<RxCodec>,
}

impl Codec {
    pub fn new(cipher: ChaChaCipher, auth_key: [u8; 32]) -> Self {
        let (rx_stream, tx_stream) = cipher.split();
        let auth = SessionAuth::new(auth_key);

        Self {
            tx: Some(TxCodec::new(tx_stream, auth)),
            rx: Some(RxCodec::new(rx_stream, auth, BytesMut::with_capacity(4096))),
        }
    }

    pub fn split(mut self) -> (RxCodec, TxCodec) {
        (
            self.rx.take().expect("RxCodec missing"),
            self.tx.take().expect("TxCodec missing"),
        )
    }
}
