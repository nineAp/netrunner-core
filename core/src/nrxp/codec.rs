use bytes::{Bytes, BytesMut};
use crate::crypto::{AeadPacker, ChaChaCipher, ChaChaStream, SessionAuth};
use crate::nrxp::bridge::TlsBridge;
use crate::nrxp::errors::{ErrorAction, ErrorStage, TlsError};
use crate::nrxp::frame::{Frame, FrameType};
use crate::parser::Parser;

pub struct TxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
}

impl TxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth) -> Self {
        Self { crypto, auth }
    }

    pub fn encode_frame(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        let tag = self.auth.generate_current_tag();
        let frame = Frame::new(stream_id, frame_type, payload);
        let mut frame_bytes = frame.into_bytes(&tag);

        let encrypted_payload = self.crypto.encrypt(&mut frame_bytes).map_err(|e| {
            netrunner_logger::error!("Encryption failed: {:?}", e);
            TlsError::new(ErrorStage::Tls("Encryption failed"), ErrorAction::Drop, Bytes::new())
        })?;

        Ok(TlsBridge::pack_app_data(encrypted_payload))
    }
}

pub struct RxCodec {
    crypto: ChaChaStream,
    auth: SessionAuth,
    staging: BytesMut,
}

impl RxCodec {
    pub fn new(crypto: ChaChaStream, auth: SessionAuth, staging: BytesMut) -> Self {
        Self { crypto, auth, staging }
    }

    pub fn decode_inbound(&mut self, buffer: &mut BytesMut) -> Result<Option<Frame>, TlsError> {
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        while let Some(app_data) = TlsBridge::unpack_app_data(buffer).map_err(|e| {
            self.staging.clear();
            e
        })? {
            let mut data_to_decrypt = BytesMut::from(app_data.payload);
            
            let decrypted = self.crypto.decrypt(&mut data_to_decrypt).map_err(|e| {
                self.staging.clear();
                let bad_data = Bytes::copy_from_slice(&data_to_decrypt[..data_to_decrypt.len().min(32)]);
                TlsError::new(ErrorStage::Tls("AEAD Decrypt Failed"), ErrorAction::Drop, bad_data)
            })?;

            if decrypted.len() < 16 {
                self.staging.clear();
                return Err(TlsError::new(ErrorStage::Tls("Packet too short"), ErrorAction::Drop, Bytes::new()));
            }

            let mut received_tag = [0u8; 16];
            received_tag.copy_from_slice(&decrypted[..16]);

            if !self.auth.verify_tag(&received_tag) {
                self.staging.clear();
                return Err(TlsError::new(ErrorStage::Tls("Auth mismatch"), ErrorAction::Drop, Bytes::new()));
            }

            self.staging.extend_from_slice(&decrypted);

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
            Err(_) => {
                self.staging.clear();
                Err(TlsError::new(ErrorStage::Tls("Parse error"), ErrorAction::Drop, Bytes::new()))
            }
        }
    }
}

pub struct Codec {
    tx: Option<TxCodec>,
    rx: Option<RxCodec>,
}

impl Codec {
    // УБРАЛИ staging из аргументов
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