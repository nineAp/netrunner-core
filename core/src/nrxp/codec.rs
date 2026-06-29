use crate::crypto::{AeadPacker, ChaChaCipher, ChaChaStream, SessionAuth};
use crate::nrxp::bridge::TlsBridge;
use crate::nrxp::errors::{ErrorAction, ErrorStage, TlsError};
use crate::nrxp::frame::{Frame, FrameType};
use crate::parser::Parser;
use bytes::{Bytes, BytesMut};

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
        // Drain any complete frame that was left in staging from the previous call.
        // This happens when multiple TLS records arrived in one TCP read and we
        // returned after the first parsed frame, leaving the rest in staging.
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        // Encoding invariant: one TLS ApplicationData record = one encrypted NRXP
        // frame.  We decrypt each record independently into the staging buffer and
        // immediately attempt to parse.  split_off + decrypt_in_place + unsplit is
        // used to keep the decrypted bytes in staging's existing allocation (zero
        // extra allocation on the fast path).
        while let Some(app_data) = TlsBridge::unpack_app_data(buffer)? {
            let start_idx = self.staging.len();
            self.staging.extend_from_slice(&app_data.payload);

            // Split off just the new encrypted bytes; staging[..start_idx] holds
            // any prior plaintext that is still waiting for a parse attempt.
            let mut data_to_decrypt = self.staging.split_off(start_idx);

            if let Err(_) = self.crypto.decrypt(&mut data_to_decrypt) {
                // AEAD failure after a successful TCP delivery means key/nonce
                // mismatch or tampering.  Clear staging to avoid feeding garbled
                // plaintext into the parser on the next call, then signal Drop so
                // the caller tears down and reconnects (fresh keys, nonce=0).
                self.staging.clear();
                return Err(TlsError::new(
                    ErrorStage::Tls("AEAD Decrypt Failed"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            // Re-join: staging now contains [prev_plaintext || new_plaintext].
            // decrypt_in_place shrank data_to_decrypt by 16 (stripped AEAD tag);
            // unsplit handles the adjusted length correctly because the underlying
            // allocation is contiguous and data_to_decrypt is still adjacent.
            self.staging.unsplit(data_to_decrypt);

            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }

            // try_parse_frame returned Ok(None) — this should never happen with the
            // 1:1 TLS-record→NRXP-frame invariant, but if it does (e.g. an empty
            // padding-only frame), we continue to the next TLS record rather than
            // looping indefinitely.  The staging bytes will be parsed on the next
            // decode_inbound call.
        }

        Ok(None)
    }

    fn try_parse_frame(&mut self) -> Result<Option<Frame>, TlsError> {
        match Frame::parse(&mut self.staging) {
            Ok(Some(frame)) => Ok(Some(frame)),
            Ok(None) => Ok(None),
            Err(e) => {
                // Frame::parse only returns Err for protocol-level violations
                // (e.g. unknown FrameType byte) that survive AEAD decryption.
                // This is not a partial-data situation — it means the stream is
                // desynchronised. Drop the leg so reconnect generates fresh keys.
                netrunner_logger::error!(
                    "Frame parse error after AEAD success — dropping leg: {}",
                    e
                );
                self.staging.clear();
                Err(TlsError::new(
                    crate::nrxp::errors::ErrorStage::Tls("Frame parse error"),
                    crate::nrxp::errors::ErrorAction::Drop,
                    bytes::Bytes::new(),
                ))
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
