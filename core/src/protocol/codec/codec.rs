use bytes::{Bytes, BytesMut};

use crate::crypto::aead::AeadPacker;
use crate::crypto::chacha::ChaChaCipher;
use crate::crypto::session::SessionKeys;
use crate::protocol::codec::bridge::TlsBridge;
use crate::protocol::codec::frame::{Frame, FrameHeader, FrameType};
use crate::protocol::codec::padding::Padding;
use crate::protocol::errors::{ErrorAction, ErrorStage, TlsError};
use crate::protocol::parser::parser::Parser;
use crate::tlseng::profile::{BrowserProfile, ServerProfile};

pub struct Codec {
    crypto: ChaChaCipher,
    pub session_keys: SessionKeys,
    staging: BytesMut,
}

impl Codec {
    pub fn new(is_initiator: bool) -> Self {
        Self {
            crypto: ChaChaCipher::new(),
            session_keys: SessionKeys::new(is_initiator),
            staging: BytesMut::new(),
        }
    }

    pub fn make_client_handshake(
        &mut self,
        profile: &BrowserProfile,
        host: &str,
    ) -> Result<Bytes, TlsError> {
        Ok(TlsBridge::wrap_client_hello(
            profile,
            host,
            &self.session_keys,
        ))
    }

    pub fn make_server_handshake(&mut self, buffer: &mut BytesMut) -> Result<Bytes, TlsError> {
        let client_msg = TlsBridge::unpack_handshake(buffer)?.ok_or_else(|| {
            TlsError::new(
                ErrorStage::Handshake("No CH"),
                ErrorAction::Wait,
                Bytes::new(),
            )
        })?;

        let server_hello_record = TlsBridge::wrap_server_hello(
            &client_msg,
            &mut self.session_keys,
            &ServerProfile::MODERN,
        )?;

        let (w_key, w_iv, r_key, r_iv) = self.session_keys.get_aead_parameters();
        self.crypto.set_keys(w_key, w_iv, r_key, r_iv);

        Ok(server_hello_record)
    }
    pub fn process_handshake(&mut self, buffer: &mut BytesMut) -> Result<(), TlsError> {
        let mes_opt = TlsBridge::unpack_handshake(buffer)?;
        let mes = mes_opt.ok_or_else(|| {
            TlsError::new(
                ErrorStage::Handshake("Incomplete record"),
                ErrorAction::Wait,
                Bytes::new(),
            )
        })?;

        let (w_key, w_iv, r_key, r_iv) = self
            .session_keys
            .update_keys(mes.random(), mes.extensions(), false)
            .map_err(|e| {
                netrunner_logger::error!(error = %e, "Client failed to update keys from ServerHello");
                TlsError::new(
                    ErrorStage::Handshake("Keys update error"),
                    ErrorAction::Drop,
                    Bytes::new(),
                )
            })?;

        self.crypto.set_keys(w_key, w_iv, r_key, r_iv);
        Ok(())
    }

    pub async fn try_handshake(&mut self, buffer: &mut BytesMut) -> Result<bool, TlsError> {
        match self.process_handshake(buffer) {
            Ok(_) => Ok(true),
            Err(e) if e.action == ErrorAction::Wait => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn outbound(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        let padding = Padding::generate_padding();

        let tag = self.session_keys.generate_auth_tag();
        netrunner_logger::debug!(
            step = %(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 60),
            auth_key_hash = %hex::encode(&self.session_keys.auth_key[..4]),
            generated_tag = %hex::encode(&tag[..4]),
            "OUTBOUND: Generated auth tag"
        );

        let header = FrameHeader {
            auth_tag: [0u8; 16],
            stream_id,
            frame_type,
            payload_len: payload.len() as u16,
            padding_len: padding.len as u16,
        };

        let frame = Frame {
            header,
            payload,
            padding: padding.data,
        };
        let mut frame_bytes = frame.into_bytes(&tag);

        let encrypted_payload = self.crypto.encrypt(&mut frame_bytes).map_err(|e| {
            netrunner_logger::error!("Encryption failed: {:?}", e);
            TlsError::new(
                ErrorStage::Tls("Encryption failed"),
                ErrorAction::Drop,
                Bytes::new(),
            )
        })?;

        Ok(TlsBridge::pack_app_data(encrypted_payload))
    }

    pub fn encrypt_data(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        data: Bytes,
    ) -> Result<Bytes, TlsError> {
        self.outbound(stream_id, frame_type, data)
    }

    pub fn inbound(&mut self, buffer: &mut BytesMut) -> Result<Option<Frame>, TlsError> {
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        while let Some(app_data) = TlsBridge::unpack_app_data(buffer)? {
            let mut data_to_decrypt = BytesMut::from(app_data.payload);

            let decrypted = self.crypto.decrypt(&mut data_to_decrypt).map_err(|_| {
                TlsError::new(
                    ErrorStage::Tls("Decr error"),
                    ErrorAction::Drop,
                    Bytes::new(),
                )
            })?;

            if decrypted.len() < 16 {
                return Err(TlsError::new(
                    ErrorStage::Tls("Packet too short for auth"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
            }

            let mut received_tag = [0u8; 16];
            received_tag.copy_from_slice(&decrypted[..16]);

            if !self.session_keys.verify_auth_tag(&received_tag) {
                netrunner_logger::error!(
                    expected_hash = %hex::encode(&self.session_keys.auth_key[..4]),
                    received = %hex::encode(&received_tag[..4]),
                    "AUTH MISMATCH: Potential replay or MITM attack. Dropping connection."
                );
                return Err(TlsError::new(
                    ErrorStage::Tls("Auth tag mismatch"),
                    ErrorAction::Drop,
                    Bytes::new(),
                ));
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
            Err(_) => Err(TlsError::new(
                ErrorStage::Tls("Parse error"),
                ErrorAction::Drop,
                Bytes::new(),
            )),
        }
    }
}
