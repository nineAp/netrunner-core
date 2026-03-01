use bytes::{Bytes, BytesMut};

use crate::crypto::aead::AeadPacker;
use crate::crypto::chacha::ChaChaCipher;
use crate::crypto::session::SessionKeys;
use crate::protocol::codec::bridge::TlsBridge;
use crate::protocol::codec::frame::{Frame, FrameHeader, FrameType};
use crate::protocol::codec::padding::Padding;
use crate::protocol::errors::{ErrorAction, ErrorStage, TlsError};
use crate::protocol::parser::parser::Parser;
use crate::tlseng::profile::BrowserProfile;

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
        let pub_key = self.session_keys.ecdh.public_key.to_bytes();

        // 2. Передаем его в мост
        Ok(TlsBridge::wrap_client_hello(
            profile,
            host,
            &pub_key,
            self.session_keys.salt.get_local(),
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

        let server_pub_key = self.session_keys.ecdh.public_key.to_bytes();
        let server_hello_record = TlsBridge::wrap_server_hello(
            &client_msg,
            &server_pub_key,
            self.session_keys.salt.get_local(),
        )?;

        let (w_key, w_iv, r_key, r_iv) = self
            .session_keys
            .update_keys(client_msg.random(), client_msg.extensions(), true)
            .map_err(|e| {
                tracing::error!(error = %e, "Server failed to update keys from ClientHello");
                TlsError::new(
                    ErrorStage::Handshake("Key Err"),
                    ErrorAction::Drop,
                    Bytes::new(),
                )
            })?;

        // Инициализируем шифратор сервера
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

        // ОБНОВЛЕНИЕ КЛЮЧЕЙ НА КЛИЕНТЕ
        // Передаем false, так как клиент ПАРСИТ ServerHello (смещение 4 байта)
        let (w_key, w_iv, r_key, r_iv) = self
            .session_keys
            .update_keys(mes.random(), mes.extensions(), false)
            .map_err(|e| {
                tracing::error!(error = %e, "Client failed to update keys from ServerHello");
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

        let mut frame_bytes = frame.into_bytes();

        // ВАЖНО: вызываем шифрование ОДИН РАЗ.
        // Метод encrypt возвращает Result<Bytes, chacha20poly1305::Error>
        // Мы вручную превращаем его ошибку в твой TlsError.
        let encrypted_payload = self.crypto.encrypt(&mut frame_bytes).map_err(|e| {
            tracing::error!("Encryption failed: {:?}", e);
            TlsError::new(
                ErrorStage::Tls("Encryption failed"),
                ErrorAction::Drop,
                Bytes::new(),
            )
        })?;

        // Теперь передаем зашифрованные байты в новый метод упаковки
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
        // 1. Сначала проверяем, нет ли уже готового фрейма в staging с прошлого раза
        if !self.staging.is_empty() {
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        // 2. Распаковываем ВСЕ доступные TLS-рекорды из сетевого буфера
        while let Some(app_data) = TlsBridge::unpack_app_data(buffer)? {
            // Берем Bytes напрямую (app_data.payload — это уже Bytes)
            let mut data_to_decrypt = BytesMut::from(app_data.payload);

            // Дешифруем "на месте" (In-place decryption)
            // Твоя библиотека ChaCha скорее всего поддерживает дешифровку прямо в том же буфере
            let decrypted = self.crypto.decrypt(&mut data_to_decrypt).map_err(|_| {
                TlsError::new(
                    ErrorStage::Tls("Decr error"),
                    ErrorAction::Drop,
                    Bytes::new(),
                )
            })?;

            // ВАЖНО: Вместо extend_from_slice (копирование), используем split_off/unsplit или просто Bytes
            // Если staging — это BytesMut, используй put или reserve
            self.staging.extend_from_slice(&decrypted); // Увы, BytesMut требует копирования для конкатенации

            // НО! Мы можем попытаться распарсить фрейм сразу после добавления каждого рекорда
            if let Some(frame) = self.try_parse_frame()? {
                return Ok(Some(frame));
            }
        }

        Ok(None)
    }

    // Выносим парсинг в отдельный метод, чтобы не дублировать код
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
