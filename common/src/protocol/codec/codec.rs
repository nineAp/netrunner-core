use bytes::{Bytes, BytesMut};

use crate::crypto::aead::AeadPacker;
use crate::crypto::chacha::ChaChaCipher;
use crate::crypto::session::SessionKeys;
use crate::protocol::codec::bridges::tls_bridge::TlsBridge;
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
    //maybe generator?
    //should anwer socks5 and open connection to proxy server
    /// Логика для Клиента: Генерирует байты ClientHello для инициализации соединения.
    /// Клиент: генерирует TLS Record [ ClientHello ]
    pub fn make_client_handshake(
        &mut self,
        profile: &BrowserProfile,
        host: &str,
    ) -> Result<Bytes, TlsError> {
        // 1. Извлекаем публичный ключ нашей текущей сессии
        let my_pub_key = self.session_keys.ecdh.public_key.to_bytes();
        // (Убедись, что метод возвращает [u8; 32])

        // 2. Передаем его в мост
        Ok(TlsBridge::wrap_client_hello(
            profile,
            host,
            &my_pub_key,
            self.session_keys.salt.get_local(),
        ))
    }
    /// Сервер: берет буфер, достает ClientHello и генерирует в ответ TLS Record [ ServerHello ]
    pub fn make_server_handshake(&mut self, buffer: &mut BytesMut) -> Result<Bytes, TlsError> {
        // 1. Распаковываем сообщение клиента
        let client_msg = TlsBridge::unpack_handshake(buffer)?.ok_or_else(|| {
            TlsError::new(
                ErrorStage::Handshake("No CH"),
                ErrorAction::Wait,
                Bytes::new(),
            )
        })?;

        // 2. Генерируем ответный ServerHello рекорд
        let server_pub_key = self.session_keys.ecdh.public_key.to_bytes();
        let server_hello_record = TlsBridge::wrap_server_hello(
            &client_msg,
            &server_pub_key,
            self.session_keys.salt.get_local(),
        )?;

        // 3. ОБНОВЛЕНИЕ КЛЮЧЕЙ НА СЕРВЕРЕ
        // Передаем true, так как сервер ПАРСИТ ClientHello (смещение 6 байт)
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
        // Логгируем входящее состояние сетевого буфера (TLS слой)
        if !buffer.is_empty() {
            let header = &buffer[..std::cmp::min(buffer.len(), 5)];
            tracing::debug!(
                buf_len = buffer.len(),
                header_hex = %hex::encode(header),
                "RAW TLS buffer state"
            );
        }

        // --- ШАГ 1: Извлекаем ВСЕ доступные TLS-рекорды и расшифровываем в staging ---
        // Мы крутим цикл, пока TlsBridge может "откусить" целый TLS-рекорд из buffer
        while let Some(app_data) = TlsBridge::unpack_app_data(buffer)? {
            let mut encrypted_chunk = BytesMut::from(app_data.payload.as_ref());
            let raw_len = encrypted_chunk.len();

            // Расшифровываем кусок
            let decrypted_chunk = self.crypto.decrypt(&mut encrypted_chunk).map_err(|e| {
                tracing::error!(len = raw_len, "Decryption failed: {:?}", e);
                TlsError::new(
                    ErrorStage::Tls("Decryption error"),
                    ErrorAction::Drop,
                    Bytes::new(),
                )
            })?;

            // КЛАДЕМ В ЧИСТУЮ ЗОНУ: расшифрованный поток байтов нашего протокола
            self.staging.extend_from_slice(&decrypted_chunk);

            tracing::debug!(
                added = decrypted_chunk.len(),
                total_staging = self.staging.len(),
                "Decrypted data moved to staging"
            );
        }

        // --- ШАГ 2: Парсим Frame из "чистых" данных в staging ---
        if !self.staging.is_empty() {
            // Важно: Frame::parse должен вызывать advance() или split_to() у staging
            match Frame::parse(&mut self.staging) {
                Ok(Some(frame)) => {
                    tracing::info!(
                        stream_id = frame.header.stream_id,
                        "Frame successfully parsed from staging"
                    );
                    return Ok(Some(frame));
                }
                Ok(None) => {
                    tracing::debug!("Frame is incomplete in staging, waiting for more TLS records");
                    return Ok(None);
                }
                Err(e) => {
                    tracing::error!("Frame parse error: {:?}", e);
                    return Err(TlsError::new(
                        ErrorStage::Tls("Frame parse error"),
                        ErrorAction::Drop,
                        Bytes::new(),
                    ));
                }
            }
        }

        Ok(None)
    }
}
