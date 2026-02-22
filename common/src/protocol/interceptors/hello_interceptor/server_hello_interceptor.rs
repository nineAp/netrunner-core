use bytes::{Buf, Bytes};

use crate::{
    protocol::interceptors::{
        error_interceptor::interceptor_error::{ErrorAction, ErrorType, InterceptorError},
        interceptor::Interceptor,
    },
    tlseng::tls::{ProtocolVersion, ServerHello},
};

impl Interceptor for ServerHello {
    type Error = InterceptorError;

    fn can_handle(bytes: &bytes::BytesMut) -> bool {
        // Минимальный ServerHello:
        // Version(2) + Random(32) + SessionID_len(1) + Cipher(2) + Compression(1) = 38 байт
        bytes.len() >= 38
    }

    fn intercept(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized,
    {
        // 1. Базовая проверка длины (базовые поля до компрессии включительно)
        if bytes.len() < 38 {
            return Ok(None);
        }

        // 2. Version (2 bytes)
        let raw_version = bytes.get_u16();
        let version = ProtocolVersion::try_from(raw_version).map_err(|e| {
            InterceptorError::new(
                ErrorType::Tls(e),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&raw_version.to_be_bytes()),
            )
        })?;

        // 3. Random (32 bytes)
        let mut random = [0u8; 32];
        bytes.copy_to_slice(&mut random);

        // 4. Session ID (1 byte len + data)
        let session_id_len = bytes.get_u8() as usize;
        if bytes.len() < session_id_len {
            return Ok(None);
        }
        let session_id = bytes.split_to(session_id_len).freeze();

        // 5. Cipher Suite (2 bytes)
        if bytes.len() < 2 {
            return Ok(None);
        }
        let cipher_suite = bytes.get_u16();

        // 6. Compression Method (1 byte)
        if bytes.len() < 1 {
            return Ok(None);
        }
        let _compression = bytes.get_u8();

        // 7. Extensions (2 bytes len + data)
        // Если после компрессии байтов нет — расширений просто нет.
        if bytes.is_empty() {
            return Ok(Some(Self {
                version,
                random,
                session_id,
                cipher_suite,
                extensions: Bytes::new(),
            }));
        }

        // Если байты есть, проверяем заголовок длины расширений
        if bytes.len() < 2 {
            return Ok(None);
        }
        let extensions_len = bytes.get_u16() as usize;

        if bytes.len() < extensions_len {
            return Ok(None);
        }

        let extensions = bytes.split_to(extensions_len).freeze();

        Ok(Some(Self {
            version,
            random,
            session_id,
            cipher_suite,
            extensions,
        }))
    }
}
