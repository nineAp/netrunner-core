use bytes::{Buf, Bytes};

use crate::{
    protocol::interceptors::{
        error_interceptor::interceptor_error::{ErrorAction, ErrorType, InterceptorError},
        interceptor::Interceptor,
    },
    tlseng::tls::{ClientHello, ProtocolVersion},
};

impl Interceptor for ClientHello {
    type Error = InterceptorError;

    fn can_handle(bytes: &bytes::BytesMut) -> bool {
        // Мы предполагаем, что HelloHeader уже проверил тип.
        // Здесь можно проверить минимально допустимый размер ClientHello
        // (Version 2 + Random 32 + SessionID_len 1 = 35 байт)
        bytes.len() >= 35
    }

    fn intercept(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error>
    where
        Self: Sized,
    {
        // 1. Проверяем минимальную длину для базовых полей (до Session ID включительно)
        if bytes.len() < 35 {
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

        // 4. Session ID (Variable length: 1 byte len + data)
        let session_id_len = bytes.get_u8() as usize;
        if bytes.len() < session_id_len {
            return Ok(None); // Данные неполные
        }
        let session_id = bytes.split_to(session_id_len).freeze();

        // 5. Cipher Suites (Variable length: 2 bytes len + data)
        if bytes.len() < 2 {
            return Ok(None);
        }
        let ciphers_len = bytes.get_u16() as usize;
        if bytes.len() < ciphers_len {
            return Ok(None);
        }

        let mut cipher_suites = Vec::with_capacity(ciphers_len / 2);
        let mut ciphers_data = bytes.split_to(ciphers_len);
        while ciphers_data.has_remaining() {
            cipher_suites.push(ciphers_data.get_u16());
        }

        // 6. Compression Methods (1 byte len + data) - в TLS 1.3 обычно [0x01, 0x00]
        if bytes.len() < 1 {
            return Ok(None);
        }
        let comp_len = bytes.get_u8() as usize;
        if bytes.len() < comp_len {
            return Ok(None);
        }
        bytes.advance(comp_len); // Мы их просто пропускаем, они не нужны в структуре

        // 7. Extensions (2 bytes len + data)
        if bytes.is_empty() {
            // Расширений может не быть (теоретически в старых TLS)
            return Ok(Some(Self {
                version,
                random,
                session_id,
                cipher_suites,
                extensions: Bytes::new(),
            }));
        }

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
            cipher_suites,
            extensions,
        }))
    }
}
