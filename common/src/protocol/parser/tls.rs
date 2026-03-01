use crate::{
    protocol::{
        errors::{ErrorAction, ErrorStage, TlsError},
        parser::Parser,
    },
    tlseng::{
        extension::{Extension, ExtensionStack},
        handshake::*,
        tls_record::TlsRecord,
        types::{ContentType, HelloType, ProtocolVersion},
        ApplicationData,
    },
    utils::u24::{BufExt, U24},
};
use bytes::{Buf, Bytes, BytesMut};

// =================================================================
// 1. RECORD LAYER
// =================================================================

impl Parser for TlsRecord {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        // 1. Минимум 5 байт для заголовка
        if bytes.len() < 5 {
            return false;
        }

        // 2. Проверяем ContentType
        let content_type = bytes[0];
        let is_valid_type = content_type == ContentType::Handshake as u8
            || content_type == ContentType::ApplicationData as u8
            || content_type == ContentType::Alert as u8;

        if !is_valid_type {
            return false;
        }

        // 3. Извлекаем заявленную длину тела рекорда
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        // 4. Специфика TLS 1.3:
        // Если это зашифрованные данные (0x17), они ДОЛЖНЫ содержать тег (16 байт)
        // + как минимум 1 байт зашифрованного типа контента.
        if content_type == ContentType::ApplicationData as u8 {
            if record_len < 17 {
                // Если длина < 17, это либо неполный пакет, либо ошибка протокола.
                // Возвращаем false, чтобы подождать еще данных из сокета.
                return false;
            }
        }

        // 5. Ждем, пока в буфере будет заголовок + всё тело
        bytes.len() >= 5 + record_len
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<TlsRecord>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        // --- ТОЛЬКО ТЕПЕРЬ МЫ ИЗМЕНЯЕМ БУФЕР ---
        let raw_content_type = bytes.get_u8();
        let raw_version = bytes.get_u16();
        let record_len = bytes.get_u16() as usize;

        let content_type = ContentType::try_from(raw_content_type)
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let version = ProtocolVersion::try_from(raw_version)
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        // Забираем ровно столько, сколько указано в заголовке
        let payload = bytes.split_to(record_len).freeze();

        Ok(Some(TlsRecord::new(content_type, version, payload)))
    }
}

// =================================================================
// 2. PAYLOAD TYPES
// =================================================================

impl Parser for ApplicationData {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        !bytes.is_empty()
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        let len = bytes.len();
        if len == 0 {
            return Ok(None);
        }
        let payload = bytes.split_to(len).freeze();
        Ok(Some(Self { len, payload }))
    }
}

impl Parser for HelloHeader {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        bytes[0] == HelloType::Client as u8 || bytes[0] == HelloType::Server as u8
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let raw_type = bytes.get_u8();
        let header_type = HelloType::try_from(raw_type).map_err(|e| {
            TlsError::new(ErrorStage::Handshake(e), ErrorAction::Drop, Bytes::new())
        })?;

        let len = bytes.get_u24();

        Ok(Some(Self {
            header_type,
            len: U24::from_u32(len),
        }))
    }
}

// =================================================================
// 3. HELLO MESSAGES
// =================================================================

impl Parser for ClientHello {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut offset = 34; // ProtocolVersion (2) + Random (32)
        if bytes.len() < offset + 1 {
            return false;
        }

        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;
        if bytes.len() < offset + 2 {
            return false;
        }

        let ciphers_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2 + ciphers_len;
        if bytes.len() < offset + 1 {
            return false;
        }

        let comp_len = bytes[offset] as usize;
        offset += 1 + comp_len;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        bytes.len() >= offset
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        // --- ШАГ 1: Атомарная проверка всего пакета ---
        let mut offset = 34; // Version + Random
        if bytes.len() < offset + 1 {
            return Ok(None);
        }
        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        if bytes.len() < offset + 2 {
            return Ok(None);
        }
        let ciphers_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2 + ciphers_len;

        if bytes.len() < offset + 1 {
            return Ok(None);
        }
        let comp_len = bytes[offset] as usize;
        offset += 1 + comp_len;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        // Если нам не хватает данных для полного ClientHello, выходим, не трогая буфер
        if bytes.len() < offset {
            return Ok(None);
        }

        // --- ШАГ 2: Безопасное чтение ---
        // Изолируем ровно тот кусок, который проверили.
        let mut msg = bytes.split_to(offset);

        let version = ProtocolVersion::try_from(msg.get_u16())
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let mut random = [0u8; 32];
        msg.copy_to_slice(&mut random);

        let sid_len = msg.get_u8() as usize;
        let session_id = msg.split_to(sid_len).freeze();

        let c_len = msg.get_u16() as usize;
        let mut cipher_suites = Vec::with_capacity(c_len / 2);
        let mut ciphers_data = msg.split_to(c_len);
        while ciphers_data.has_remaining() {
            cipher_suites.push(ciphers_data.get_u16());
        }

        let cmp_len = msg.get_u8() as usize;
        msg.advance(cmp_len); // пропускаем методы сжатия

        let extensions = if msg.remaining() >= 2 {
            let ext_len = msg.get_u16() as usize;
            msg.split_to(ext_len).freeze()
        } else {
            Bytes::new()
        };

        Ok(Some(Self {
            version,
            random,
            session_id,
            cipher_suites,
            extensions,
        }))
    }
}

impl Parser for ServerHello {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut offset = 34; // ProtocolVersion (2) + Random (32)
        if bytes.len() < offset + 1 {
            return false;
        }

        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suite (2) + Compression (1)
        offset += 3;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        bytes.len() >= offset
    }

    fn parse(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error> {
        // --- ШАГ 1: Атомарная проверка всего пакета ---
        let mut offset = 34; // Version + Random
        if bytes.len() < offset + 1 {
            return Ok(None);
        }
        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        offset += 3; // Cipher Suite (2) + Compression (1)

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        if bytes.len() < offset {
            return Ok(None);
        }

        // --- ШАГ 2: Безопасное чтение ---
        let mut msg = bytes.split_to(offset);

        let version = ProtocolVersion::try_from(msg.get_u16())
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let mut random = [0u8; 32];
        msg.copy_to_slice(&mut random);

        let sid_len = msg.get_u8() as usize;
        let session_id = msg.split_to(sid_len).freeze();

        let cipher_suite = msg.get_u16();
        msg.advance(1); // compression

        let extensions = if msg.remaining() >= 2 {
            let ext_len = msg.get_u16() as usize;
            msg.split_to(ext_len)
        } else {
            BytesMut::new()
        };

        Ok(Some(Self {
            version,
            random,
            session_id,
            cipher_suite,
            extensions,
        }))
    }
}

// =================================================================
// 4. EXTENSIONS
// =================================================================

impl Parser for ExtensionStack {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut offset = 0;
        let data_len = bytes.len();

        while offset + 4 <= data_len {
            let elen = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4 + elen;
        }

        offset <= data_len
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        // Проверяем на целостность всех расширений
        let mut offset = 0;
        let data_len = bytes.len();

        while offset + 4 <= data_len {
            let elen = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4 + elen;
        }

        // Если offset > data_len, значит кусок данных расширения отсечен, ждем еще данных
        if offset > data_len {
            return Ok(None);
        }

        // Если offset < data_len, есть лишние байты (Trailing garbage). Но так как мы
        // обычно передаем сюда точный срез `extensions`, это может быть ошибкой формата.
        if offset != data_len {
            return Err(TlsError::new(
                ErrorStage::Tls("Malformed extension stack: trailing data"),
                ErrorAction::Drop,
                Bytes::new(),
            ));
        }

        // Теперь гарантированно безопасно парсить всё до конца
        let mut extensions = Vec::new();
        while bytes.remaining() >= 4 {
            let etype = bytes.get_u16();
            let elen = bytes.get_u16() as usize;
            let data = bytes.split_to(elen).freeze();
            extensions.push(Extension::new(etype, data));
        }

        Ok(Some(Self { extensions }))
    }
}
