use bytes::{BufMut, Bytes, BytesMut};

use crate::tlseng::{
    consts::HANDSHAKE_TYPE_SERVER_HELLO,
    tls_record::TlsRecord,
    types::{ContentType, ProtocolVersion},
};

pub struct ServerHello {
    pub version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suite: u16,
    pub extensions: BytesMut,
}

impl ServerHello {
    pub fn make_mock_server_hello() -> Bytes {
        // 1. Генерируем "рандом" (в реальном Nginx здесь случайные байты)
        let mut mock_random = [0u8; 32];
        mock_random[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // Просто метка

        // 2. Имитируем Session ID (в TLS 1.3 сервер часто эхоит ID клиента)
        let mut session_id = BytesMut::with_capacity(32);
        session_id.put_slice(&[0u8; 32]);

        // 3. Подготавливаем минимальные расширения (пустые или базовые)
        // Для TLS 1.3 тут обязательно должны быть Supported Versions (0x002b)
        let mut mock_extensions = BytesMut::new();

        // Extension: Supported Versions (TLS 1.3)
        mock_extensions.put_u16(0x002b); // Type
        mock_extensions.put_u16(2); // Length
        mock_extensions.put_u16(0x0304); // Value: TLS 1.3

        let server_hello = ServerHello {
            version: ProtocolVersion::Tls12, // Legacy 0x0303
            random: mock_random,
            session_id: session_id.freeze(),
            cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
            extensions: mock_extensions,
        };

        // 4. Сериализуем Handshake сообщение
        let handshake_payload = server_hello.serialize();

        // 5. Оборачиваем в TLS Record
        // ContentType: Handshake (22)
        // Version: TLS 1.0 (0x0301) для совместимости
        let record = TlsRecord::new(
            ContentType::Handshake,
            ProtocolVersion::Tls10,
            handshake_payload.freeze(), // Теперь payload — это Bytes
        );

        // Финальный результат: [Header(5 bytes)][Handshake(N bytes)]
        record.serialize()
    }

    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256 + self.extensions.len());

        // 1. Handshake Type: 0x02 (ServerHello)
        buf.put_u8(HANDSHAKE_TYPE_SERVER_HELLO);

        // 2. Placeholder for u24 length
        let length_pos = buf.len();
        buf.put_bytes(0, 3);

        // 3. body of ServerHello
        buf.put_u16(ProtocolVersion::Tls12 as u16); // Legacy 0x0303
        buf.put_slice(&self.random);

        // Session ID
        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        // Selected Cipher Suite (only one)
        buf.put_u16(self.cipher_suite);

        // Compression: always 0x00
        buf.put_u8(0x00);

        // Extensions
        buf.put_u16(self.extensions.len() as u16);
        buf.put_slice(&self.extensions);

        // 4. Patch length
        let total_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_len.to_be_bytes();
        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf
    }
}
