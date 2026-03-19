use aead::{rand_core::RngCore, OsRng};
use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    crypto::session::SessionKeys,
    tlseng::{
        consts::{HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO},
        extension::ExtensionBuilder,
        profile::{BrowserProfile, ServerProfile},
        tls_record::TlsRecord,
        types::{ContentType, HelloType, ProtocolVersion, TlsVersions},
    },
    utils::u24::U24,
};

pub struct HelloHeader {
    pub header_type: HelloType,
    pub len: U24,
}

pub struct ClientHello {
    pub version: ProtocolVersion,

    pub random: [u8; 32],

    pub session_id: Bytes,

    pub cipher_suites: Vec<u16>,

    pub extensions: Bytes,
}

impl ClientHello {
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(512 + self.extensions.len());

        buf.put_u8(HANDSHAKE_TYPE_CLIENT_HELLO);

        // Резервируем 3 байта под длину Handshake (U24)
        let length_pos = buf.len();
        buf.put_bytes(0, 3);

        buf.put_u16(0x0303); // Legacy Version
        buf.put_slice(&self.random);

        // Session ID
        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        // Cipher Suites
        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for &suite in &self.cipher_suites {
            buf.put_u16(suite);
        }

        // Compression Methods (всегда 0x01 0x00 для маскировки)
        buf.put_u8(1);
        buf.put_u8(0x00);

        // Extensions
        buf.put_u16(self.extensions.len() as u16);
        buf.put_slice(&self.extensions);

        // ПРАВИЛЬНЫЙ РАСЧЕТ ДЛИНЫ:
        // Длина сообщения Handshake не включает сам тип (1 байт) и поле длины (3 байта)
        let total_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_len.to_be_bytes();
        // Записываем 3 байта длины (Big Endian)
        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf.freeze()
    }

    pub fn make_client_hello(profile: &BrowserProfile, host: &str, keys: &SessionKeys) -> Bytes {
        let tls_random = keys.salt.get_local();
        let mut session_id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut session_id_bytes[..16]);
        session_id_bytes[16..].copy_from_slice(&keys.generate_auth_tag());

        let record_header = 5;
        let handshake_header = 4;
        let client_hello_fixed = 2 + 32 + 1 + 32 + 2 + (profile.cipher_suites.len() * 2) + 2 + 2;

        let total_overhead = record_header + handshake_header + client_hello_fixed;

        let mut ext_builder = ExtensionBuilder::new();

        ext_builder.apply_profile(
            profile,
            host,
            &keys.ecdh.public_key.to_bytes(),
            total_overhead,
        );

        let extensions_bytes = ext_builder.build();

        let client_hello = ClientHello {
            version: ProtocolVersion::Tls12,
            random: tls_random,
            session_id: Bytes::copy_from_slice(&session_id_bytes),
            cipher_suites: profile.cipher_suites.to_vec(),
            extensions: extensions_bytes,
        };

        let record = TlsRecord::new(
            ContentType::Handshake,
            profile.record_layer_version,
            client_hello.serialize(),
        );

        record.serialize()
    }
}

pub struct ServerHello {
    pub version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suite: u16,
    pub extensions: BytesMut,
}
impl ServerHello {
    pub fn make_server_hello(
        client_hello: &ClientHello,
        server_public_key: &[u8],
        salt: [u8; 32],
        profile: &ServerProfile,
    ) -> Bytes {
        // Создаем инстанс ServerHello
        let server_hello = Self::from_client_hello(client_hello, server_public_key, salt, profile);

        // Оборачиваем в Record Layer
        let record = TlsRecord::new(
            ContentType::Handshake,
            profile.record_layer_version, // 0x0303 обычно
            server_hello.serialize(),     // Сериализация самого SH
        );

        record.serialize()
    }

    pub fn from_client_hello(
        client_hello: &ClientHello,
        server_public_key: &[u8],
        salt: [u8; 32],
        profile: &ServerProfile,
    ) -> Self {
        // 1. Используем соль как рандом сервера
        let server_random = salt;

        // 2. Выбор Cipher Suite (твой код здесь хорош, оставляем)
        let selected_suite = if profile.honor_cipher_order {
            profile
                .cipher_suites
                .iter()
                .find(|&&suite| client_hello.cipher_suites.contains(&suite))
                .cloned()
                .unwrap_or(0x1301)
        } else {
            client_hello
                .cipher_suites
                .iter()
                .find(|&&suite| profile.cipher_suites.contains(&suite))
                .cloned()
                .unwrap_or(0x1301)
        };

        let mut extensions = BytesMut::new();

        // 3. Работа с версией.
        // Выбираем макс. версию из профиля (например, TLS 1.3)
        let selected_version = profile.versions.max();

        // Добавляем расширение Supported Versions (обязательно для TLS 1.3)
        extensions.put_u16(0x002b);
        extensions.put_u16(2);
        extensions.put_u16(selected_version as u16);

        // 4. Key Share (исправляем расчет длины, чтобы не было как в прошлый раз)
        let key_len = server_public_key.len() as u16;
        extensions.put_u16(0x0033);
        extensions.put_u16(key_len + 4); // Группа(2) + Длина(2) + Ключ
        extensions.put_u16(0x001d); // x25519
        extensions.put_u16(key_len);
        extensions.put_slice(server_public_key);

        Self {
            // Это поле будет использоваться как legacy_version (0x0303)
            version: ProtocolVersion::Tls12,
            random: server_random, // ИСПОЛЬЗУЕМ переменную
            session_id: client_hello.session_id.clone(),
            cipher_suite: selected_suite,
            extensions,
        }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256 + self.extensions.len());

        buf.put_u8(HANDSHAKE_TYPE_SERVER_HELLO);

        // Резервируем место под длину Handshake (3 байта)
        let length_pos = buf.len();
        buf.put_slice(&[0, 0, 0]);

        // Используем версию из структуры (Legacy Version)
        buf.put_u16(self.version as u16);

        // Используем рандом из структуры
        buf.put_slice(&self.random);

        // Session ID (Echo)
        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u16(self.cipher_suite);

        // Compression (0x00)
        buf.put_u8(0x00);

        // Extensions
        if !self.extensions.is_empty() {
            buf.put_u16(self.extensions.len() as u16);
            buf.put_slice(&self.extensions);
        } else {
            buf.put_u16(0);
        }

        // Заполняем длину handshake-сообщения
        let total_handshake_body_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_handshake_body_len.to_be_bytes();
        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf.freeze()
    }
}
