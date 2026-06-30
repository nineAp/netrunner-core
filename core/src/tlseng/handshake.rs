//! Сборка и разбор hello-сообщений рукопожатия.
//!
//! Здесь живёт «полезная контрабанда» внутри маскировки: поля поддельного
//! `ClientHello`/`ServerHello` переиспользуются под обмен ключами.
//!
//! - **`random` (32 байта)** ← локальная соль стороны (см. [`SessionKeys::local_salt`]).
//! - **`session_id` (32 байта)** ← 16 случайных байт + 16 байт time-based
//!   auth-тега. Сервер первым делом проверяет этот тег (см.
//!   [`bridge`](crate::nrxp)) — отсев чужих/сканеров до любой крипты.
//! - **публичный ключ X25519** ← в расширении KeyShare (собирается [`ExtensionBuilder`]).
//!
//! Все три структуры реализуют [`Parser`] (разбор входящих) и имеют `serialize`
//! (сборка исходящих). Точные размеры/порядок берутся из [`profile`](super::profile),
//! чтобы итоговый отпечаток совпал с реальным браузером.

use aead::{rand_core::RngCore, OsRng};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    crypto::{SessionAuth, SessionKeys},
    nrxp::{ErrorAction, ErrorStage, TlsError},
    parser::Parser,
    tlseng::{
        consts::{HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO},
        extension::ExtensionBuilder,
        profile::{BrowserProfile, ServerProfile},
        tls_record::TlsRecord,
        types::{ContentType, HelloType, ProtocolVersion},
    },
    utils::u24::{BufExt, U24},
};

/// Заголовок handshake-сообщения: тип (`ClientHello`/`ServerHello`) + 24-битная
/// длина тела. Парсится первым, чтобы понять, какое именно hello разбирать дальше.
pub(crate) struct HelloHeader {
    pub header_type: HelloType,
    pub _len: U24,
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
            _len: U24::from_u32(len),
        }))
    }
}

/// `ClientHello`: первое сообщение клиента, оно же главный носитель отпечатка.
///
/// `random` несёт соль, `session_id` — auth-тег, `extensions` — публичный ключ и
/// прочие поля профиля. Cipher-suites и порядок расширений берутся из браузерного
/// профиля.
pub(crate) struct ClientHello {
    pub _version: ProtocolVersion,
    /// 32 байта «random» = локальная соль клиента (для HKDF).
    pub random: [u8; 32],
    /// 32 байта: 16 случайных + 16 auth-тег (проверяется сервером).
    pub session_id: Bytes,
    /// Список cipher-suites (значения и порядок — часть JA3).
    pub cipher_suites: Vec<u16>,
    /// Сырые байты блока расширений (содержат KeyShare с pubkey).
    pub extensions: Bytes,
}

impl ClientHello {
    /// Сериализует `ClientHello` в тело handshake-сообщения с корректной
    /// 24-битной длиной (длина дописывается задним числом по `length_pos`).
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(512 + self.extensions.len());

        buf.put_u8(HANDSHAKE_TYPE_CLIENT_HELLO);

        let length_pos = buf.len();
        buf.put_bytes(0, 3);

        buf.put_u16(0x0303);
        buf.put_slice(&self.random);

        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for &suite in &self.cipher_suites {
            buf.put_u16(suite);
        }

        buf.put_u8(1);
        buf.put_u8(0x00);

        buf.put_u16(self.extensions.len() as u16);
        buf.put_slice(&self.extensions);

        let total_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_len.to_be_bytes();

        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf.freeze()
    }

    /// Высокоуровневая сборка готового к отправке `ClientHello` (в TLS-записи).
    ///
    /// Кладёт соль в `random`, формирует `session_id` = `[16 random | 16 auth-tag]`,
    /// затем через [`ExtensionBuilder`] собирает расширения по профилю (включая
    /// SNI=`host` и KeyShare с публичным ключом). `total_overhead` нужен билдеру,
    /// чтобы посчитать padding до целевого размера отпечатка.
    pub fn make_client_hello(profile: &BrowserProfile, host: &str, keys: &SessionKeys) -> Bytes {
        let tls_random = keys.local_salt();
        let mut session_id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut session_id_bytes[..16]);

        // session_id[16..32] = текущий time-based auth-тег: сервер проверит его
        // первым делом и отвергнет ClientHello без валидного тега.
        let auth = SessionAuth::new(keys.get_auth_key());
        session_id_bytes[16..].copy_from_slice(&auth.generate_current_tag());

        let record_header = 5;
        let handshake_header = 4;
        let client_hello_fixed = 2 + 32 + 1 + 32 + 2 + (profile.cipher_suites.len() * 2) + 2 + 2;

        let total_overhead = record_header + handshake_header + client_hello_fixed;

        let mut ext_builder = ExtensionBuilder::new();

        ext_builder.apply_profile(profile, host, &keys.public_key_bytes(), total_overhead);

        let extensions_bytes = ext_builder.build();

        let client_hello = ClientHello {
            _version: ProtocolVersion::Tls12,
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

/// Разбор входящего `ClientHello` (серверная сторона). `can_parse` «прыжковым
/// поиском» проходит по полям переменной длины (session_id → ciphers →
/// compression → extensions), не сдвигая курсор, и убеждается, что пришёл весь
/// блок; `parse` затем извлекает поля по-настоящему.
impl Parser for ClientHello {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut reader = &bytes[..];

        // 34 = 2 (version) + 32 (random) — фиксированная «голова» перед session_id.
        if reader.len() < 35 {
            return false;
        }
        reader.advance(34);

        let sid_len = reader[0] as usize;
        reader.advance(1);
        if reader.len() < sid_len + 2 {
            return false;
        }
        reader.advance(sid_len);

        let ciphers_len = u16::from_be_bytes([reader[0], reader[1]]) as usize;
        reader.advance(2);
        if reader.len() < ciphers_len + 1 {
            return false;
        }
        reader.advance(ciphers_len);

        let comp_len = reader[0] as usize;
        reader.advance(1);
        if reader.len() < comp_len {
            return false;
        }
        reader.advance(comp_len);

        if reader.len() >= 2 {
            let ext_len = u16::from_be_bytes([reader[0], reader[1]]) as usize;
            reader.advance(2);
            if reader.len() < ext_len {
                return false;
            }
        }

        true
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let _version = ProtocolVersion::try_from(bytes.get_u16())
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let mut random = [0u8; 32];
        bytes.copy_to_slice(&mut random);

        let sid_len = bytes.get_u8() as usize;
        let session_id = bytes.split_to(sid_len).freeze();

        let c_len = bytes.get_u16() as usize;
        let mut cipher_suites = Vec::with_capacity(c_len / 2);
        let mut ciphers_data = bytes.split_to(c_len);
        while ciphers_data.has_remaining() {
            cipher_suites.push(ciphers_data.get_u16());
        }

        let cmp_len = bytes.get_u8() as usize;
        bytes.advance(cmp_len);

        let extensions = if bytes.remaining() >= 2 {
            let ext_len = bytes.get_u16() as usize;
            bytes.split_to(ext_len).freeze()
        } else {
            Bytes::new()
        };

        Ok(Some(Self {
            _version,
            random,
            session_id,
            cipher_suites,
            extensions,
        }))
    }
}

/// `ServerHello`: ответ сервера. Минимальный TLS 1.3-совместимый: всегда несёт
/// `supported_versions` и `key_share` (публичный ключ сервера), `random` = соль
/// сервера, а `session_id` эхом возвращается из `ClientHello`.
pub(crate) struct ServerHello {
    pub version: ProtocolVersion,
    /// 32 байта «random» = локальная соль сервера (для HKDF).
    pub random: [u8; 32],
    /// Эхо `session_id` клиента (так требует TLS 1.3).
    pub session_id: Bytes,
    /// Один выбранный cipher-suite.
    pub cipher_suite: u16,
    /// Блок расширений (supported_versions + key_share с pubkey сервера).
    pub extensions: BytesMut,
}
impl ServerHello {
    /// Высокоуровневая сборка готового к отправке `ServerHello` (в TLS-записи).
    pub fn make_server_hello(
        client_hello: &ClientHello,
        server_public_key: &[u8],
        salt: [u8; 32],
        profile: &ServerProfile,
    ) -> Bytes {
        let server_hello = Self::from_client_hello(client_hello, server_public_key, salt, profile);

        let record = TlsRecord::new(
            ContentType::Handshake,
            profile.record_layer_version,
            server_hello.serialize(),
        );

        record.serialize()
    }

    /// Конструирует `ServerHello` из принятого `ClientHello`.
    ///
    /// Выбор cipher-suite зависит от `honor_cipher_order`: либо берём первый из
    /// предпочтений сервера, который поддержал клиент, либо наоборот; fallback —
    /// `0x1301` (TLS_AES_128_GCM_SHA256). Дальше вручную пишутся два обязательных
    /// расширения: `supported_versions` (0x002b) и `key_share` (0x0033) с
    /// публичным ключом сервера по группе X25519 (0x001d).
    pub fn from_client_hello(
        client_hello: &ClientHello,
        server_public_key: &[u8],
        salt: [u8; 32],
        profile: &ServerProfile,
    ) -> Self {
        let server_random = salt;

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

        let selected_version = profile.versions.max();

        extensions.put_u16(0x002b);
        extensions.put_u16(2);
        extensions.put_u16(selected_version as u16);

        let key_len = server_public_key.len() as u16;
        extensions.put_u16(0x0033);
        extensions.put_u16(key_len + 4);
        extensions.put_u16(0x001d);
        extensions.put_u16(key_len);
        extensions.put_slice(server_public_key);

        Self {
            version: ProtocolVersion::Tls12,
            random: server_random,
            session_id: client_hello.session_id.clone(),
            cipher_suite: selected_suite,
            extensions,
        }
    }

    /// Сериализует `ServerHello` в тело handshake с 24-битной длиной.
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256 + self.extensions.len());

        buf.put_u8(HANDSHAKE_TYPE_SERVER_HELLO);

        let length_pos = buf.len();
        buf.put_slice(&[0, 0, 0]);

        buf.put_u16(self.version as u16);

        buf.put_slice(&self.random);

        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u16(self.cipher_suite);

        buf.put_u8(0x00);

        if !self.extensions.is_empty() {
            buf.put_u16(self.extensions.len() as u16);
            buf.put_slice(&self.extensions);
        } else {
            buf.put_u16(0);
        }

        let total_handshake_body_len = (buf.len() - length_pos - 3) as u32;
        let len_bytes = total_handshake_body_len.to_be_bytes();
        buf[length_pos..length_pos + 3].copy_from_slice(&len_bytes[1..4]);

        buf.freeze()
    }
}

/// Разбор входящего `ServerHello` (клиентская сторона). Так же прыжками по полям
/// вычисляет полную длину сообщения, отрезает его (`split_to`) и читает поля;
/// из расширений потом достаётся публичный ключ сервера для ECDH.
impl Parser for ServerHello {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        // 34 = 2 (version) + 32 (random) перед длиной session_id.
        let mut offset = 34;
        if bytes.len() < offset + 1 {
            return false;
        }

        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        offset += 3;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        bytes.len() >= offset
    }

    fn parse(bytes: &mut bytes::BytesMut) -> Result<Option<Self>, Self::Error> {
        let mut offset = 34;
        if bytes.len() < offset + 1 {
            return Ok(None);
        }
        let session_id_len = bytes[offset] as usize;
        offset += 1 + session_id_len;

        offset += 3;

        if bytes.len() >= offset + 2 {
            let ext_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2 + ext_len;
        }

        if bytes.len() < offset {
            return Ok(None);
        }

        let mut msg = bytes.split_to(offset);

        let version = ProtocolVersion::try_from(msg.get_u16())
            .map_err(|e| TlsError::new(ErrorStage::Tls(e), ErrorAction::Drop, Bytes::new()))?;

        let mut random = [0u8; 32];
        msg.copy_to_slice(&mut random);

        let sid_len = msg.get_u8() as usize;
        let session_id = msg.split_to(sid_len).freeze();

        let cipher_suite = msg.get_u16();
        msg.advance(1);

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
