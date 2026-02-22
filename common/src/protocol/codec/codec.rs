use aead::rand_core::RngCore;
use aead::OsRng;
use bytes::{BufMut, Bytes, BytesMut};

use crate::crypto::chacha::ChaChaCipher;
use crate::crypto::ecdh::ECDH;
use crate::crypto::hmac::generate_auth_tag;
use crate::protocol::interceptors::hello_interceptor::extension_interceptor::ExtensionStack;
use crate::protocol::interceptors::interceptor::Interceptor;
use crate::tlseng::etype::EXT_KEY_SHARE;
use crate::tlseng::extension::ExtensionBuilder;
use crate::tlseng::profile::profile::BrowserProfile;
use crate::tlseng::tls::{
    ClientHello, ContentType, HelloHeader, HelloType, ProtocolVersion, ServerHello, TlsRecord,
};

use crate::crypto::aead::AeadPacker;
pub struct Codec {
    crypto: ChaChaCipher,
}

impl Codec {
    pub fn new() -> Self {
        Self {
            crypto: ChaChaCipher::new(),
        }
    }

    pub fn make_handshake(&mut self, profile: &BrowserProfile, host: &str) -> Bytes {
        // 1. Key Exchange: Generate ECDH pair and get public key
        let ecdh = ECDH::new();
        let pub_key = &ecdh.public_key;

        // 2. Authentication: Generate 32 bytes for TLS Random
        // [16 bytes entropy] + [16 bytes HMAC(timestamp)]
        let mut tls_random = [0u8; 32];
        OsRng.fill_bytes(&mut tls_random[..16]);

        let auth_token = generate_auth_tag(&[]);
        tls_random[16..32].copy_from_slice(&auth_token);

        // 3. Extensions: Build the extensions block using the profile
        let mut ext_builder = ExtensionBuilder::new();
        // Pass the public key into the KeyShare extension via apply_profile
        ext_builder.apply_profile(profile, host, pub_key.as_bytes());
        let extensions_bytes = ext_builder.build();

        let mut session_id = BytesMut::with_capacity(32);
        session_id.put_slice(&[0u8; 32]);

        // 4. Assemble ClientHello Handshake message
        let client_hello = ClientHello {
            version: ProtocolVersion::Tls12, // Legacy version for compatibility
            random: tls_random,
            session_id: session_id.freeze(), // Standard 32-byte session ID
            cipher_suites: vec![0x1301, 0x1302, 0x1303], // TLS 1.3 suites
            extensions: extensions_bytes,
        };

        // 5. Wrap ClientHello into a TLS Record
        let record = TlsRecord {
            content_type: ContentType::Handshake,
            version: ProtocolVersion::Tls10, // Standard for ClientHello records
            len: client_hello.serialize().len() as u16,
            payload: client_hello.serialize(),
        };

        println!("Client Hello: {:02x?}", record.payload.to_vec());

        // Final result: Byte buffer ready for the wire
        record.serialize()
    }

    /// Основная точка входа для входящих данных из сокета
    pub fn process_incoming(&mut self, mut buffer: BytesMut) {
        // 1. Пытаемся достать TLS Record (самый верхний слой)
        match TlsRecord::intercept(&mut buffer) {
            Ok(Some(record)) => {
                println!(
                    "Получен Record: type={:?}, len={}",
                    record.content_type, record.len
                );

                // 2. Диспетчеризация по типу контента
                self.handle_record(record);
            }
            Ok(None) => {
                // Пакет неполный, ждем догрузки в буфер
            }
            Err(_e) => {
                // Заглушка: ошибка парсинга рекорда
            }
        }
    }

    fn handle_record(&mut self, record: TlsRecord) {
        match record.content_type {
            ContentType::Handshake => {
                self.handle_handshake(record.payload);
            }
            ContentType::ApplicationData => {
                self.handle_application_data(record.payload);
            }
            _ => {
                // Остальные типы (Alert, ChangeCipherSpec) пока игнорируем
            }
        }
    }

    fn handle_handshake(&mut self, mut payload: Bytes) {
        // Превращаем Bytes в BytesMut для интерцепторов (без копирования данных)
        let mut body = BytesMut::from(payload.as_ref());

        // 1. Парсим заголовок Handshake (Type + Length)
        match HelloHeader::intercept(&mut body) {
            Ok(Some(header)) => {
                match header.header_type {
                    HelloType::Server => {
                        let mut server_hello_body = body; // Тут уже откушенное тело
                        if let Ok(Some(server_hello)) =
                            ServerHello::intercept(&mut server_hello_body)
                        {
                            self.process_server_hello(server_hello);
                        }
                    }
                    HelloType::Client => {
                        let mut client_hello_body = body;
                        if let Ok(Some(client_hello)) =
                            ClientHello::intercept(&mut client_hello_body)
                        {
                            self.process_client_hello(client_hello);
                        }
                    }
                    _ => { /* Другие типы Handshake (EncryptedExtensions, Certificate и т.д.) */
                    }
                }
            }
            _ => { /* Заглушка на ошибку */ }
        }
    }

    fn process_server_hello(&mut self, hello: ServerHello) {
        println!("Server Hello получен! Random: {:02x?}", hello.random);

        // Парсим расширения сервера, если нужно
        let mut ext_bytes = BytesMut::from(hello.extensions.as_ref());
        if let Ok(Some(stack)) = ExtensionStack::intercept(&mut ext_bytes) {
            // Например, ищем KeyShare сервера для завершения ECDH
            if let Some(key_share) = stack.find_by_type(EXT_KEY_SHARE) {
                println!("Найден KeyShare сервера, длина: {}", key_share.len());
            }
        }
    }

    fn process_client_hello(&mut self, hello: ClientHello) {
        println!("Client Hello получен! Random: {:02x?}", hello.random);

        // Парсим расширения сервера, если нужно
        let mut ext_bytes = BytesMut::from(hello.extensions.as_ref());
        if let Ok(Some(stack)) = ExtensionStack::intercept(&mut ext_bytes) {
            if let Some(key_share) = stack.find_by_type(EXT_KEY_SHARE) {
                println!("Найден KeyShare сервера, длина: {}", key_share.len());
            }
        }
    }

    fn handle_application_data(&mut self, payload: Bytes) {
        // Здесь будет логика расшифровки через твой ChaChaCipher
        // Пока просто выводим длину зашифрованных данных
        println!("Получены Application Data: {} байт", payload.len());
    }
}
