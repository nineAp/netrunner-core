use crate::protocol::errors::{ErrorAction, ErrorStage, TlsError};
use crate::protocol::parser::parser::Parser;
use crate::tlseng::extension::ExtensionStack;
use crate::tlseng::handshake::{ClientHello, HelloHeader, ServerHello};
use crate::tlseng::profile::BrowserProfile;
use crate::tlseng::tls_record::TlsRecord;
use crate::tlseng::types::{ContentType, HelloType};
use crate::tlseng::ApplicationData;
use bytes::{Bytes, BytesMut};

// --- 1. Общий интерфейс перехвата ---
pub trait TlsInterceptor {
    type Output;

    fn start_process(buffer: &mut BytesMut) -> Result<Option<Self::Output>, TlsError> {
        match TlsRecord::parse(buffer) {
            Ok(Some(record)) => Self::handle_record(record),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError>;
}

// --- 2. Обработка Handshake ---
pub enum HandshakeMessage {
    Client {
        base: ClientHello,
        extensions: ExtensionStack,
    },
    Server {
        base: ServerHello,
        extensions: ExtensionStack,
    },
}

impl HandshakeMessage {
    pub fn random(&self) -> [u8; 32] {
        match self {
            Self::Client { base, .. } => base.random,
            Self::Server { base, .. } => base.random,
        }
    }

    pub fn extensions(&self) -> &ExtensionStack {
        match self {
            Self::Client { extensions, .. } => extensions,
            Self::Server { extensions, .. } => extensions,
        }
    }
}

impl TlsInterceptor for HandshakeMessage {
    type Output = HandshakeMessage;

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError> {
        if record.content_type != ContentType::Handshake {
            return Err(TlsError::new(
                ErrorStage::Handshake("Expected Handshake record"),
                ErrorAction::Drop,
                record.serialize(),
            ));
        }

        let mut payload = BytesMut::from(record.payload.as_ref());
        if let Some(header) = HelloHeader::parse(&mut payload)? {
            match header.header_type {
                HelloType::Client => {
                    if let Some(hello) = ClientHello::parse(&mut payload)? {
                        let ext =
                            ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))?
                                .ok_or_else(|| {
                                    TlsError::new(
                                        ErrorStage::Handshake("Ext Err"),
                                        ErrorAction::Drop,
                                        Bytes::new(),
                                    )
                                })?;
                        return Ok(Some(HandshakeMessage::Client {
                            base: hello,
                            extensions: ext,
                        }));
                    }
                }
                HelloType::Server => {
                    if let Some(hello) = ServerHello::parse(&mut payload)? {
                        let ext =
                            ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))?
                                .ok_or_else(|| {
                                    TlsError::new(
                                        ErrorStage::Handshake("Ext Err"),
                                        ErrorAction::Drop,
                                        Bytes::new(),
                                    )
                                })?;
                        return Ok(Some(HandshakeMessage::Server {
                            base: hello,
                            extensions: ext,
                        }));
                    }
                }
            }
        }
        Ok(None)
    }
}

// --- 3. Обработка Application Data ---
impl TlsInterceptor for ApplicationData {
    type Output = ApplicationData;

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, TlsError> {
        if record.content_type != ContentType::ApplicationData {
            return Err(TlsError::new(
                ErrorStage::ApplicationData("Expected AppData record"),
                ErrorAction::Drop,
                record.serialize(),
            ));
        }
        Ok(Some(ApplicationData {
            len: record.payload.len(),
            payload: record.payload,
        }))
    }
}

// --- 4. Высокоуровневый Bridge API ---
pub struct TlsBridge;

impl TlsBridge {
    // --- Распаковка (уже была) ---

    pub fn unpack_handshake(buffer: &mut BytesMut) -> Result<Option<HandshakeMessage>, TlsError> {
        HandshakeMessage::start_process(buffer)
    }

    pub fn unpack_app_data(buffer: &mut BytesMut) -> Result<Option<ApplicationData>, TlsError> {
        ApplicationData::start_process(buffer)
    }

    // --- Запаковка (новое) ---

    /// Создает полный TLS Record с ClientHello внутри
    pub fn wrap_client_hello(
        profile: &BrowserProfile,
        host: &str,
        public_key: &[u8; 32],
        salt: [u8; 32],
    ) -> Bytes {
        ClientHello::make_client_hello(profile, host, public_key, salt) // Передаем ключ дальше
    }

    /// Создает полный TLS Record с ServerHello, базируясь на данных из HandshakeMessage::Client
    pub fn wrap_server_hello(
        client_msg: &HandshakeMessage,
        server_pub_key: &[u8],
        salt: [u8; 32],
    ) -> Result<Bytes, TlsError> {
        if let HandshakeMessage::Client { base, .. } = client_msg {
            Ok(ServerHello::make_server_hello(base, server_pub_key, salt))
        } else {
            Err(TlsError::new(
                ErrorStage::Handshake("Wrong message type for ServerHello generation"),
                ErrorAction::Drop,
                Bytes::new(),
            ))
        }
    }

    pub fn pack_app_data(buffer: Bytes) -> Bytes {
        TlsRecord::build_application_data(buffer)
    }
}
