use crate::crypto::{SessionAuth, SessionKeys};
use crate::nrxp::errors::{ErrorAction, ErrorStage, TlsError};
use crate::parser::Parser;
use crate::tlseng::ExtensionStack;
use crate::tlseng::{ApplicationData, TlsRecord};
use crate::tlseng::{BrowserProfile, ServerProfile};
use crate::tlseng::{ClientHello, HelloHeader, ServerHello};
use crate::tlseng::{ContentType, HelloType};
use bytes::{Bytes, BytesMut};

trait TlsInterceptor {
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

pub(crate) enum HandshakeMessage {
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
                                    TlsError::new(ErrorStage::Handshake("Ext Err"), ErrorAction::Drop, Bytes::new())
                                })?;
                        return Ok(Some(HandshakeMessage::Client { base: hello, extensions: ext }));
                    }
                }
                HelloType::Server => {
                    if let Some(hello) = ServerHello::parse(&mut payload)? {
                        let ext =
                            ExtensionStack::parse(&mut BytesMut::from(hello.extensions.as_ref()))?
                                .ok_or_else(|| {
                                    TlsError::new(ErrorStage::Handshake("Ext Err"), ErrorAction::Drop, Bytes::new())
                                })?;
                        return Ok(Some(HandshakeMessage::Server { base: hello, extensions: ext }));
                    }
                }
            }
        }
        Ok(None)
    }
}

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
            _len: record.payload.len(),
            payload: record.payload,
        }))
    }
}

pub(crate) struct TlsBridge;

impl TlsBridge {
    pub fn unpack_handshake(buffer: &mut BytesMut) -> Result<Option<HandshakeMessage>, TlsError> {
        HandshakeMessage::start_process(buffer)
    }

    pub fn unpack_app_data(buffer: &mut BytesMut) -> Result<Option<ApplicationData>, TlsError> {
        ApplicationData::start_process(buffer)
    }

    pub fn wrap_client_hello(profile: &BrowserProfile, host: &str, keys: &SessionKeys) -> Bytes {
        ClientHello::make_client_hello(profile, host, keys)
    }

    pub fn wrap_server_hello(
        client_msg: &HandshakeMessage,
        keys: &mut SessionKeys,
        profile: &ServerProfile,
    ) -> Result<Bytes, TlsError> {
        if let HandshakeMessage::Client { base, extensions } = client_msg {
            if base.session_id.len() != 32 {
                return Err(TlsError::new(ErrorStage::Handshake("Invalid SessionID len"), ErrorAction::Drop, Bytes::new()));
            }

            let mut received_tag = [0u8; 16];
            received_tag.copy_from_slice(&base.session_id[16..32]);

            // ВАЖНО: Используем SessionAuth для проверки начального тега хендшейка
            let auth = SessionAuth::new(keys.get_auth_key());
            if !auth.verify_tag(&received_tag) {
                netrunner_logger::warn!("Unauthorized ClientHello: Auth Tag mismatch");
                return Err(TlsError::new(ErrorStage::Handshake("Auth Failed"), ErrorAction::Drop, Bytes::new()));
            }

            keys.update_keys(base.random, extensions, true).map_err(|e| {
                netrunner_logger::error!(error = %e, "Server failed key update");
                TlsError::new(ErrorStage::Handshake("Key Exchange Failed"), ErrorAction::Drop, Bytes::new())
            })?;

            let server_pub_key = keys.public_key_bytes();

            Ok(ServerHello::make_server_hello(base, &server_pub_key, keys.local_salt(), profile))
        } else {
            Err(TlsError::new(ErrorStage::Handshake("Expected ClientHello"), ErrorAction::Drop, Bytes::new()))
        }
    }
    
    pub fn pack_app_data(buffer: Bytes) -> Bytes {
        TlsRecord::build_application_data(buffer)
    }
}