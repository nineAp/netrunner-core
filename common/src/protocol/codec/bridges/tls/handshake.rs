use bytes::{Bytes, BytesMut};

use crate::{
    protocol::{
        codec::bridges::tls::tls_interceptor::TlsInterceptor,
        interceptors::error_interceptor::{ErrorAction, ErrorType, InterceptorError},
        parser::parser::FrameParser,
    },
    tlseng::{
        extension::ExtensionStack,
        handshake::{
            client_hello::ClientHello, hello_header::HelloHeader, server_hello::ServerHello,
        },
        tls_record::TlsRecord,
        types::{ContentType, HelloType},
    },
};

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

impl TlsInterceptor for HandshakeMessage {
    type Output = HandshakeMessage;

    fn handle_record(record: TlsRecord) -> Result<Option<Self::Output>, InterceptorError> {
        let mut payload = BytesMut::from(record.payload.as_ref());
        match record.content_type {
            ContentType::Handshake => Self::handle_handshake(&mut payload),
            _ => {
                // It is strange if in this prcoess not a Handshake
                todo!()
            }
        }
    }
}

impl HandshakeMessage {
    fn handle_handshake(payload: &mut BytesMut) -> Result<Option<Self>, InterceptorError> {
        if let Some(header) = HelloHeader::parse(payload)? {
            match header.header_type {
                HelloType::Server => {
                    let mut server_hello_body = payload;
                    if let Some(server_hello) = ServerHello::parse(&mut server_hello_body)? {
                        return Self::process_server_hello(server_hello);
                    }
                }
                HelloType::Client => {
                    let mut client_hello_body = payload;
                    if let Some(client_hello) = ClientHello::parse(&mut client_hello_body)? {
                        return Self::process_client_hello(client_hello);
                    }
                }
            }
        }

        Ok(None)
    }

    fn process_server_hello(hello: ServerHello) -> Result<Option<Self>, InterceptorError> {
        println!("Server Hello получен! Random: {:02x?}", hello.random);

        // Парсим расширения сервера, если нужно
        let mut ext_bytes = BytesMut::from(hello.extensions.as_ref());
        let ext_stack_option = ExtensionStack::parse(&mut ext_bytes)?;
        let ext_stack = ext_stack_option.ok_or_else(|| {
            InterceptorError::new(
                ErrorType::Handshake("Extension Err TODO"),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&[]),
            )
        })?;
        Ok(Some(HandshakeMessage::Server {
            base: hello,
            extensions: ext_stack,
        }))
    }

    fn process_client_hello(hello: ClientHello) -> Result<Option<Self>, InterceptorError> {
        println!("Client Hello получен! Random: {:02x?}", hello.random);

        // Парсим расширения клиента, если нужно
        let mut ext_bytes = BytesMut::from(hello.extensions.as_ref());
        let ext_stack_option = ExtensionStack::parse(&mut ext_bytes)?;
        let ext_stack = ext_stack_option.ok_or_else(|| {
            InterceptorError::new(
                ErrorType::Handshake("Extension Err TODO"),
                ErrorAction::Drop,
                Bytes::copy_from_slice(&[]),
            )
        })?;
        Ok(Some(HandshakeMessage::Client {
            base: hello,
            extensions: ext_stack,
        }))
    }
}
