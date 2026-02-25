use bytes::{Bytes, BytesMut};
use x25519_dalek::PublicKey;

use crate::{
    protocol::codec::{
        bridges::tls::{handshake::HandshakeMessage, tls_interceptor::TlsInterceptor},
        codec::Codec,
    },
    tlseng::{application_data::ApplicationData, consts::EXT_KEY_SHARE, extension::ExtensionStack},
};

pub struct TlsBridge;

impl TlsBridge {
    fn process_key_share(extensions: &ExtensionStack, codec: &mut Codec) -> Result<(), String> {
        if let Some(dh_key) = extensions.find_by_type(EXT_KEY_SHARE) {
            let mut key = [0u8; 32];
            if dh_key.len() < 32 {
                return Err("Key too short".into());
            }
            key.copy_from_slice(&dh_key[..32]);

            let public_key = PublicKey::from(key);
            codec
                .session_keys
                .generate_keys(&public_key)
                .map_err(|e| format!("Key gen error: {:?}", e))?; // Обработка Result
            Ok(())
        } else {
            Err("No key share extension found".into())
        }
    }
    //unpack handshake
    pub fn make_handshake(buffer: &mut BytesMut, codec: &mut Codec) -> Result<(), String> {
        let incoming_process = HandshakeMessage::start_process(buffer);
        println!("buffer {:02x?}", &buffer);
        let message_option = match incoming_process {
            Ok(mes) => mes,
            Err(e) => {
                println!("Error: {:?}", e);
                None
            }
        };
        if let Some(message) = message_option {
            match message {
                HandshakeMessage::Client { base, extensions } => {
                    codec.session_keys.salt.set_remote_salt(base.random);
                    Self::process_key_share(&extensions, codec)?;
                }
                HandshakeMessage::Server { base, extensions } => {
                    codec.session_keys.salt.set_remote_salt(base.random);
                    Self::process_key_share(&extensions, codec)?;
                }
            };
        }
        Ok(())
    }

    pub fn unpack_app_data(buffer: &mut BytesMut) -> Result<BytesMut, &str> {
        println!("What is here?");
        println!("Data {:?}", &buffer);
        let incoming_process = ApplicationData::start_process(buffer);
        let option_bytes = match incoming_process {
            Ok(mes) => mes,
            Err(e) => {
                println!("Error: {:?}", e);
                None
            }
        };
        if let Some(b) = option_bytes {
            return Ok(BytesMut::from(b.payload.as_ref()));
        } else {
            Err("no data")
        }
    }

    pub fn pack_in_app_data(buffer: &mut BytesMut) -> Bytes {
        ApplicationData::make_application_data(buffer)
    }
}
