use bytes::{Bytes, BytesMut};

use crate::crypto::chacha::ChaChaCipher;
use crate::protocol::codec::bridges::tls::bridge::TlsBridge;
use crate::protocol::codec::session_keys::SessionKeys;

use crate::crypto::aead::AeadPacker;

pub struct Codec {
    crypto: ChaChaCipher, //rename chacha
    pub session_keys: SessionKeys,
}

impl Codec {
    pub fn new(is_initiator: bool) -> Self {
        Self {
            crypto: ChaChaCipher::new(),
            session_keys: SessionKeys::new(is_initiator),
        }
    }

    pub fn make_handshake(&mut self, buffer: &mut BytesMut) {
        println!("Handshake len in codec: {:?}", &buffer.len());
        TlsBridge::make_handshake(buffer, self);
    }

    pub fn unpack(&mut self, buffer: &mut BytesMut) -> Result<Bytes, String> {
        println!("App data unpack len in codec?: {:?}", &buffer.len());
        let mut data = TlsBridge::unpack_app_data(buffer);
        //self.decrypt(&mut data);
        match data {
            Ok(bytes) => Ok(bytes.freeze()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn pack(&mut self, buffer: &mut BytesMut) -> Bytes {
        println!("App data len in codec?: {:?}", &buffer.len());
        TlsBridge::pack_in_app_data(buffer)
    }

    pub fn encrypt(&mut self, data: &mut BytesMut) {
        self.crypto.encrypt(data);
    }

    pub fn decrypt(&mut self, data: &mut BytesMut) {
        self.crypto.decrypt(data);
    }
}
