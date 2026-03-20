use bytes::Bytes;

pub struct ApplicationData {
    pub _len: usize,
    pub payload: Bytes,
}

mod consts;
pub mod extension;
pub mod handshake;
pub mod profile;
pub mod tls_record;
pub mod types;
