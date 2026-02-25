use bytes::{Bytes, BytesMut};

use crate::tlseng::{
    tls_record::TlsRecord,
    types::{ContentType, ProtocolVersion},
};

pub struct ApplicationData {
    pub len: usize,
    pub payload: Bytes,
}

impl ApplicationData {
    pub fn make_application_data(bytes: &mut BytesMut) -> Bytes {
        let record = TlsRecord::new(
            ContentType::ApplicationData,
            ProtocolVersion::Tls12,
            bytes.split_to(bytes.len()).freeze(),
        );
        record.serialize()
    }
}
