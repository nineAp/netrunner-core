use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    nrxp::{ErrorAction, ErrorStage, TlsError},
    parser::Parser,
    tlseng::{
        consts::{CERT_COMPRESSION_BROTLI, OCSP_STATUS_TYPE, PSK_DHE_KE_MODE, TYPE_HOST_NAME},
        profile::BrowserProfile,
        types::{TlsExtensions, TlsGroups, TlsSignatures, TlsVersions},
    },
};

#[derive(Debug)]
pub(crate) struct Extension {
    pub etype: u16,
    pub _elen: u16,
    pub data: Bytes,
}

#[derive(Debug)]
pub(crate) struct ExtensionStack {
    pub extensions: Vec<Extension>,
}

impl ExtensionStack {
    pub fn find_by_type(&self, etype: u16) -> Option<Bytes> {
        self.extensions
            .iter()
            .find(|e| e.etype == etype)
            .map(|e| e.data.clone())
    }
}

impl Parser for ExtensionStack {
    type Error = TlsError;

    fn can_parse(bytes: &BytesMut) -> bool {
        let mut offset = 0;
        let data_len = bytes.len();

        while offset + 4 <= data_len {
            let elen = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4 + elen;
        }

        offset <= data_len
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        let mut offset = 0;
        let data_len = bytes.len();

        while offset + 4 <= data_len {
            let elen = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4 + elen;
        }

        if offset > data_len {
            return Ok(None);
        }

        if offset != data_len {
            return Err(TlsError::new(
                ErrorStage::Tls("Malformed extension stack: trailing data"),
                ErrorAction::Drop,
                Bytes::new(),
            ));
        }

        let mut extensions = Vec::new();
        while bytes.remaining() >= 4 {
            let etype = bytes.get_u16();
            let elen = bytes.get_u16() as usize;
            let data = bytes.split_to(elen).freeze();
            extensions.push(Extension::new(etype, data));
        }

        Ok(Some(Self { extensions }))
    }
}

impl Extension {
    pub fn new(etype: u16, data: Bytes) -> Self {
        Self {
            etype,
            _elen: data.len() as u16,
            data,
        }
    }
}

pub(crate) struct ExtensionBuilder {
    payload: BytesMut,
}

impl ExtensionBuilder {
    pub fn new() -> Self {
        Self {
            payload: BytesMut::with_capacity(2048),
        }
    }

    fn add_extension(&mut self, etype: u16, data: &[u8]) {
        self.payload.put_u16(etype);
        self.payload.put_u16(data.len() as u16);
        self.payload.put_slice(data);
    }

    pub fn grease_with_id(&mut self, etype: u16) {
        self.add_extension(etype, &[]);
    }

    pub fn apply_generic_extension(&mut self, etype: u16, _profile: &BrowserProfile) {
        match etype {
            _ => {
                netrunner_logger::trace!(etype, "Applying generic or unknown extension");
            }
        }
    }

    pub fn server_name(&mut self, host: &str) {
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len() as u16;
        let list_inner_len = 1 + 2 + host_len;

        let mut data = BytesMut::with_capacity(2 + list_inner_len as usize);
        data.put_u16(list_inner_len);
        data.put_u8(TYPE_HOST_NAME);
        data.put_u16(host_len);
        data.put_slice(host_bytes);

        self.add_extension(TlsExtensions::SNI, &data);
    }

    pub fn extended_main_secret(&mut self) {
        self.add_extension(TlsExtensions::EMS, &[]);
    }

    pub fn supported_groups(&mut self, groups: TlsGroups) {
        let mut data = BytesMut::with_capacity(2 + groups.0.len() * 2);
        data.put_u16((groups.0.len() * 2) as u16);
        for &g in groups.0 {
            data.put_u16(g);
        }
        self.add_extension(TlsExtensions::SUPPORTED_GROUPS, &data);
    }

    pub fn signature_algorithms(&mut self, algs: TlsSignatures) {
        let mut data = BytesMut::with_capacity(2 + algs.0.len() * 2);
        data.put_u16((algs.0.len() * 2) as u16);
        for &a in algs.0 {
            data.put_u16(a);
        }
        self.add_extension(TlsExtensions::SIGNATURE_ALGORITHMS, &data);
    }

    pub fn supported_versions(&mut self, versions: TlsVersions) {
        let mut data = BytesMut::with_capacity(1 + versions.0.len() * 2);
        data.put_u8((versions.0.len() * 2) as u8);
        for &v in versions.0 {
            data.put_u16(v);
        }
        self.add_extension(TlsExtensions::SUPPORTED_VERSIONS, &data);
    }

    pub fn key_share(&mut self, profile: &BrowserProfile, pub_key: &[u8]) {
        let key_len = pub_key.len() as u16;

        let mut entry = BytesMut::with_capacity(key_len as usize + 4);
        let group = profile.groups.0.first().cloned().unwrap_or(0x001d);
        entry.put_u16(group);
        entry.put_u16(key_len);
        entry.put_slice(pub_key);

        let mut list = BytesMut::with_capacity(entry.len() + 2);
        list.put_u16(entry.len() as u16);
        list.put_slice(&entry);

        self.add_extension(TlsExtensions::KEY_SHARE, &list);
    }
    pub fn application_settings(&mut self, protocols: &[&str]) {
        let mut data = BytesMut::new();
        for proto in protocols {
            let p_bytes = proto.as_bytes();
            data.put_u8(p_bytes.len() as u8);
            data.put_slice(p_bytes);
            data.put_u16(0);
        }
        self.add_extension(TlsExtensions::ALPS, &data);
    }

    pub fn alpn(&mut self, protocols: &[&str]) {
        let mut list_data = BytesMut::new();
        for proto in protocols {
            let bytes = proto.as_bytes();
            list_data.put_u8(bytes.len() as u8);
            list_data.put_slice(bytes);
        }
        let mut extension_data = BytesMut::new();
        extension_data.put_u16(list_data.len() as u16);
        extension_data.put_slice(&list_data);
        self.add_extension(TlsExtensions::ALPN, &extension_data);
    }

    pub fn psk_key_exchange_modes(&mut self) {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(1);
        data.put_u8(PSK_DHE_KE_MODE);
        self.add_extension(TlsExtensions::PSK_MODES, &data);
    }

    pub fn compress_certificate(&mut self, algorithms: &[u16]) {
        let mut data = BytesMut::with_capacity(1 + algorithms.len() * 2);
        data.put_u8((algorithms.len() * 2) as u8);
        for &alg in algorithms {
            data.put_u16(alg);
        }
        self.add_extension(TlsExtensions::COMPRESS_CERT, &data);
    }

    pub fn status_request(&mut self) {
        let mut data = BytesMut::with_capacity(5);
        data.put_u8(OCSP_STATUS_TYPE);
        data.put_u16(0);
        data.put_u16(0);
        self.add_extension(TlsExtensions::STATUS_REQUEST, &data);
    }

    pub fn ec_point_formats(&mut self) {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(1);
        data.put_u8(0x00);
        self.add_extension(TlsExtensions::EC_POINT_FORMATS, &data);
    }

    pub fn signed_certificate_timestamp(&mut self) {
        self.add_extension(TlsExtensions::SCT, &[]);
    }

    pub fn delegated_credential(&mut self, algs: TlsSignatures) {
        let mut data = BytesMut::with_capacity(2 + algs.0.len() * 2);
        data.put_u16((algs.0.len() * 2) as u16);
        for &a in algs.0 {
            data.put_u16(a);
        }
        self.add_extension(TlsExtensions::DELEGATED_CREDENTIAL, &data);
    }

    pub fn session_ticket(&mut self) {
        self.add_extension(TlsExtensions::SESSION_TICKET, &[]);
    }

    pub fn renegotiation_info(&mut self) {
        self.add_extension(TlsExtensions::RENEGOTIATION_INFO, &[0x00]);
    }

    pub fn padding(&mut self, target_size: usize, overhead: usize) {
        let current_total_size = self.payload.len() + overhead;

        if target_size > current_total_size + 4 {
            let pad_len = target_size - current_total_size - 4;
            let data = vec![0u8; pad_len];
            self.add_extension(TlsExtensions::PADDING, &data);
        }
    }

    pub fn apply_profile(
        &mut self,
        profile: &BrowserProfile,
        host: &str,
        pub_key: &[u8],
        overhead: usize,
    ) {
        for &ext_id in &profile.extension_order {
            match ext_id {
                TlsExtensions::SNI => self.server_name(host),
                TlsExtensions::SUPPORTED_GROUPS => self.supported_groups(profile.groups),
                TlsExtensions::SIGNATURE_ALGORITHMS => {
                    self.signature_algorithms(profile.signatures)
                }
                TlsExtensions::ALPN => self.alpn(profile.alpn),
                TlsExtensions::SCT => self.signed_certificate_timestamp(),
                TlsExtensions::EMS => self.extended_main_secret(),
                TlsExtensions::COMPRESS_CERT => {
                    self.compress_certificate(&[CERT_COMPRESSION_BROTLI])
                }
                TlsExtensions::DELEGATED_CREDENTIAL => {
                    self.delegated_credential(profile.delegated_signatures)
                }
                TlsExtensions::SESSION_TICKET => self.session_ticket(),
                TlsExtensions::SUPPORTED_VERSIONS => self.supported_versions(profile.versions),
                TlsExtensions::PSK_MODES => self.psk_key_exchange_modes(),
                TlsExtensions::KEY_SHARE => self.key_share(profile, pub_key),
                TlsExtensions::ALPS => {
                    if !profile.alps_protocols.is_empty() {
                        self.application_settings(profile.alps_protocols);
                    }
                }
                TlsExtensions::STATUS_REQUEST => self.status_request(),
                TlsExtensions::EC_POINT_FORMATS => self.ec_point_formats(),
                TlsExtensions::RENEGOTIATION_INFO => self.renegotiation_info(),
                TlsExtensions::PADDING => {
                    if profile.target_padding_len > 0 {
                        self.padding(profile.target_padding_len as usize, overhead);
                    }
                }

                id if TlsExtensions::is_grease(id) => {
                    if profile.has_grease {
                        self.grease_with_id(id);
                    }
                }
                _ => self.apply_generic_extension(ext_id, profile),
            }
        }
    }

    pub fn build(&mut self) -> Bytes {
        self.payload.split().freeze()
    }
}
