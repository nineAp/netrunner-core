use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

// Using your provided constants and types
use crate::tlseng::{
    consts::*,
    params::{TlsGroups, TlsSignatures, TlsVersions},
    profile::profile::BrowserProfile,
    values::*,
};

#[derive(Debug)]
pub struct Extension {
    pub etype: u16,
    pub elen: u16,
    pub data: Bytes,
}

#[derive(Debug)]
pub struct ExtensionStack {
    pub extensions: Vec<Extension>,
}

impl Extension {
    pub fn new(etype: u16, data: Bytes) -> Self {
        Self {
            etype,
            elen: data.len() as u16,
            data,
        }
    }
    pub fn pack(etype: u16, data: &[u8]) -> Bytes {
        let mut ext = BytesMut::with_capacity(4 + data.len());
        ext.put_u16(etype);
        ext.put_u16(data.len() as u16);
        ext.put_slice(data);
        ext.freeze()
    }
}

pub struct ExtensionBuilder {
    payload: BytesMut,
}

impl ExtensionBuilder {
    pub fn new() -> Self {
        Self {
            payload: BytesMut::with_capacity(2048),
        }
    }

    /// Internal helper to pack and append an extension.
    fn add_extension(&mut self, etype: u16, data: &[u8]) {
        let ext = Extension::pack(etype, data);
        self.payload.put_slice(&ext);
    }

    /// 0x?a?a - Randomized GREASE
    pub fn grease(&mut self) {
        let mut rng = rand::rng();
        let rnd = Rng::next_u32(&mut rng) % 16;
        let etype = GREASE_IDENTIFIERS[rnd as usize];
        self.add_extension(etype, &[]);
    }

    /// Used for exact hex-matching of GREASE values
    pub fn grease_fixed(&mut self, etype: u16) {
        self.add_extension(etype, &[]);
    }

    /// 0x0000 - SNI
    pub fn server_name(&mut self, host: &str) {
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len() as u16;
        let list_inner_len = 1 + 2 + host_len;

        let mut data = BytesMut::with_capacity(2 + list_inner_len as usize);
        data.put_u16(list_inner_len);
        data.put_u8(TYPE_HOST_NAME);
        data.put_u16(host_len);
        data.put_slice(host_bytes);

        self.add_extension(EXT_TYPE_SNI, &data);
    }

    /// 0x0017 - Extended Master Secret
    pub fn extended_main_secret(&mut self) {
        self.add_extension(EXT_EXTENDED_MASTER_SECRET, &[]);
    }

    /// 0x000a - Supported Groups
    pub fn supported_groups(&mut self, groups: TlsGroups) {
        let mut data = BytesMut::with_capacity(2 + groups.0.len() * 2);
        data.put_u16((groups.0.len() * 2) as u16);
        for &g in groups.0 {
            data.put_u16(g);
        }
        self.add_extension(EXT_SUPPORTED_GROUPS, &data);
    }

    /// 0x000d - Signature Algorithms
    pub fn signature_algorithms(&mut self, algs: TlsSignatures) {
        let mut data = BytesMut::with_capacity(2 + algs.0.len() * 2);
        data.put_u16((algs.0.len() * 2) as u16);
        for &a in algs.0 {
            data.put_u16(a);
        }
        self.add_extension(EXT_SIGNATURE_ALGORITHMS, &data);
    }

    /// 0x44cd - ALPS (Application Settings)
    /// Updated to support specific protocols
    pub fn application_settings(&mut self, protocols: &[&str]) {
        let mut data = BytesMut::new();
        for proto in protocols {
            let p_bytes = proto.as_bytes();
            data.put_u8(p_bytes.len() as u8);
            data.put_slice(p_bytes);
            data.put_u16(0); // Empty settings per-protocol
        }
        self.add_extension(EXT_ALPS, &data);
    }

    /// 0x002b - Supported Versions
    pub fn supported_versions(&mut self, versions: TlsVersions) {
        let mut data = BytesMut::with_capacity(1 + versions.0.len() * 2);
        data.put_u8((versions.0.len() * 2) as u8);
        for &v in versions.0 {
            data.put_u16(v);
        }
        self.add_extension(EXT_SUPPORTED_VERSIONS, &data);
    }

    /// 0x002d - PSK Key Exchange Modes
    pub fn psk_key_exchange_modes(&mut self) {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(1);
        data.put_u8(PSK_DHE_KE_MODE);
        self.add_extension(EXT_PSK_KEY_EXCHANGE_MODES, &data);
    }

    /// 0x001b - Certificate Compression
    pub fn compress_certificate(&mut self, algorithms: &[u16]) {
        let mut data = BytesMut::with_capacity(1 + algorithms.len() * 2);
        data.put_u8((algorithms.len() * 2) as u8);
        for &alg in algorithms {
            data.put_u16(alg);
        }
        self.add_extension(EXT_COMPRESS_CERTIFICATE, &data);
    }

    /// 0x0005 - Status Request
    pub fn status_request(&mut self) {
        let mut data = BytesMut::with_capacity(5);
        data.put_u8(OCSP_STATUS_TYPE);
        data.put_u16(0); // responder_id_list
        data.put_u16(0); // request_extensions
        self.add_extension(EXT_STATUS_REQUEST, &data);
    }

    /// 0x0033 - Key Share
    /// Corrected: ClientHello KeyShare has a list length AND a group/key length
    pub fn key_share(&mut self, public_key: &[u8]) {
        let mut data = BytesMut::with_capacity(38);
        data.put_u16(34); // Total Key Share List Length
        data.put_u16(GROUP_X25519);
        data.put_u16(32); // Public Key length
        data.put_slice(public_key);
        self.add_extension(EXT_KEY_SHARE, &data);
    }

    /// 0x000b - EC Point Formats
    pub fn ec_point_formats(&mut self) {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(1);
        data.put_u8(EC_POINT_FORMAT_UNCOMPRESSED);
        self.add_extension(EXT_EC_POINT_FORMATS, &data);
    }

    /// 0x0012 - SCT
    pub fn signed_certificate_timestamp(&mut self) {
        self.add_extension(EXT_SIGNED_CERT_TIMESTAMP, &[]);
    }

    /// 0x0022 - Delegated Credentials
    pub fn delegated_credential(&mut self, algs: TlsSignatures) {
        let mut data = BytesMut::with_capacity(2 + algs.0.len() * 2);
        data.put_u16((algs.0.len() * 2) as u16);
        for &a in algs.0 {
            data.put_u16(a);
        }
        self.add_extension(EXT_DELEGATED_CREDENTIAL, &data);
    }

    /// 0x0010 - ALPN
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
        self.add_extension(EXT_ALPN, &extension_data);
    }

    /// 0x0023 - Session Ticket
    pub fn session_ticket(&mut self) {
        self.add_extension(0x0023, &[]);
    }

    pub fn padding(&mut self, target_size: usize) {
        // Текущий размер накопленной нагрузки
        let current_size = self.payload.len();

        // 4 байта резервируем под заголовок самого расширения (Type + Length)
        if target_size > current_size + 4 {
            let pad_len = target_size - current_size - 4;
            let data = vec![0u8; pad_len];

            // Используем pack, как и в других методах
            let ext = Extension::pack(EXT_PADDING, &data);
            self.payload.put_slice(&ext);
        }
    }

    /// 0xff01 - Renegotiation Info
    pub fn renegotiation_info(&mut self) {
        self.add_extension(EXT_RENEGOTIATION_INFO, &[0x00]);
    }

    pub fn build(&mut self) -> Bytes {
        self.payload.split().freeze()
    }

    pub fn apply_profile(&mut self, profile: &BrowserProfile, host: &str, pub_key: &[u8]) {
        for &ext_id in profile.extension_order {
            match ext_id {
                0x0000 => self.server_name(host),
                0x000a => self.supported_groups(profile.groups),
                0x000d => self.signature_algorithms(profile.signatures),
                0x0010 => self.alpn(&["h2", "http/1.1"]),
                0x0012 => self.signed_certificate_timestamp(),
                0x0017 => self.extended_main_secret(),
                0x001b => self.compress_certificate(&[CERT_COMPRESSION_BROTLI]),
                0x0022 => self.delegated_credential(profile.delegated_signatures),
                0x0023 => self.session_ticket(),
                0x002b => self.supported_versions(profile.versions),
                0x002d => self.psk_key_exchange_modes(),
                0x0033 => self.key_share(pub_key),
                0x44cd => self.application_settings(&["h2"]),
                0x0005 => self.status_request(),
                0x000b => self.ec_point_formats(),
                0xff01 => self.renegotiation_info(),
                // Padding logic
                0x0015 => {
                    if profile.is_chromium {
                        // Standard Chromium behavior: pad to 512 bytes
                        self.padding(512);
                    } else {
                        // Non-chromium might use different logic or no padding
                        self.add_extension(0x0015, &[]);
                    }
                }
                id if (id & 0x0f0f) == 0x0a0a => self.grease(),
                _ => {}
            }
        }
    }
}
