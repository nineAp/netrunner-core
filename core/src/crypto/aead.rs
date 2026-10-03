//! Shared AEAD selection and in-place operations for NRXP stream/datagram data.

use bytes::BytesMut;

/// Client preference for the NRXP data-plane AEAD.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DataCipherPreference {
    /// Let the node choose its preferred supported AES-GCM suite.
    #[default]
    Auto,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl DataCipherPreference {
    pub const fn wire_code(self) -> u8 {
        match self {
            Self::Auto => 0,
            Self::Aes128Gcm => 1,
            Self::Aes256Gcm => 2,
            Self::ChaCha20Poly1305 => 3,
        }
    }

    pub const fn from_wire_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Auto),
            1 => Some(Self::Aes128Gcm),
            2 => Some(Self::Aes256Gcm),
            3 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn from_config(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub const fn requested_tls_suite(self) -> Option<u16> {
        match self {
            Self::Auto => None,
            Self::Aes128Gcm => Some(0x1301),
            Self::Aes256Gcm => Some(0x1302),
            Self::ChaCha20Poly1305 => Some(0x1303),
        }
    }

    pub(crate) const fn matches_suite(self, suite: AeadSuite) -> bool {
        match self {
            Self::Auto => true,
            Self::Aes128Gcm => matches!(suite, AeadSuite::Aes128Gcm),
            Self::Aes256Gcm => matches!(suite, AeadSuite::Aes256Gcm),
            Self::ChaCha20Poly1305 => matches!(suite, AeadSuite::ChaCha20Poly1305),
        }
    }
}

#[cfg(test)]
mod preference_tests {
    use super::DataCipherPreference as Preference;

    #[test]
    fn preference_names_and_wire_codes_round_trip() {
        for (name, preference) in [
            ("auto", Preference::Auto),
            ("aes-128-gcm", Preference::Aes128Gcm),
            ("aes-256-gcm", Preference::Aes256Gcm),
            ("chacha20-poly1305", Preference::ChaCha20Poly1305),
        ] {
            assert_eq!(Preference::from_config(name), Some(preference));
            assert_eq!(
                Preference::from_wire_code(preference.wire_code()),
                Some(preference)
            );
        }
        assert_eq!(Preference::from_config("invalid"), None);
        assert_eq!(Preference::from_wire_code(255), None);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AeadSuite {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl AeadSuite {
    /// TLS 1.3 suite identifiers already exchanged in the masked hello.
    pub(crate) fn from_tls_suite(suite: u16) -> Option<Self> {
        match suite {
            0x1301 => Some(Self::Aes128Gcm),
            0x1302 => Some(Self::Aes256Gcm),
            0x1303 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub(crate) fn tls_suite(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x1301,
            Self::Aes256Gcm => 0x1302,
            Self::ChaCha20Poly1305 => 0x1303,
        }
    }
}

#[derive(Debug)]
pub(crate) enum AeadError {
    RustCrypto(chacha20poly1305::aead::Error),
    #[cfg(feature = "ring-aead")]
    Ring(ring::error::Unspecified),
    UnsupportedSuite,
    NonceExhausted,
}

/// AEAD primitive cached for one key/epoch. The nonce is supplied by the
/// caller so stream and datagram transports share exactly the same backend.
pub(crate) enum AeadCipher {
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
    #[cfg(feature = "ring-aead")]
    Ring(ring::aead::LessSafeKey),
}

impl AeadCipher {
    pub(crate) fn new(suite: AeadSuite, key: &[u8; 32]) -> Result<Self, AeadError> {
        use chacha20poly1305::KeyInit;
        match suite {
            AeadSuite::ChaCha20Poly1305 => Ok(Self::ChaCha(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                    .expect("ChaCha20-Poly1305 key is 32 bytes"),
            )),
            AeadSuite::Aes128Gcm => {
                #[cfg(feature = "ring-aead")]
                {
                    let key = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key[..16])
                        .map_err(AeadError::Ring)?;
                    Ok(Self::Ring(ring::aead::LessSafeKey::new(key)))
                }
                #[cfg(not(feature = "ring-aead"))]
                {
                    Err(AeadError::UnsupportedSuite)
                }
            }
            AeadSuite::Aes256Gcm => {
                #[cfg(feature = "ring-aead")]
                {
                    let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
                        .map_err(AeadError::Ring)?;
                    Ok(Self::Ring(ring::aead::LessSafeKey::new(key)))
                }
                #[cfg(not(feature = "ring-aead"))]
                {
                    Err(AeadError::UnsupportedSuite)
                }
            }
        }
    }

    pub(crate) fn seal(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        data: &mut BytesMut,
    ) -> Result<(), AeadError> {
        match self {
            Self::ChaCha(cipher) => {
                use chacha20poly1305::aead::generic_array::GenericArray;
                use chacha20poly1305::AeadInPlace;
                cipher
                    .encrypt_in_place(&GenericArray::from(nonce), aad, data)
                    .map_err(AeadError::RustCrypto)
            }
            #[cfg(feature = "ring-aead")]
            Self::Ring(cipher) => {
                let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
                data.reserve(ring::aead::AES_256_GCM.tag_len());
                let tag = cipher
                    .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(aad), data.as_mut())
                    .map_err(AeadError::Ring)?;
                data.extend_from_slice(tag.as_ref());
                Ok(())
            }
        }
    }

    pub(crate) fn open(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        data: &mut BytesMut,
    ) -> Result<(), AeadError> {
        match self {
            Self::ChaCha(cipher) => {
                use chacha20poly1305::aead::generic_array::GenericArray;
                use chacha20poly1305::AeadInPlace;
                cipher
                    .decrypt_in_place(&GenericArray::from(nonce), aad, data)
                    .map_err(AeadError::RustCrypto)
            }
            #[cfg(feature = "ring-aead")]
            Self::Ring(cipher) => {
                let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
                let plaintext_len = cipher
                    .open_in_place(nonce, ring::aead::Aad::from(aad), data.as_mut())
                    .map_err(AeadError::Ring)?
                    .len();
                data.truncate(plaintext_len);
                Ok(())
            }
        }
    }
}

/// In-place AEAD stream interface used by the NRXP record codec.
pub(crate) trait AeadPacker {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<(), AeadError>;
    fn decrypt(&mut self, data: &mut BytesMut) -> Result<(), AeadError>;
}
