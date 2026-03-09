use hkdf::Hkdf;
use sha2::Sha256;

pub struct HKDF;

impl HKDF {
    pub fn extract_key(salt: &[u8], ikm: &[u8]) -> Hkdf<Sha256> {
        let extracted_key = Hkdf::<Sha256>::new(Some(salt), ikm);
        extracted_key
    }

    pub fn expand_key<const N: usize>(
        extracted_key: &Hkdf<Sha256>,
        mark: &[u8],
    ) -> Result<[u8; N], String> {
        let mut expanded_key: [u8; N] = [0u8; N];
        extracted_key
            .expand(mark, &mut expanded_key)
            .map_err(|e| e.to_string())?;
        Ok(expanded_key)
    }
}
