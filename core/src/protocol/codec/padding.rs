use bytes::Bytes;
use rand::Rng;

use crate::protocol::codec::MAX_PADDING_SIZE;

pub struct Padding {
    pub len: u16,
    pub data: Bytes,
}

impl Padding {
    pub fn generate_padding() -> Padding {
        let mut rng = rand::rng();
        let random_u32: u32 = rng.next_u32();
        let padding_len: u16 = (random_u32 % MAX_PADDING_SIZE) as u16;
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill_bytes(&mut padding);
        Padding {
            len: padding_len,
            data: Bytes::from(padding),
        }
    }
}
