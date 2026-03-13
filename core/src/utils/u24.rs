use bytes::Buf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U24([u8; 3]);

impl U24 {
    pub fn from_u32(value: u32) -> Self {
        let b = value.to_be_bytes();
        U24([b[1], b[2], b[3]])
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    pub fn from_slice(slice: &[u8]) -> u32 {
        u32::from_be_bytes([0, slice[0], slice[1], slice[2]])
    }
}

pub trait BufExt: Buf {
    fn get_u24(&mut self) -> u32 {
        let b1 = self.get_u8() as u32;
        let b2 = self.get_u8() as u32;
        let b3 = self.get_u8() as u32;
        (b1 << 16) | (b2 << 8) | b3
    }
}

impl<T: Buf> BufExt for T {}
