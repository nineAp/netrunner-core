use bytes::Buf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U24([u8; 3]);

impl U24 {
    /// Creates a new `U24` from a given `u32` value.
    ///
    /// The `u32` value is converted to big-endian byte order and then split into
    /// three bytes, which are used to initialize the `U24`.
    ///
    /// # Examples
    ///
    ///
    pub fn from_u32(value: u32) -> Self {
        let b = value.to_be_bytes();
        U24([b[1], b[2], b[3]])
    }

    /// Converts the `U24` into a `u32` value.
    ///
    /// The `U24` is converted from big-endian byte order to a `u32` value.
    ///
    /// # Examples
    ///
    ///
    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    /// Converts a slice of three bytes into a `u32` value.
    ///
    /// The slice is interpreted as a big-endian byte order, and the resulting `u32` value is
    /// computed by combining the three bytes into a single 32-bit value.
    pub fn from_slice(slice: &[u8]) -> u32 {
        u32::from_be_bytes([0, slice[0], slice[1], slice[2]])
    }
}

pub trait BufExt: Buf {
    /// Reads three bytes from the buffer and returns a `u32` value.
    ///
    /// The bytes are read in big-endian byte order and then combined into a single `u32` value.
    ///
    /// # Examples
    ///
    ///
    /// let mut buf = BytesMut::from(&[0x12, 0x34, 0x56][..]);
    /// let val = buf.get_u24();
    /// assert_eq!(val, 0x123456);
    fn get_u24(&mut self) -> u32 {
        let b1 = self.get_u8() as u32;
        let b2 = self.get_u8() as u32;
        let b3 = self.get_u8() as u32;
        (b1 << 16) | (b2 << 8) | b3
    }
}

impl<T: Buf> BufExt for T {}
