use bytes::Buf;

pub trait PeekExt: Buf {
    fn peek_u16(&self, offset: usize) -> Option<u16> {
        let chunk = self.chunk();
        if chunk.len() >= offset + 2 {
            let b = &chunk[offset..offset + 2];
            Some(u16::from_be_bytes([b[0], b[1]]))
        } else {
            None
        }
    }

    fn peek_u24(&self, offset: usize) -> Option<u32> {
        let chunk = self.chunk();
        if chunk.len() >= offset + 3 {
            let b = &chunk[offset..offset + 3];
            Some(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
        } else {
            None
        }
    }
}

impl<T: Buf> PeekExt for T {}
