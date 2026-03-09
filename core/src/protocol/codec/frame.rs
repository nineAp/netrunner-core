use bytes::{BufMut, Bytes, BytesMut};

use crate::protocol::codec::padding::Padding;

#[derive(Copy, Clone, Debug)]
pub enum FrameType {
    Connect = 0x00,
    Data = 0x01,
    Close = 0x02,
    Heartbeat = 0x03,
}

#[derive(Copy, Clone)]
pub struct FrameHeader {
    pub auth_tag: [u8; 16],
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub payload_len: u16,
    pub padding_len: u16,
}

pub struct Frame {
    pub header: FrameHeader,
    pub payload: Bytes,
    pub padding: Bytes,
}

const AUTH_TAG_SIZE: u16 = 16;
const STREAM_ID_SIZE: u16 = 4;
const FRAME_TYPE_SIZE: u16 = 1;
const PAYLOAD_LEN_SIZE: u16 = 2;
const PADDING_LEN_SIZE: u16 = 2;

pub const FRAME_HEADER_SIZE: u16 =
    AUTH_TAG_SIZE + STREAM_ID_SIZE + FRAME_TYPE_SIZE + PAYLOAD_LEN_SIZE + PADDING_LEN_SIZE;

impl Frame {
    pub fn into_bytes(self, auth_key: &[u8; 16]) -> BytesMut {
        let updated_padding = Padding::generate_padding();
        let total_size = FRAME_HEADER_SIZE as usize + self.payload.len() + self.padding.len();
        let mut buf = BytesMut::with_capacity(total_size);

        buf.put_slice(auth_key);
        buf.put_u32(self.header.stream_id);
        buf.put_u8(self.header.frame_type as u8);
        buf.put_u16(self.header.payload_len);
        buf.put_u16(updated_padding.len);

        buf.put(self.payload);

        buf.put(updated_padding.data);

        buf
    }
}
