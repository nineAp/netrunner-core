use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{crypto::hmac::generate_auth_tag, protocol::codec::padding::Padding};

#[derive(Copy, Clone)]
enum FrameType {
    Connect = 0x00,
    Data = 0x01,
    Close = 0x02,
    Heartbeat = 0x03,
}

#[derive(Copy, Clone)]
struct FrameHeader {
    pub auth_tag: [u8; 16],
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub payload_len: u16,
    pub padding_len: u16,
}

pub struct Frame {
    header: FrameHeader,
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

impl FrameHeader {
    fn get_header(bytes: &mut BytesMut) -> Option<Self> {
        if bytes.len() < FRAME_HEADER_SIZE as usize {
            return None;
        }

        let mut header_chunk = bytes.split_to(FRAME_HEADER_SIZE as usize);

        let mut auth_tag = [0u8; 16];
        header_chunk.copy_to_slice(&mut auth_tag);

        let stream_id = header_chunk.get_u32();

        let frame_type_byte = header_chunk.get_u8();
        let frame_type = match frame_type_byte {
            0x00 => FrameType::Connect,
            0x01 => FrameType::Data,
            0x02 => FrameType::Close,
            0x03 => FrameType::Heartbeat,
            _ => FrameType::Close,
        };

        let payload_len = header_chunk.get_u16();
        let padding_len = header_chunk.get_u16();

        Some(Self {
            auth_tag,
            stream_id,
            frame_type,
            payload_len,
            padding_len,
        })
    }
}

impl Frame {
    pub fn unpack(bytes: &mut BytesMut) -> Result<Option<Self>, String> {
        if bytes.len() < FRAME_HEADER_SIZE as usize {
            return Ok(None);
        }

        let p_len = u16::from_be_bytes([bytes[21], bytes[22]]) as usize;
        let pad_len = u16::from_be_bytes([bytes[23], bytes[24]]) as usize;

        if bytes.len() < (FRAME_HEADER_SIZE as usize + p_len + pad_len) {
            return Ok(None);
        }
        let header = FrameHeader::get_header(bytes).unwrap();
        let payload = bytes.split_to(p_len).freeze();
        let padding = bytes.split_to(pad_len).freeze();

        Ok(Some(Self {
            header,
            payload,
            padding,
        }))
    }

    pub fn into_bytes(self) -> BytesMut {
        let updated_padding = Padding::generate_padding();
        let total_size = FRAME_HEADER_SIZE as usize + self.payload.len() + self.padding.len();
        let mut buf = BytesMut::with_capacity(total_size);
        let hmac = generate_auth_tag(&[0; 16]);

        buf.put_slice(&hmac);
        buf.put_u32(self.header.stream_id);
        buf.put_u8(self.header.frame_type as u8);
        buf.put_u16(self.header.payload_len);
        buf.put_u16(updated_padding.len);

        buf.put(self.payload);

        buf.put(updated_padding.data);

        buf
    }
}
