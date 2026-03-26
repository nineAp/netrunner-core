use bytes::{Buf, BufMut, Bytes, BytesMut};

use rand::Rng;

use crate::parser::Parser;

pub struct Padding {
    pub len: u16,
    pub data: Bytes,
}

pub const MAX_PADDING_SIZE: u32 = 255;

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

#[derive(Copy, Clone, Debug)]
pub enum FrameType {
    Connect = 0x00,
    Data = 0x01,
    Close = 0x02,
    Heartbeat = 0x03,
    UdpConnect = 0x04,
    UdpData = 0x05,
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

impl Parser for FrameHeader {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        bytes.len() >= FRAME_HEADER_SIZE as usize
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
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

        Ok(Some(Self {
            auth_tag,
            stream_id,
            frame_type,
            payload_len,
            padding_len,
        }))
    }
}

impl Parser for Frame {
    type Error = String;

    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < FRAME_HEADER_SIZE as usize {
            return false;
        }

        let p_len = u16::from_be_bytes([bytes[21], bytes[22]]) as usize;
        let pad_len = u16::from_be_bytes([bytes[23], bytes[24]]) as usize;

        netrunner_logger::debug!(
            "CAN_PARSE: p_len={}, pad_len={}, total_needed={}, have={}",
            p_len,
            pad_len,
            25 + p_len + pad_len,
            bytes.len()
        );

        bytes.len() >= (FRAME_HEADER_SIZE as usize + p_len + pad_len)
    }

    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let header = FrameHeader::parse(bytes)?.ok_or("Failed to parse header")?;

        let p_len = header.payload_len as usize;
        let pad_len = header.padding_len as usize;

        if bytes.len() < p_len + pad_len {
            return Err("Buffer corrupted: length mismatch after header parse".into());
        }

        let payload = bytes.split_to(p_len).freeze();
        let padding = bytes.split_to(pad_len).freeze();

        Ok(Some(Self {
            header,
            payload,
            padding,
        }))
    }
}
