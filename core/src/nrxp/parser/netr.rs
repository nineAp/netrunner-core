use bytes::{Buf, BytesMut};

use crate::nrxp::{
    codec::frame::{Frame, FrameHeader, FrameType, FRAME_HEADER_SIZE},
    parser::parser::Parser,
};

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
