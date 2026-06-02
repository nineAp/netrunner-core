use crate::parser::Parser;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;

pub const MAX_PADDING_SIZE: u32 = 255;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub(crate) enum FrameType {
    Connect = 0x00,
    Data = 0x01,
    Close = 0x02,
    Heartbeat = 0x03,
    UdpConnect = 0x04,
    UdpData = 0x05,
}

// 🔥 ОПТИМИЗАЦИЯ: Поля отсортированы по размеру для идеального Data Packing
// (устраняет скрытые байты выравнивания, структура ровно 28 байт в памяти).
#[derive(Copy, Clone)]
pub(crate) struct FrameHeader {
    pub(crate) auth_tag: [u8; 16],
    pub(crate) stream_id: u32,
    pub(crate) payload_len: u16,
    pub(crate) padding_len: u16,
    pub(crate) frame_type: FrameType,
}

pub(crate) struct Frame {
    // 🔥 ОПТИМИЗАЦИЯ: Поле _padding удалено, так как оно никогда не используется.
    pub(crate) payload: Bytes,
    pub(crate) header: FrameHeader,
}

const AUTH_TAG_SIZE: u16 = 16;
const STREAM_ID_SIZE: u16 = 4;
const FRAME_TYPE_SIZE: u16 = 1;
const PAYLOAD_LEN_SIZE: u16 = 2;
const PADDING_LEN_SIZE: u16 = 2;

pub const FRAME_HEADER_SIZE: u16 =
    AUTH_TAG_SIZE + STREAM_ID_SIZE + FRAME_TYPE_SIZE + PAYLOAD_LEN_SIZE + PADDING_LEN_SIZE; // 25 bytes

impl Frame {
    #[inline(always)]
    pub(crate) fn new(stream_id: u32, frame_type: FrameType, payload: Bytes) -> Self {
        Self {
            header: FrameHeader {
                auth_tag: [0u8; 16],
                stream_id,
                payload_len: payload.len() as u16,
                padding_len: 0,
                frame_type,
            },
            payload,
        }
    }

    #[inline]
    pub(crate) fn into_bytes(mut self, auth_key: &[u8; 16]) -> BytesMut {
        // 🔥 ОПТИМИЗАЦИЯ: Быстрая побитовая маска (& 0xFF) вместо дорогого деления с остатком (%)
        let padding_len = match self.header.frame_type {
            FrameType::Data | FrameType::UdpData => 0,
            _ => (rand::rng().next_u32() & 0xFF) as u16,
        };

        self.header.padding_len = padding_len;

        let total_size = FRAME_HEADER_SIZE as usize + self.payload.len() + padding_len as usize;
        let mut buf = BytesMut::with_capacity(total_size);

        // 🔥 ОПТИМИЗАЦИЯ (Zero-Cost Abstraction): Собираем заголовок в стеке (в регистрах)
        // и пишем в память ровно ОДНИМ вызовом copy_from_slice.
        // Это избавляет от 5 последовательных проверок границ буфера.
        let mut header_buf = [0u8; 25];
        header_buf[0..16].copy_from_slice(auth_key);
        header_buf[16..20].copy_from_slice(&self.header.stream_id.to_be_bytes());
        header_buf[20] = self.header.frame_type as u8;
        header_buf[21..23].copy_from_slice(&self.header.payload_len.to_be_bytes());
        header_buf[23..25].copy_from_slice(&self.header.padding_len.to_be_bytes());

        buf.put_slice(&header_buf);
        buf.put(self.payload);

        if padding_len > 0 {
            // 🔥 ОПТИМИЗАЦИЯ (Zero-Copy): Никаких vec![]. Мы просто растягиваем буфер нулями
            // и напрямую заполняем хвост через RNG. Ни одного лишнего выделения памяти.
            let start = buf.len();
            buf.resize(total_size, 0);
            rand::rng().fill_bytes(&mut buf[start..]);
        }

        buf
    }
}

impl Parser for FrameHeader {
    type Error = String;

    #[inline(always)]
    fn can_parse(bytes: &BytesMut) -> bool {
        bytes.len() >= FRAME_HEADER_SIZE as usize
    }

    #[inline]
    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        // 🔥 ОПТИМИЗАЦИЯ (Zero-Copy): Больше нет split_to()! Мы просто читаем
        // срез памяти напрямую. Не создается объект Bytes, не обновляются счетчики ссылок.
        let header_slice = &bytes[..FRAME_HEADER_SIZE as usize];

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&header_slice[0..16]);

        let stream_id = u32::from_be_bytes(header_slice[16..20].try_into().unwrap());

        let frame_type = match header_slice[20] {
            0x00 => FrameType::Connect,
            0x01 => FrameType::Data,
            0x02 => FrameType::Close,
            0x03 => FrameType::Heartbeat,
            0x04 => FrameType::UdpConnect,
            0x05 => FrameType::UdpData,
            _ => FrameType::Close,
        };

        let payload_len = u16::from_be_bytes(header_slice[21..23].try_into().unwrap());
        let padding_len = u16::from_be_bytes(header_slice[23..25].try_into().unwrap());

        // Просто смещаем внутренний курсор оригинального буфера
        bytes.advance(FRAME_HEADER_SIZE as usize);

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

    #[inline(always)]
    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < FRAME_HEADER_SIZE as usize {
            return false;
        }

        let p_len = u16::from_be_bytes([bytes[21], bytes[22]]) as usize;
        let pad_len = u16::from_be_bytes([bytes[23], bytes[24]]) as usize;

        bytes.len() >= (FRAME_HEADER_SIZE as usize + p_len + pad_len)
    }

    #[inline]
    fn parse(bytes: &mut BytesMut) -> Result<Option<Self>, Self::Error> {
        if !Self::can_parse(bytes) {
            return Ok(None);
        }

        let header = FrameHeader::parse(bytes)?.unwrap(); // Безопасно, т.к. can_parse прошел

        let p_len = header.payload_len as usize;
        let pad_len = header.padding_len as usize;

        // payload - единственное место, где мы аллоцируем Bytes объект (zero-copy clone),
        // так как он реально пойдет дальше по каналам в обработку.
        let payload = bytes.split_to(p_len).freeze();

        // 🔥 ОПТИМИЗАЦИЯ: Паддинг нам не нужен. Мы просто смещаем курсор, игнорируя эти байты.
        // Экономит целую аллокацию Bytes и вызов freeze() на каждом пакете.
        bytes.advance(pad_len);

        Ok(Some(Self { header, payload }))
    }
}
