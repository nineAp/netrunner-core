//! Кадр NRXP: структура и (де)сериализация.
//!
//! Полный байтовый формат см. в [обзоре модуля](super). Здесь — типы кадра и две
//! зеркальные операции:
//! - [`Frame::into_bytes`] — собрать заголовок + payload + случайный padding в
//!   единый [`BytesMut`] (заготовка под последующее AEAD-шифрование на месте);
//! - реализации [`Parser`] для [`FrameHeader`] и [`Frame`] — разобрать буфер
//!   обратно в кадр, не копируя payload лишний раз (zero-copy через `split_to`).
//!
//! Весь файл написан под zero-copy/zero-alloc на горячем пути — комментарии
//! «🔥 ОПТИМИЗАЦИЯ» помечают места, где это сознательно важно.

use crate::parser::Parser;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;

/// Тип кадра — первый байт после `stream_id`. Числовые значения фиксированы и
/// являются частью wire-формата (менять — это смена версии протокола).
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub(crate) enum FrameType {
    /// Открыть TCP-поток к цели (payload — адрес назначения).
    Connect = 0x00,
    /// Данные TCP-потока.
    Data = 0x01,
    /// Закрыть поток (FIN/abort).
    Close = 0x02,
    /// Keep-alive; держит туннель живым и измеряет RTT.
    Heartbeat = 0x03,
    /// Открыть UDP-«сессию» к цели.
    UdpConnect = 0x04,
    /// Датаграмма UDP-сессии.
    UdpData = 0x05,
    /// Диагностический отчёт клиента (один JSON-снапшот в payload). Холодный
    /// путь: едет по контрольному каналу, сервер сохраняет его в пер-сессионный
    /// файл. Никогда не маршрутизируется в локальные сокеты.
    Diag = 0x06,
    /// Кредит потока для сквозного flow-control (payload — `u32` BE, "можешь
    /// прислать ещё N байт"). Отправляется приёмной стороной по мере
    /// освобождения локального буфера — см. `Muxer::grant_credit`/`consume_credit`.
    Credit = 0x07,
}

/// Разобранный заголовок кадра (25 байт). Поля идут в том же порядке, что и в wire.
#[derive(Copy, Clone)]
pub(crate) struct FrameHeader {
    /// Time-based HMAC-тег (анти-replay). Проверяется приёмной стороной.
    pub(crate) auth_tag: [u8; 16],
    /// Идентификатор логического потока внутри туннеля.
    pub(crate) stream_id: u32,
    /// Длина полезной нагрузки в байтах.
    pub(crate) payload_len: u16,
    /// Длина случайного padding после payload (0 для Data/UdpData).
    pub(crate) padding_len: u16,
    /// Тип кадра.
    pub(crate) frame_type: FrameType,
}

/// Полный разобранный кадр: заголовок + payload (без padding — он отбрасывается).
pub(crate) struct Frame {
    // 🔥 ОПТИМИЗАЦИЯ: Поле _padding удалено, так как оно никогда не используется.
    /// Полезная нагрузка как [`Bytes`] (zero-copy ссылка на исходный буфер).
    pub(crate) payload: Bytes,
    /// Разобранный заголовок.
    pub(crate) header: FrameHeader,
}

// Размеры полей заголовка в байтах (см. формат в обзоре модуля).
const AUTH_TAG_SIZE: u16 = 16;
const STREAM_ID_SIZE: u16 = 4;
const FRAME_TYPE_SIZE: u16 = 1;
const PAYLOAD_LEN_SIZE: u16 = 2;
const PADDING_LEN_SIZE: u16 = 2;

/// Суммарный размер заголовка кадра — 25 байт.
pub const FRAME_HEADER_SIZE: u16 =
    AUTH_TAG_SIZE + STREAM_ID_SIZE + FRAME_TYPE_SIZE + PAYLOAD_LEN_SIZE + PADDING_LEN_SIZE; // 25 bytes
/// Потолок payload одного кадра (16 КБ). Совпадает с размером interleave-чанка
/// writer'а: большие сообщения режутся на куски не больше этого значения.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024;

impl Frame {
    /// Конструирует кадр с нулевым `auth_tag` и `padding_len` — оба заполняются
    /// позже в [`into_bytes`](Frame::into_bytes) при сериализации.
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

    /// Сериализует кадр в [`BytesMut`], готовый к шифрованию на месте.
    ///
    /// `auth_key` здесь — это уже готовый 16-байтовый тег (имя историческое),
    /// который кладётся в начало заголовка. Для `Data`/`UdpData` — выравнивание
    /// до ближайшего бакета из [`bucket_padding`] (throughput всё ещё важнее,
    /// поэтому кадры, уже близкие к максимальному размеру, не паддятся вовсе),
    /// для остальных типов — 0..255 случайных байт. Буфер выделяется один раз
    /// точно под итоговый размер; заголовок собирается на стеке и пишется
    /// одним `copy_from_slice`.
    #[inline]
    pub(crate) fn into_bytes(mut self, auth_key: &[u8; 16]) -> BytesMut {
        // 🔥 ОПТИМИЗАЦИЯ: Быстрая побитовая маска (& 0xFF) вместо дорогого деления с остатком (%)
        let padding_len = match self.header.frame_type {
            FrameType::Data | FrameType::UdpData => Self::bucket_padding(self.payload.len()),
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

    /// Длина паддинга для выравнивания `Data`/`UdpData` кадра до ближайшего
    /// "круглого" бакета вместо точной длины полезной нагрузки.
    ///
    /// Не паддит кадры, уже близкие к [`MAX_FRAME_PAYLOAD`] (крупные бакеты
    /// закачек) — это почти весь трафик объёмных передач, где паддинг только
    /// снижал бы throughput без выигрыша в приватности (снаружи и так виден
    /// кадр максимального размера, угадывать в нём нечего). Именно маленькие
    /// кадры (запросы, интерактив, начало HTTP-ответа) — то место, где по
    /// точной длине конкретного пакета легче всего строить атаки
    /// website/traffic fingerprinting поверх уже неотличимого от HTTPS
    /// хендшейка, поэтому их выравнивание даёт больше всего эффекта за
    /// наименьшие накладные расходы.
    #[inline]
    fn bucket_padding(payload_len: usize) -> u16 {
        const BUCKETS: [usize; 6] = [256, 512, 1024, 2048, 4096, 8192];
        for &bucket in &BUCKETS {
            if payload_len <= bucket {
                return (bucket - payload_len) as u16;
            }
        }
        0
    }
}

/// Разбор только заголовка: `can_parse` проверяет, накопились ли 25 байт,
/// `parse` читает их и сдвигает курсор буфера (payload остаётся в `bytes`).
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
            0x06 => FrameType::Diag,
            0x07 => FrameType::Credit,
            unknown => {
                // After successful AEAD decryption an unknown frame type means a
                // protocol version mismatch or data corruption that the cipher
                // somehow didn't catch. Propagate as an error so the caller can
                // drop the leg and reconnect rather than silently treating it as
                // Close (which would leak resources on the remote end).
                return Err(format!("Unknown FrameType byte: 0x{:02x}", unknown));
            }
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

/// Разбор полного кадра. `can_parse` подглядывает в поля длин прямо в буфере
/// (без сдвига курсора), чтобы убедиться, что пришёл весь кадр целиком; только
/// тогда `parse` извлекает заголовок и payload и пропускает padding.
impl Parser for Frame {
    type Error = String;

    #[inline(always)]
    fn can_parse(bytes: &BytesMut) -> bool {
        if bytes.len() < FRAME_HEADER_SIZE as usize {
            return false;
        }

        // Подглядываем payload_len и padding_len по их смещениям в заголовке,
        // не трогая курсор: байты 21..23 и 23..25.
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

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_KEY: [u8; 16] = [0x42; 16];

    fn round_trip(frame_type: FrameType, payload: &[u8]) -> Frame {
        let frame = Frame::new(7, frame_type, Bytes::copy_from_slice(payload));
        let mut wire = frame.into_bytes(&AUTH_KEY);
        Frame::parse(&mut wire).unwrap().unwrap()
    }

    #[test]
    fn round_trip_preserves_payload_and_metadata() {
        let parsed = round_trip(FrameType::Data, b"some tunnel payload");
        assert_eq!(parsed.header.stream_id, 7);
        assert_eq!(parsed.header.frame_type, FrameType::Data);
        assert_eq!(&parsed.payload[..], b"some tunnel payload");
        assert_eq!(parsed.header.auth_tag, AUTH_KEY);
    }

    #[test]
    fn control_frames_get_random_padding_0_to_255() {
        for frame_type in [
            FrameType::Connect,
            FrameType::Close,
            FrameType::Heartbeat,
            FrameType::UdpConnect,
            FrameType::Diag,
            FrameType::Credit,
        ] {
            let frame = Frame::new(1, frame_type, Bytes::from_static(b"x"));
            let wire = frame.into_bytes(&AUTH_KEY);
            // padding_len живёт в байтах 23..25 заголовка.
            let padding_len = u16::from_be_bytes([wire[23], wire[24]]);
            assert!(
                padding_len <= 255,
                "{:?} padding {} exceeds the 0..=255 range",
                frame_type,
                padding_len
            );
            assert_eq!(
                wire.len(),
                FRAME_HEADER_SIZE as usize + 1 + padding_len as usize
            );
        }
    }

    #[test]
    fn data_frames_never_get_legacy_unbounded_padding() {
        // Регрессия: раньше Data/UdpData вообще не паддились (padding_len == 0
        // всегда). Теперь бакетное выравнивание — здесь просто фиксируем, что
        // поведение осознанно изменилось, а не просто "иногда 0".
        let frame = Frame::new(1, FrameType::Data, Bytes::copy_from_slice(&[0u8; 100]));
        let wire = frame.into_bytes(&AUTH_KEY);
        let padding_len = u16::from_be_bytes([wire[23], wire[24]]);
        assert_eq!(padding_len, (256 - 100) as u16);
    }

    #[test]
    fn bucket_padding_boundaries() {
        // На границе бакета — паддинг 0 (уже ровно на бакете).
        assert_eq!(Frame::bucket_padding(256), 0);
        assert_eq!(Frame::bucket_padding(512), 0);
        assert_eq!(Frame::bucket_padding(8192), 0);
        // На единицу больше границы — едет в следующий бакет.
        assert_eq!(Frame::bucket_padding(257), 512 - 257);
        assert_eq!(Frame::bucket_padding(2049), 4096 - 2049);
        // Пустой payload — паддится до первого бакета.
        assert_eq!(Frame::bucket_padding(0), 256);
        // Крупные кадры (около MAX_FRAME_PAYLOAD) — без паддинга вовсе,
        // throughput объёмных закачек не должен страдать.
        assert_eq!(Frame::bucket_padding(8193), 0);
        assert_eq!(Frame::bucket_padding(MAX_FRAME_PAYLOAD), 0);
    }

    #[test]
    fn data_and_udpdata_frames_are_bucketed_identically() {
        for frame_type in [FrameType::Data, FrameType::UdpData] {
            let frame = Frame::new(1, frame_type, Bytes::copy_from_slice(&[0u8; 300]));
            let wire = frame.into_bytes(&AUTH_KEY);
            let padding_len = u16::from_be_bytes([wire[23], wire[24]]);
            assert_eq!(padding_len, (512 - 300) as u16);
        }
    }

    #[test]
    fn parse_skips_padding_without_exposing_it() {
        let frame = Frame::new(3, FrameType::Heartbeat, Bytes::from_static(b"auth-payload"));
        let mut wire = frame.into_bytes(&AUTH_KEY);

        let parsed = Frame::parse(&mut wire).unwrap().unwrap();
        assert_eq!(&parsed.payload[..], b"auth-payload");
        assert!(
            wire.is_empty(),
            "parse must advance past payload AND padding (random 0..=255 for control frames), leaving nothing behind"
        );
    }

    #[test]
    fn incomplete_frame_is_none() {
        let frame = Frame::new(1, FrameType::Data, Bytes::copy_from_slice(&[0u8; 50]));
        let mut wire = frame.into_bytes(&AUTH_KEY);
        wire.truncate(wire.len() - 1);
        assert!(Frame::parse(&mut wire).unwrap().is_none());
    }

    #[test]
    fn unknown_frame_type_byte_is_an_error() {
        let frame = Frame::new(1, FrameType::Data, Bytes::copy_from_slice(&[0u8; 10]));
        let mut wire = frame.into_bytes(&AUTH_KEY);
        wire[20] = 0xEE; // frame_type byte — не входит ни в один известный вариант
        assert!(Frame::parse(&mut wire).is_err());
    }
}
