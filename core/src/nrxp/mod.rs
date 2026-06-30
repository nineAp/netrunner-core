//! # Протокол NRXP (`nrxp`) — Netrunner eXchange Protocol
//!
//! Прикладной протокол, который ездит **внутри** замаскированного TLS-канала.
//! Снаружи трафик выглядит как обычные TLS-записи `ApplicationData` (`0x17`), а
//! внутри каждой записи лежит один зашифрованный кадр NRXP с мультиплексированием
//! логических потоков.
//!
//! Этот блок отвечает за «упаковку/распаковку» и ничего не знает о сети как
//! таковой — он лишь превращает `(stream_id, тип, payload)` в байты и обратно.
//!
//! ## Состав блока
//!
//! | Файл        | Ответственность                                                       |
//! |-------------|-----------------------------------------------------------------------|
//! | [`frame`]   | Структура кадра, его (де)сериализация, паддинг.                       |
//! | [`codec`]   | Шифрующий слой: [`TxCodec`]/[`RxCodec`] (кадр ⇄ зашифрованный TLS).    |
//! | [`bridge`]  | TLS-обёртка: хендшейк (`ClientHello`/`ServerHello`) и `ApplicationData`.|
//! | [`errors`]  | [`TlsError`] и стратегия реакции ([`ErrorAction`]: Wait/Redirect/Drop).|
//!
//! ## Формат кадра (25-байтовый заголовок + payload + padding)
//!
//! ```text
//! ┌──────────────┬───────────┬──────┬────────────┬────────────┬─────────┬─────────┐
//! │ Auth Tag     │ Stream ID │ Type │ Payload Len│ Padding Len│ Payload │ Padding │
//! │ 16 байт      │ 4 байта   │ 1 б. │ 2 байта    │ 2 байта    │ N байт  │ 0..255  │
//! └──────────────┴───────────┴──────┴────────────┴────────────┴─────────┴─────────┘
//!   └──────────────────── FRAME_HEADER_SIZE = 25 ────────────────────┘
//! ```
//!
//! - **Auth Tag** — TOTP-подобный HMAC-тег (см. [`SessionAuth`](crate::crypto)),
//!   привязан ко времени → защита от replay со стороны DPI.
//! - **Stream ID** — id логического потока внутри туннеля (нечётные у клиента,
//!   чётные у сервера — так стороны не конфликтуют за номера).
//! - **Type** — [`FrameType`]: `Connect`/`Data`/`Close`/`Heartbeat`/`UdpConnect`/`UdpData`.
//! - **Padding** — случайные байты переменной длины: ломают анализ длин пакетов.
//!   Добавляется только к управляющим кадрам; кадры `Data`/`UdpData` не паддятся
//!   (их и так много, паддинг бил бы по throughput).
//!
//! ## Конвейер кодирования
//!
//! ```text
//!  TX:  Frame::new → into_bytes(tag)      → AEAD encrypt in-place → TlsBridge::pack_app_data
//!  RX:  TlsBridge::unpack_app_data → AEAD decrypt in-place (staging) → Frame::parse
//! ```
//!
//! **Инвариант кодирования:** одна TLS-запись `ApplicationData` = ровно один
//! зашифрованный кадр NRXP. На нём держится потоковая расшифровка в [`codec`].

mod bridge;
mod codec;
mod errors;
mod frame;

pub(crate) use bridge::TlsBridge;
pub(crate) use codec::{Codec, RxCodec, TxCodec};
pub(crate) use errors::{ErrorAction, ErrorStage, TlsError};
pub(crate) use frame::{Frame, FrameType, MAX_FRAME_PAYLOAD};
