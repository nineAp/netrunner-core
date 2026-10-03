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
//! - **Padding** — ломает анализ длин пакетов. Управляющие кадры получают
//!   0..255 случайных байт; `Data`/`UdpData` выравниваются до ближайшего
//!   "круглого" бакета (256/512/1024/2048/4096/8192, см. `Frame::into_bytes`)
//!   — кроме кадров, уже близких к максимальному размеру (крупные закачки),
//!   где паддинг только бил бы по throughput без выигрыша в приватности.
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
mod datagram;
mod errors;
mod frame;

#[cfg(all(test, feature = "ring-aead"))]
pub(crate) use bridge::HandshakeMessage;
pub(crate) use bridge::TlsBridge;
pub(crate) use codec::{Codec, RxCodec, TxCodec};
// `expand_counter`/`SealedDatagram` are used only inside `datagram` itself —
// full counter reconstruction and the seal result stay internal to
// `DatagramTx::seal`/`DatagramRx::open`; callers outside this module only
// ever need `truncate_counter` (to place a wire-width seq/PN) and the two
// codec types themselves.
pub(crate) use datagram::{truncate_counter, DatagramRx, DatagramTx};
pub(crate) use errors::{ErrorAction, ErrorStage, TlsError};
pub(crate) use frame::{Frame, FrameType, MAX_FRAME_PAYLOAD};
