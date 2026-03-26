// Скрываем модули
mod bridge;
mod codec;
mod errors;
mod frame;
mod socks;

// Экспортируем для остального ядра только необходимые типы
pub(crate) use codec::Codec;
pub(crate) use errors::{ErrorAction, ErrorStage, TlsError};
pub(crate) use frame::{Frame, FrameType, FRAME_HEADER_SIZE, MAX_PADDING_SIZE};
pub use socks::TargetAddress;
pub(crate) use socks::{SocksReply, SocksRequest};
