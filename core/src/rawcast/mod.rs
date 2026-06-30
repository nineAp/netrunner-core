//! # Блок RawCast (`rawcast`) — локальный протокол сокет ⇄ кадр
//!
//! Промежуточный формат между «локальной» стороной клиента (реальные TCP/UDP
//! сокеты приложений) и протоколом туннеля [`nrxp`](crate::nrxp). Когда трафик
//! приходит не из TUN, а из локальных соединений, его описывают компактным
//! [`RawCastFrame`] — «что за сокет, какой протокол, куда, какое событие, данные» —
//! а [`RawCastAdapter`] переводит это в кадры NRXP и обратно.
//!
//! ## Состав блока
//!
//! | Файл        | Ответственность                                                  |
//! |-------------|------------------------------------------------------------------|
//! | [`frame`]   | [`RawCastFrame`] + enum'ы [`LocalProtocol`]/[`RawCastEvent`], wire-формат. |
//! | [`adapter`] | [`RawCastAdapter`]: трансляция RawCast ⇄ NRXP-[`Frame`](crate::nrxp).|
//!
//! ## Связь с остальным
//!
//! ```text
//!   локальный сокет ──→ RawCastFrame ──RawCastAdapter::to_nrxp──→ NRXP Frame ──→ туннель
//!   туннель ──→ NRXP Frame ──RawCastAdapter::from_nrxp──→ RawCastFrame ──→ локальный сокет
//! ```
//!
//! `socket_id` локальной стороны напрямую отображается в `stream_id` потока NRXP,
//! так что мультиплексирование «бесплатно» переносится между двумя протоколами.

mod adapter;
mod frame;

pub use adapter::RawCastAdapter;
pub use frame::{LocalProtocol, RawCastEvent, RawCastFrame};
