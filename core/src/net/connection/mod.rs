//! Подмодуль `connection` — собственно машинерия туннеля.
//!
//! Самый плотный по логике участок крейта. Делится по ролям:
//!
//! - [`muxer`] — **мультиплексор**: реестр потоков и ног, балансировка
//!   (`select_leg`), эвикт упавших ног, failover потоков, оценка RTT
//!   ([`GLOBAL_MIN_RTT`]).
//! - [`engine`] — **движок ноги**: пара задач reader/writer на одно TCP-соединение,
//!   шифрование/дешифрование кадров, heartbeat, переподключение.
//! - [`connection`] — обёртки над TCP/SOCKS, [`SessionManager`] и хендлеры:
//!   [`ClientHandler`] (SOCKS→потоки), [`ServerHandler`] (приём туннеля + stealth-fallback),
//!   [`TunnelHandler`].
//! - [`handler`] — диспетчеризация входящих кадров по `stream_id`/типу к нужному мосту.
//! - [`bridge`] — проксирование данных между потоком туннеля и реальным TCP/UDP-сокетом цели.

mod bridge;
mod buftune;
#[allow(clippy::module_inception)]
mod connection;
mod dgram_engine;
mod engine;
mod handler;
mod muxer;

pub use buftune::BUF_CAP;
pub use connection::{ClientHandler, Connection, ServerHandler, SessionManager, TunnelHandler};
pub(crate) use connection::{MeshPeerSession, mesh_process_uptime_ms};
pub use dgram_engine::run_datagram_listener;
pub use muxer::{GLOBAL_MIN_RTT, Muxer};
