//! Сетевой слой клиента: userspace TCP/IP-стек на smoltcp + мост в туннель.
//!
//! Здесь живёт «локальная» половина клиента — то, что превращает перехваченные
//! IP-пакеты приложений в логические соединения и кормит ими ядро
//! ([`netrunner_core`]). Поток данных:
//!
//! ```text
//!   TUN ─пакеты→ engine ─push_rx→ smoltcp ─→ connection_manager
//!        ─перехват SYN/датаграмм→ TcpConnection/UdpConnection ─RawCastFrame→ туннель
//! ```
//!
//! Состав:
//! - [`engine`] — главный poll-цикл стека и сборка ([`EngineBuilder`](engine::EngineBuilder)).
//! - [`connection_manager`] — перехват L3-пакетов, реестр сокетов, диспетчеризация.
//! - [`connection`] — виртуальные TCP/UDP-соединения и ICMP-ответчик.
//! - [`session_tracker`] — NAT-таблица сокетов, idle/LRU-уборка.
//! - [`socket_factory`] — создание smoltcp-сокетов под профиль трафика.
//! - [`dns`] — локальный DNS с фейковыми IP и блок-листом.

mod connection;
pub mod connection_manager;
mod dns;
pub mod engine;
mod session_tracker;
mod socket_factory;
