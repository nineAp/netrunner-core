//! # Сетевое ядро (`net`) — оркестровка живого туннеля
//!
//! Самый верхний блок крейта: здесь синхронный разбор протокола ([`nrxp`](crate::nrxp))
//! и асинхронная сеть `tokio` соединяются в работающий мультиплексированный
//! туннель. Всё, что ниже — крипта, кадры, маскировка — лишь «кирпичи», а этот
//! блок строит из них дом: слушает соединения, держит ноги туннеля, балансирует
//! потоки и проксирует трафик к целям.
//!
//! ## Состав блока
//!
//! | Файл/подмодуль        | Ответственность                                                     |
//! |-----------------------|---------------------------------------------------------------------|
//! | [`config`]            | [`NetworkConfig`] — MTU-зависимые размеры буферов и каналов.        |
//! | `constants`           | Тайм-ауты, лимиты, порты, тюнинг анти-bufferbloat (re-export `*`).   |
//! | [`diagnostics`]       | Сбор и снапшоты метрик туннеля (RTT, очереди, события ног).         |
//! | `connection`          | Ядро: соединения, мультиплексор, движок туннеля, мосты, хендлеры.    |
//!
//! Подмодуль `connection` — самый крупный; его части:
//! - **muxer** — мультиплексор: распределяет потоки по ногам, балансирует, эвиктит;
//! - **engine** — `TunnelEngine`: reader/writer-задачи одной ноги, шифр/дешифр, heartbeat;
//! - **connection** — обёртки над TCP, SOCKS, `SessionManager`, хендлеры клиента/сервера;
//! - **handler** — обработка входящих кадров (диспетчеризация по `stream_id`/типу);
//! - **bridge** — проксирование TCP/UDP между потоком туннеля и реальной целью.
//!
//! ## Ключевая идея
//!
//! **Одно TCP-соединение (нога) = много логических потоков (`stream_id`).** Ради
//! устойчивости ног может быть несколько ([`MAX_TUNNEL_LEGS`]); поток «прилипает»
//! к ноге, а при её падении бесшовно переезжает на соседнюю (failover вместо
//! каскадного сброса). Подробности балансировки — в `connection::muxer`.
//!
//! ## Что экспортируется
//!
//! Наружу крейта выходят высокоуровневые сущности: [`NetworkConfig`],
//! хендлеры/менеджер сессий (через `connection`) и [`Muxer`] с глобальной оценкой
//! [`GLOBAL_MIN_RTT`], а также все константы.

mod auth;
mod config;
#[cfg(not(target_arch = "wasm32"))]
mod mesh;
#[cfg(not(target_arch = "wasm32"))]
mod mesh_onion;
#[cfg(all(not(target_arch = "wasm32"), feature = "mesh-quic"))]
mod mesh_quic;
// `connection` — оркестровка живых TCP-ног туннеля через `tokio::net`. Этот
// стек недоступен на `wasm32-unknown-unknown` (у tokio там нет сетевого
// драйвера), поэтому модуль целиком выключен из wasm-сборок. Лёгкий
// протокольный клиент для таких рантаймов (например, Cloudflare Workers) —
// см. [`crate::edge`], которая переиспользует `nrxp`/`crypto`/`tlseng` без
// какого-либо `tokio::net`.
#[cfg(not(target_arch = "wasm32"))]
mod connection;
mod constants;
pub mod diagnostics;

pub use auth::{
    parse_mesh_auth_token, AuthValidator, MeshAuth, MeshPeer, MeshRoute, MeshRouteSelection,
    NodeHealthReport, UsageDelta, UsageReport, UserQuota, MAX_MESH_HOPS, MESH_ONION_READY,
    MESH_ROUTE_READY,
};
pub use config::NetworkConfig;
#[cfg(not(target_arch = "wasm32"))]
pub use connection::{
    run_datagram_listener, ClientHandler, Connection, Muxer, ServerHandler, SessionManager,
    TunnelHandler, BUF_CAP, GLOBAL_MIN_RTT,
};
pub use constants::*;
#[cfg(not(target_arch = "wasm32"))]
pub use mesh::{MeshTunnel, MeshTunnelSender, NodeMesh, SharedNodeMesh};
#[cfg(all(not(target_arch = "wasm32"), feature = "mesh-quic"))]
pub(crate) use mesh_quic::client_endpoint as mesh_quic_client_endpoint;
#[cfg(all(not(target_arch = "wasm32"), feature = "mesh-quic"))]
pub use mesh_quic::server_endpoint as mesh_quic_server_endpoint;
