//! Реестр виртуальных соединений userspace-стека smoltcp.
//!
//! [`SessionTracker`] — это «NAT-таблица» клиента: он связывает хендлы сокетов
//! smoltcp ([`SocketHandle`]) с логическими id, держит активные TCP/UDP-соединения
//! и каналы доставки входящих данных, следит за активностью и убирает «призраков».
//!
//! Ключевые обязанности:
//! - **Реестр** TCP/UDP-соединений и двусторонний маппинг `handle ⇄ id`.
//! - **Pending TCP** — полуоткрытые соединения с удерживаемым семафор-пермитом
//!   (ограничение числа одновременных установок).
//! - **Idle-выметание** ([`enforce_idle_timeouts`](SessionTracker::enforce_idle_timeouts))
//!   и **LRU-эвикт** ([`evict_oldest_socket`](SessionTracker::evict_oldest_socket))
//!   при достижении лимита сокетов — с защитой системных/слушающих сокетов.
//! - **Отложенное удаление**: `queue_removal` + `cleanup` (нельзя трогать
//!   `SocketSet` во время итерации по нему).

use std::{
    collections::HashMap,
    time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use dashmap::DashMap;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::Socket,
    wire::IpAddress,
};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use crate::net::connection::{TcpConnection, UdpConnection};

/// Состояние всех виртуальных соединений и их маппингов на хендлы smoltcp.
pub struct SessionTracker {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp: HashMap<SocketHandle, TcpConnection>,
    active_udp: HashMap<SocketHandle, UdpConnection>,
    pub inbound_tx: Arc<DashMap<u64, (mpsc::Sender<Bytes>, Arc<std::sync::atomic::AtomicBool>)>>,
    handle_to_id: HashMap<SocketHandle, u64>,

    id_to_handle: HashMap<u64, SocketHandle>,
    pending_tcp: HashMap<SocketHandle, (StdInstant, OwnedSemaphorePermit)>,
    to_remove: Vec<SocketHandle>,
    next_socket_id: u64,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp: HashMap::new(),
            active_udp: HashMap::new(),
            inbound_tx: Arc::new(DashMap::new()),
            handle_to_id: HashMap::new(),
            id_to_handle: HashMap::new(),
            pending_tcp: HashMap::new(),
            to_remove: Vec::new(),
            next_socket_id: 1,
        }
    }

    pub fn next_id(&mut self) -> u64 {
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.wrapping_add(1);
        id
    }

    pub fn add_pending_tcp(&mut self, handle: SocketHandle, permit: OwnedSemaphorePermit) {
        self.pending_tcp.insert(handle, (StdInstant::now(), permit));
        self.last_activity.insert(handle, StdInstant::now());
    }

    pub fn pop_pending_permit(&mut self, handle: SocketHandle) -> Option<OwnedSemaphorePermit> {
        self.pending_tcp.remove(&handle).map(|(_, permit)| permit)
    }

    pub fn register_tcp(
        &mut self,
        handle: SocketHandle,
        id: u64,
        conn: TcpConnection,
        tx: mpsc::Sender<Bytes>,
        is_saturated: Arc<std::sync::atomic::AtomicBool>,
    ) {
        self.handle_to_id.insert(handle, id);
        self.id_to_handle.insert(id, handle);
        self.active_tcp.insert(handle, conn);
        self.inbound_tx.insert(id, (tx, is_saturated));
        self.last_activity.insert(handle, StdInstant::now());
    }

    pub fn register_udp(
        &mut self,
        handle: SocketHandle,
        id: u64,
        conn: UdpConnection,
        tx: mpsc::Sender<Bytes>,
        is_saturated: Arc<std::sync::atomic::AtomicBool>,
    ) {
        self.handle_to_id.insert(handle, id);
        self.id_to_handle.insert(id, handle);
        self.active_udp.insert(handle, conn);
        self.inbound_tx.insert(id, (tx, is_saturated));
        self.last_activity.insert(handle, StdInstant::now());
    }

    pub fn has_connection_from(
        &self,
        src_addr: IpAddress,
        src_port: u16,
        socket_set: &SocketSet,
    ) -> bool {
        socket_set.iter().any(|(_, s)| {
            if let Socket::Tcp(tcp) = s {
                if let Some(remote) = tcp.remote_endpoint() {
                    return remote.addr == src_addr && remote.port == src_port;
                }
            }
            false
        })
    }

    pub fn is_client_known(&self, port: u16) -> bool {
        self.active_udp.values().any(|conn| conn.has_client(port))
    }

    pub fn should_init_tcp(&mut self, handle: SocketHandle) -> bool {
        self.pending_tcp.contains_key(&handle) && !self.active_tcp.contains_key(&handle)
    }

    pub fn get_tcp_mut(&mut self, handle: SocketHandle) -> Option<&mut TcpConnection> {
        self.active_tcp.get_mut(&handle)
    }

    pub fn get_udp_mut(&mut self, handle: SocketHandle) -> Option<&mut UdpConnection> {
        self.active_udp.get_mut(&handle)
    }

    pub fn update_activity(&mut self, handle: SocketHandle) {
        self.last_activity.insert(handle, StdInstant::now());
    }

    pub fn queue_removal(&mut self, handle: SocketHandle) {
        if !self.to_remove.contains(&handle) {
            self.to_remove.push(handle);
        }
    }

    pub fn enforce_idle_timeouts(&mut self, timeout: Duration) {
        let now = StdInstant::now();
        let mut ghosts = Vec::new();

        for (&handle, &last_seen) in &self.last_activity {
            if now.duration_since(last_seen) > timeout {
                ghosts.push(handle);
            }
        }

        for handle in ghosts {
            netrunner_logger::debug!("🧹 Sweeping idle ghost socket: {:?}", handle);
            self.queue_removal(handle);
        }
    }

    /// LRU-эвикт для освобождения слота при достижении лимита сокетов.
    ///
    /// Сначала ищет уже «мёртвый» TCP-сокет (Closed/TimeWait/CloseWait/FinWait);
    /// если таких нет — закрывает самый давно неактивный пользовательский сокет,
    /// **не трогая** системные/слушающие. Возвращает `true`, если кого-то закрыл.
    pub fn evict_oldest_socket(&mut self, socket_set: &mut SocketSet) -> bool {
        let mut victim = None;

        for (handle, socket) in socket_set.iter() {
            if let smoltcp::socket::Socket::Tcp(tcp_socket) = socket {
                let state = tcp_socket.state();
                if matches!(
                    state,
                    smoltcp::socket::tcp::State::Closed
                        | smoltcp::socket::tcp::State::TimeWait
                        | smoltcp::socket::tcp::State::CloseWait
                        | smoltcp::socket::tcp::State::FinWait1
                        | smoltcp::socket::tcp::State::FinWait2
                ) {
                    victim = Some(handle);
                    break;
                }
            }
        }

        if victim.is_none() {
            // 🔥 ИСПРАВЛЕНИЕ: Защищаем системные (слушающие) сокеты от удаления
            victim = self
                .last_activity
                .iter()
                .filter(|(h, _)| {
                    self.active_tcp.contains_key(h)
                        || self.active_udp.contains_key(h)
                        || self.pending_tcp.contains_key(h)
                })
                .min_by_key(|&(_, &time)| time)
                .map(|(&handle, _)| handle);
        }

        if let Some(handle) = victim {
            netrunner_logger::info!(
                "🔪 LRU Eviction: Force closing socket {:?} to free up a slot",
                handle
            );
            self.queue_removal(handle);
            self.cleanup(socket_set);
            true
        } else {
            false
        }
    }

    /// Фактически удаляет все сокеты из очереди `to_remove` из `SocketSet` и всех
    /// внутренних таблиц. Вызывается вне итерации по сокетам (см. отложенность).
    pub fn cleanup(&mut self, socket_set: &mut SocketSet) {
        for handle in self.to_remove.drain(..) {
            socket_set.remove(handle);
            self.active_tcp.remove(&handle);
            self.active_udp.remove(&handle);
            self.pending_tcp.remove(&handle);
            self.last_activity.remove(&handle);

            if let Some(id) = self.handle_to_id.remove(&handle) {
                self.inbound_tx.remove(&id);
                self.id_to_handle.remove(&id);
            }
        }
    }

    pub fn get_app_buffer_info(&self, handle: SocketHandle) -> usize {
        self.active_tcp
            .get(&handle)
            .map(|conn| conn.app_pending_out_size())
            .unwrap_or(0)
    }
}
