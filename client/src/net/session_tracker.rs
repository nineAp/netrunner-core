use std::{
    collections::HashMap,
    time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::Socket,
    wire::IpAddress,
};
use tokio::sync::mpsc;

use crate::net::connection::{TcpConnection, UdpConnection};

pub struct SessionTracker {
    last_activity: HashMap<SocketHandle, StdInstant>,
    active_tcp: HashMap<SocketHandle, TcpConnection>,
    active_udp: HashMap<SocketHandle, UdpConnection>,
    inbound_tx: HashMap<u64, mpsc::Sender<Bytes>>,
    handle_to_id: HashMap<SocketHandle, u64>,

    id_to_handle: HashMap<u64, SocketHandle>,
    pending_tcp: HashMap<SocketHandle, StdInstant>,
    to_remove: Vec<SocketHandle>,
    next_socket_id: u64,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            last_activity: HashMap::new(),
            active_tcp: HashMap::new(),
            active_udp: HashMap::new(),
            inbound_tx: HashMap::new(),
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

    pub fn add_pending_tcp(&mut self, handle: SocketHandle) {
        self.pending_tcp.insert(handle, StdInstant::now());
    }

    pub fn register_tcp(
        &mut self,
        handle: SocketHandle,
        id: u64,
        conn: TcpConnection,
        tx: mpsc::Sender<Bytes>,
    ) {
        self.pending_tcp.remove(&handle);
        self.handle_to_id.insert(handle, id);
        self.id_to_handle.insert(id, handle);
        self.active_tcp.insert(handle, conn);
        self.inbound_tx.insert(id, tx);
        self.last_activity.insert(handle, StdInstant::now());
    }

    pub fn register_udp(
        &mut self,
        handle: SocketHandle,
        id: u64,
        conn: UdpConnection,
        tx: mpsc::Sender<Bytes>,
    ) {
        self.handle_to_id.insert(handle, id);
        self.id_to_handle.insert(id, handle);
        self.active_udp.insert(handle, conn);
        self.inbound_tx.insert(id, tx);
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

    pub fn check_pending_timeout(&self, handle: SocketHandle, timeout: Duration) -> bool {
        self.pending_tcp
            .get(&handle)
            .map_or(false, |t| t.elapsed() > timeout)
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

    pub fn get_inbound_tx(&self, id: u64) -> Option<&mpsc::Sender<Bytes>> {
        self.inbound_tx.get(&id)
    }

    pub fn close_tunnel_session(&mut self, id: u64) {
        self.inbound_tx.remove(&id);

        if let Some(handle) = self.id_to_handle.remove(&id) {
            self.queue_removal(handle);
        }
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
}
