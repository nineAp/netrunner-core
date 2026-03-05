use bytes::{Bytes, BytesMut};
use netrunner_common::proxy::connection::muxer::{MuxMessage, Muxer};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use std::collections::HashMap;
use tracing::{debug, info, trace};

pub enum BridgeState {
    WaitingHandshake,
    WaitingConnect,
    DataTransferring {
        tx_to_muxer: tokio::sync::mpsc::Sender<MuxMessage>,
        stream_id: u32,
    },
}

pub struct NetStack {
    socket_buffers: HashMap<SocketHandle, BytesMut>,
    bridges: HashMap<SocketHandle, BridgeState>,
    muxer: Muxer,
}

//Net stack is a core. There is logic for work with my proxy

impl NetStack {
    pub fn new(muxer: Muxer) -> Self {
        Self {
            socket_buffers: HashMap::new(),
            bridges: HashMap::new(),
            muxer,
        }
    }

    pub fn run(&mut self) {}
}
