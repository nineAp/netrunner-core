use crate::connections::dns::handle_dns_query;
use crate::connections::ip_store::FakeIpStore;
use smoltcp::socket::udp;
use tracing::{debug, trace};

pub struct UdpConnection;

impl UdpConnection {
    pub fn process_incoming(socket: &mut udp::Socket, store: &mut FakeIpStore) {
        while socket.can_recv() {
            let (data, metadata) = match socket.recv() {
                Ok(res) => res,
                Err(_) => break,
            };

            let endpoint = metadata.endpoint;

            if let Some(response) = handle_dns_query(&data, store) {
                debug!(to = %endpoint, "Sending DNS response");
                let _ = socket.send_slice(&response, metadata);
            }
        }
    }
}
