use crate::connections::dns::DnsHandler; // проверь путь
use crate::connections::ip_store::FakeIpStore;
use smoltcp::socket::udp;

pub struct UdpConnection;

impl UdpConnection {
    pub fn process_incoming(
        socket: &mut udp::Socket,
        store: &mut FakeIpStore,
        dns_handler: &DnsHandler,
    ) {
        while socket.can_recv() {
            let (data, metadata) = match socket.recv() {
                Ok(res) => res,
                Err(_) => break,
            };

            let endpoint = metadata.endpoint;

            if let Some(response) = dns_handler.handle_query(&data, store) {
                netrunner_logger::debug!(to = %endpoint, "Sending DNS response (filtered)");
                let _ = socket.send_slice(&response, metadata);
            }
        }
    }
}
