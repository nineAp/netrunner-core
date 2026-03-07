use crate::connections::dns::handle_dns_query;
use crate::connections::ip_store::FakeIpStore;
use smoltcp::socket::udp;

pub struct UdpConnection;

impl UdpConnection {
    pub fn process_incoming(socket: &mut udp::Socket, store: &mut FakeIpStore) {
        // Мы используем peek или recv, чтобы понять, куда идти дальше
        while socket.can_recv() {
            let (data, metadata) = match socket.recv() {
                Ok(res) => res,
                Err(_) => break,
            };

            // Диспетчер: определяем тип трафика по порту
            match metadata.endpoint.port {
                53 => {
                    // Это DNS
                    if let Some(response) = handle_dns_query(&data, store) {
                        let _ = socket.send_slice(&response, metadata);
                    }
                }
                // Тут в будущем можно добавить обработку других протоколов
                // 443 => process_quic(...),
                _ => {
                    // Можно логировать неизвестный трафик или просто дропать
                    // trace!("Received UDP on unknown port: {}", endpoint.port);
                }
            }
        }
    }
}
