use std::sync::{Arc, atomic::AtomicBool};

use smoltcp::{iface::{Config, Interface as InterfaceInstance, SocketSet}, phy::DeviceCapabilities, socket::tcp::{Socket, SocketBuffer}, time::Instant, wire::IpListenEndpoint};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::tun::virt_device::{TokenBuffer, VirtTunDevice};
pub struct Interface {
    instance: InterfaceInstance,
    socket_set: SocketSet<'static>,
    input: UnboundedSender<TokenBuffer>,
    output: UnboundedReceiver<TokenBuffer>,
    available: Arc<AtomicBool>
}

lazy_static::lazy_static! {
    static ref START_TIME: std::time::Instant = std::time::Instant::now();
}


fn current_smoltcp_time() -> Instant {
    let nanos = START_TIME.elapsed().as_micros() as i64;
    smoltcp::time::Instant::from_micros(nanos)
}


impl Interface {
    pub fn new(caps: DeviceCapabilities, config: Config) -> Self {
        //create virtual tun device (async device)
        let (virt_device, output, input, available) = VirtTunDevice::new(caps);
        let device = Box::leak(Box::new(virt_device));

        let now: Instant = current_smoltcp_time();
        //smoltcp interface instance create
        let mut instance = InterfaceInstance::new(config, device, now);
        //instance settings
        instance.set_any_ip(true);

        instance.update_ip_addrs(|addrs| {
            addrs
                .push(smoltcp::wire::IpCidr::new(
                    smoltcp::wire::IpAddress::v4(10, 0, 0, 2),
                    24,
                ))
                .unwrap();
        });
        instance
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 2))
            .unwrap();


        let socket_set = SocketSet::new(vec![]);

        let endpoint = IpListenEndpoint {
            addr: None,
            port: 443,
        };
        let rx_data = Box::leak(vec![0u8; 4096].into_boxed_slice());
        let tx_data = Box::leak(vec![0u8; 4096].into_boxed_slice());

        let mut socket = Socket::new(SocketBuffer::new(rx_data), SocketBuffer::new(tx_data));

        socket.listen(endpoint).unwrap();

        Self {
            instance,
            socket_set,
            input,
            output,
            available
        }
    }

    pub fn run(&mut self) {

    }

    pub fn process_tun_input(&mut self, data: &[u8]) {
        let mut token = TokenBuffer::with_capacity(data.len());
        token.extend_from_slice(data);

        if self.input.send(token).is_ok() {
            self.available
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    pub async fn next_outbound_packet(&mut self) -> Option<TokenBuffer> {
        self.output.recv().await
    }

    pub fn poll_delay(&mut self) -> tokio::time::Sleep {
        let timestamp = current_smoltcp_time();
        let ms = self
            .instance
            .poll_delay(timestamp, &self.socket_set)
            .map(|d| d.total_millis())
            .unwrap_or(10); // Порог отзывчивости стека

        tokio::time::sleep(std::time::Duration::from_millis(ms))
    }
}

