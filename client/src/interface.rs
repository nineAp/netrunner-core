use std::sync::{Arc, atomic::AtomicBool};

use smoltcp::{
    iface::{Config, Interface as InterfaceInstance, SocketSet},
    phy::DeviceCapabilities,
    socket::tcp::{Socket, SocketBuffer},
    time::Instant,
    wire::IpListenEndpoint,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::error;

use crate::tun::{
    Tun, TunBuilder,
    virt_device::{TokenBuffer, VirtTunDevice},
};

pub struct Interface {
    instance: InterfaceInstance,            //smoltcp interface instance
    tun: Tun,                               //real device that gets data
    socket_set: SocketSet<'static>,         //opened sockets
    input: UnboundedSender<TokenBuffer>,    //virtual device input
    output: UnboundedReceiver<TokenBuffer>, //virtual device output
    available: Arc<AtomicBool>,             //virtual device buffer available
}

lazy_static::lazy_static! {
    static ref START_TIME: std::time::Instant = std::time::Instant::now();
}

fn current_smoltcp_time() -> Instant {
    let nanos = START_TIME.elapsed().as_micros() as i64;
    smoltcp::time::Instant::from_micros(nanos)
}
//Interface is a wrapper for smoltcp interface. It works with virtual device for async
impl Interface {
    pub async fn new(caps: DeviceCapabilities, config: Config) -> Self {
        //creating real tun device
        let tun_result = TunBuilder::new().build().await;

        let Ok(tun) = tun_result else {
            error!("Tun creation error");
            panic!();
        };

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
            tun,
            socket_set,
            input,
            output,
            available,
        }
    }

    pub fn poll(&mut self) {}
}
