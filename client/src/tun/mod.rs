use std::os::unix::io::RawFd;
use std::{io, mem, net::IpAddr, time::Duration};

use byte_string::ByteStr;
use ipnet::IpNet;
use log::{error, info, trace, warn};
use tokio::io::AsyncReadExt;

use tun::{
    create_as_async, AbstractDevice, AsyncDevice, Configuration as TunConfiguration,
    Error as TunError, Layer,
};

use crate::tun::ip_packet::IpPacket;
use crate::tun::virt_device::TokenBuffer;

mod ip_packet;
pub mod linux_tun_device;
pub mod virt_device;

/// Tun service builder
pub struct TunBuilder {
    tun_config: TunConfiguration,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
}

/// TunConfiguration contains a HANDLE, which is a *mut c_void on Windows.
unsafe impl Send for TunBuilder {}

impl TunBuilder {
    /// Create a Tun service builder
    pub fn new() -> Self {
        Self {
            tun_config: TunConfiguration::default(),
            udp_expiry_duration: None,
            udp_capacity: None,
        }
    }

    pub fn address(&mut self, addr: IpNet) {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
    }

    pub fn destination(&mut self, addr: IpNet) {
        self.tun_config.destination(addr.addr());
    }

    pub fn name(&mut self, name: &str) {
        self.tun_config.tun_name(name);
    }

    #[cfg(unix)]
    pub fn file_descriptor(&mut self, fd: RawFd) {
        self.tun_config.raw_fd(fd);
    }

    pub fn udp_expiry_duration(&mut self, udp_expiry_duration: Duration) {
        self.udp_expiry_duration = Some(udp_expiry_duration);
    }

    pub fn udp_capacity(&mut self, udp_capacity: usize) {
        self.udp_capacity = Some(udp_capacity);
    }

    /// Build Tun server
    pub async fn build(mut self) -> io::Result<Tun> {
        self.tun_config.layer(Layer::L3).up();

        let device = match create_as_async(&self.tun_config) {
            Ok(d) => d,
            Err(TunError::Io(err)) => return Err(err),
            Err(err) => return Err(io::Error::other(err)),
        };

        Ok(Tun { device })
    }
}

/// Tun service
pub struct Tun {
    device: AsyncDevice,
}

impl Tun {
    /// Start serving
    pub async fn run(mut self) -> io::Result<()> {
        info!(
            "tun device {}",
            self.device
                .tun_name()
                .or_else(|r| Ok::<_, ()>(r.to_string()))
                .unwrap(),
        );

        let address = match self.device.address() {
            Ok(a) => a,
            Err(err) => {
                error!("[TUN] failed to get device address, error: {}", err);
                return Err(io::Error::other(err));
            }
        };

        let netmask = match self.device.netmask() {
            Ok(n) => n,
            Err(err) => {
                error!("[TUN] failed to get device netmask, error: {}", err);
                return Err(io::Error::other(err));
            }
        };

        let address_net = match IpNet::with_netmask(address, netmask) {
            Ok(n) => n,
            Err(err) => {
                error!(
                    "[TUN] invalid address {}, netmask {}, error: {}",
                    address, netmask, err
                );
                return Err(io::Error::other(err));
            }
        };

        trace!(
            "[TUN] tun device network: {} (address: {}, netmask: {})",
            address_net,
            address,
            netmask
        );

        let address_broadcast = address_net.broadcast();

        let create_packet_buffer = || {
            const PACKET_BUFFER_SIZE: usize = 65536;
            let mut packet_buffer = TokenBuffer::with_capacity(PACKET_BUFFER_SIZE);
            unsafe {
                packet_buffer.set_len(PACKET_BUFFER_SIZE);
            }
            packet_buffer
        };

        let mut packet_buffer = create_packet_buffer();

        loop {
            tokio::select! {
                // tun device
                n = self.device.read(&mut packet_buffer) => {
                    let n = n?;

                    let mut packet_buffer = mem::replace(&mut packet_buffer, create_packet_buffer());
                    unsafe {
                        packet_buffer.set_len(n);
                    }

                    trace!("[TUN] received IP packet {:?}", ByteStr::new(&packet_buffer));

                    if let Err(err) = self.handle_tun_frame(&address_broadcast, packet_buffer).await {
                        error!("[TUN] handle IP frame failed, error: {}", err);
                    }
                }
            }
        }
    }

    async fn handle_tun_frame(
        &mut self,
        device_broadcast_addr: &IpAddr,
        frame: TokenBuffer,
    ) -> smoltcp::wire::Result<()> {
        let packet = match IpPacket::new_checked(frame.as_ref())? {
            Some(packet) => packet,
            None => {
                warn!("unrecognized IP packet {:?}", ByteStr::new(&frame));
                return Ok(());
            }
        };

        trace!("[TUN] {:?}", packet);

        let src_ip_addr = packet.src_addr();
        let dst_ip_addr = packet.dst_addr();
        let src_non_unicast = src_ip_addr == *device_broadcast_addr
            || match src_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };
        let dst_non_unicast = dst_ip_addr == *device_broadcast_addr
            || match dst_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };

        if src_non_unicast || dst_non_unicast {
            trace!(
                "[TUN] IP packet {} (unicast? {}) -> {} (unicast? {}) throwing away",
                src_ip_addr,
                !src_non_unicast,
                dst_ip_addr,
                !dst_non_unicast
            );
            return Ok(());
        }
        Ok(())
    }
}
