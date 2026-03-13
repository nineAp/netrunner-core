use crate::tun::tun::Tun; // Убедись, что путь к Tun верный
use std::io;

pub fn setup_platform_routing(tun_device: &Tun, remote_address: &str) -> io::Result<()> {
    let proxy_ip = remote_address.split(':').next().unwrap_or(remote_address);
    tun_device.setup_routing(proxy_ip)?;
    tun_device.setup_dns_redirection()?;
    Ok(())
}
