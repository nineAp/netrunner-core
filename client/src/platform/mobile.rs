use crate::tun::tun::Tun;
use std::io;

pub fn setup_platform_routing(_tun_device: &Tun, _remote_address: &str) -> io::Result<()> {
    eprintln!("Android routing on Kotlin side");
    Ok(())
}
