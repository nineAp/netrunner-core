#[cfg(feature = "desktop")]
pub mod desktop;
#[cfg(feature = "mobile")]
pub mod mobile;

pub fn setup_platform_routing(tun: &crate::tun::tun::Tun, addr: &str) -> std::io::Result<()> {
    #[cfg(feature = "desktop")]
    {
        desktop::setup_platform_routing(tun, addr)
    }
    #[cfg(not(feature = "desktop"))]
    {
        mobile::setup_platform_routing(tun, addr)
    }
}
