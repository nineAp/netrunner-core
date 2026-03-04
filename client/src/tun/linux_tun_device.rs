use tun::AsyncDevice;

//tun device
pub fn create_linux_tun() -> AsyncDevice {
    let mut config = tun::Configuration::default();
    config
        .tun_name("netr0")
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    let dev = tun::create_as_async(&config).expect("Нужны права root или CAP_NET_ADMIN!");
    dev
}
