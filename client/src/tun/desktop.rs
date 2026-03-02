use tun::Device;

pub fn create_linux_tun() -> Device {
    let mut config = tun::Configuration::default();
    config
        .tun_name("netr0")
        .address((10, 0, 0, 1)) // IP нашего "моста"
        .netmask((255, 255, 255, 0)) // Маска подсети
        .up(); // Сразу включаем интерфейс

    // Это создаст в системе интерфейс tun0
    let dev = tun::create(&config).expect("Нужны права root или CAP_NET_ADMIN!");
    dev
}
