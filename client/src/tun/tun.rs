use std::io;
use tracing::{error, info, warn};
use tun::{AsyncDevice, Configuration, DeviceReader, DeviceWriter, create_as_async};

pub struct Tun {
    device: AsyncDevice,
}

impl Tun {
    pub fn build() -> Configuration {
        Configuration::default()
    }

    pub fn new(config: &Configuration) -> io::Result<Self> {
        match create_as_async(config) {
            Ok(device) => Ok(Self { device }),
            Err(e) => {
                error!("Failed to create TUN device: {}", e);
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    pub fn create<F>(f: F) -> io::Result<Self>
    where
        F: FnOnce(&mut Configuration),
    {
        let mut config = Configuration::default();
        f(&mut config);
        Self::new(&config)
    }

    pub fn from_android_fd(fd: i32) -> io::Result<Self> {
        let mut config = Configuration::default();
        config.raw_fd(fd);
        config.up();

        Self::new(&config)
    }

    pub fn split(self) -> io::Result<(DeviceWriter, DeviceReader)> {
        let (writer, reader) = self.device.split()?;
        Ok((writer, reader))
    }

    fn get_route_part<'a>(parts: &'a [&'a str], key: &str) -> Option<&'a str> {
        parts
            .iter()
            .position(|&x| x == key)
            .and_then(|i| parts.get(i + 1))
            .copied()
    }

    #[cfg(feature = "desktop")]
    pub fn setup_routing(&self, remote_address: &str) -> io::Result<()> {
        use std::process::Command;

        info!(
            "Начинаем настройку маршрутизации для прокси: {}",
            remote_address
        );

        let output = Command::new("ip")
            .args(&["route", "get", remote_address])
            .output()?;
        let route_info = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = route_info.split_whitespace().collect();

        let dev = Self::get_route_part(&parts, "dev").unwrap_or("eth0");
        let via = Self::get_route_part(&parts, "via");

        info!("Обнаружен физический маршрут: dev={}, via={:?}", dev, via);

        info!("Добавляем статический маршрут для прокси...");
        let mut proxy_route = vec!["ip", "route", "add", remote_address, "dev", dev];
        if let Some(gw) = via {
            proxy_route.extend_from_slice(&["via", gw]);
        }
        let status = Command::new("sudo").args(proxy_route).status()?;
        if !status.success() {
            warn!("Маршрут к прокси уже существует или возникла ошибка (это нормально).");
        }

        info!("Переключаем default маршрут на tun0...");
        let _ = Command::new("sudo")
            .args(&["ip", "route", "del", "default"])
            .status();

        let status = Command::new("sudo")
            .args(&[
                "ip", "route", "add", "default", "via", "10.0.0.2", "dev", "tun0", "metric", "1",
            ])
            .status()?;
        if status.success() {
            info!("TUN успешно установлен как основной default.");
        } else {
            error!("Не удалось установить tun0 как default!");
        }

        if let Some(gw) = via {
            info!("Добавляем резервный маршрут через {} с метрикой 100", dev);
            let _ = Command::new("sudo")
                .args(&[
                    "ip", "route", "add", "default", "via", gw, "dev", dev, "metric", "100",
                ])
                .status();
        }

        info!("Маршрутизация полностью настроена.");
        Ok(())
    }
    #[cfg(feature = "desktop")]
    pub fn setup_dns_redirection(&self) -> io::Result<()> {
        let _ = std::fs::write("/tmp/resolv.conf.netrunner", "nameserver 10.0.0.2\n");

        let _ = std::process::Command::new("sudo")
            .args(&["cp", "/tmp/resolv.conf.netrunner", "/etc/resolv.conf"])
            .status();

        info!("DNS перенаправлен на 10.0.0.1");
        Ok(())
    }
}
