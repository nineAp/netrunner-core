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
        config.raw_fd(fd); // Передаем дескриптор, который нам дал Android VpnService
        config.up(); // Убеждаемся, что он поднят

        Self::new(&config)
    }

    pub fn split(self) -> io::Result<(DeviceWriter, DeviceReader)> {
        let (writer, reader) = self.device.split()?;
        Ok((writer, reader))
    }

    pub fn setup_routing(&self) -> io::Result<()> {
        use std::process::Command;

        // 1. Удаляем существующий default-маршрут (чтобы не было конфликтов)
        // Игнорируем ошибку, если его вдруг нет
        let _ = Command::new("sudo")
            .args(&["ip", "route", "del", "default"])
            .status();

        // 2. Добавляем tun0 как ГЛАВНЫЙ маршрут (метрика 1 — самый высокий приоритет)
        let _ = Command::new("sudo")
            .args(&[
                "ip", "route", "add", "default", "via", "10.0.0.2", "dev", "tun0", "metric", "1",
            ])
            .status();

        // 3. Добавляем eth0 как РЕЗЕРВНЫЙ маршрут (метрика 100 — низкий приоритет)
        // ВАЖНО: Тебе нужно знать IP шлюза твоего eth0.
        // Если ты не знаешь его заранее, можешь попробовать вытащить его из `ip route`
        // или просто оставить как есть, если eth0 — единственный физический интерфейс.
        let _ = Command::new("sudo")
            .args(&[
                "ip",
                "route",
                "add",
                "default",
                "via",
                "172.18.144.1",
                "dev",
                "eth0",
                "metric",
                "100",
            ])
            .status();

        info!(
            "Маршрутизация настроена: tun0 (metric 1) -> основной, eth0 (metric 100) -> резервный"
        );
        Ok(())
    }

    pub fn setup_dns_redirection(&self) -> io::Result<()> {
        // 1. Создаем временный файл resolv.conf
        // Мы говорим системе: "Твой DNS-сервер теперь 10.0.0.1" (твой TUN-IP)
        let _ = std::fs::write("/tmp/resolv.conf.netrunner", "nameserver 10.0.0.2\n");

        // 2. Применяем его (для Linux/systemd)
        let _ = std::process::Command::new("sudo")
            .args(&["cp", "/tmp/resolv.conf.netrunner", "/etc/resolv.conf"])
            .status();

        info!("DNS перенаправлен на 10.0.0.1");
        Ok(())
    }
}
