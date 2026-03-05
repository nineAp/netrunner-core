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

    pub fn setup_linux_routes(&self) -> io::Result<()> {
        use std::process::Command;

        // Направляем трафик через IP, который слушает твой smoltcp Engine
        // Предположим, smoltcp настроен на 10.0.0.2
        let status = Command::new("ip")
            .args(&["route", "add", "default", "via", "10.0.0.2", "dev", "tun0"])
            .status()?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to setup routes",
            ));
        }
        Ok(())
    }

    pub fn clear_default_route(&self) -> io::Result<()> {
        use std::process::Command;

        info!("Removing existing default route...");

        // Удаляем текущий маршрут по умолчанию
        let status = Command::new("sudo")
            .args(&["ip", "route", "del", "default"])
            .status()?;

        if !status.success() {
            warn!("Could not delete default route (maybe it doesn't exist?)");
        }
        Ok(())
    }
}
