use std::io;
use tracing::error;
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
}
