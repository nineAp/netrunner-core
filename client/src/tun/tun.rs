//! Обёртка над асинхронным TUN-устройством.
//!
//! [`Tun`] инкапсулирует создание/открытие TUN тремя путями: по конфигурации
//! ([`new`](Tun::new)), через билдер-замыкание ([`create`](Tun::create)) или из
//! готового файлового дескриптора ([`from_fd`](Tun::from_fd) — так его передаёт
//! Android `VpnService`). [`split`](Tun::split) разводит устройство на отдельные
//! reader/writer, чтобы читать и писать пакеты из разных задач.

use netrunner_logger::error;
use std::io;
use tun::{AsyncDevice, Configuration, DeviceReader, DeviceWriter, create_as_async};

/// Асинхронное TUN-устройство.
pub struct Tun {
    device: AsyncDevice,
}

impl Tun {
    /// Создаёт устройство из готовой конфигурации.
    pub fn new(config: &Configuration) -> io::Result<Self> {
        match create_as_async(config) {
            Ok(device) => Ok(Self { device }),
            Err(e) => {
                error!("Failed to create TUN device: {}", e);
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    /// Создаёт устройство, настраивая конфигурацию через замыкание-билдер.
    pub fn create<F>(f: F) -> io::Result<Self>
    where
        F: FnOnce(&mut Configuration),
    {
        let mut config = Configuration::default();
        f(&mut config);
        Self::new(&config)
    }

    /// Открывает устройство из уже существующего fd (передаётся Android `VpnService`).
    pub fn from_fd(fd: i32) -> io::Result<Self> {
        let mut config = Configuration::default();
        config.raw_fd(fd);
        config.up();

        Self::new(&config)
    }

    /// Разводит устройство на пишущую и читающую половины (для разных задач).
    pub fn split(self) -> io::Result<(DeviceWriter, DeviceReader)> {
        let (writer, reader) = self.device.split()?;
        Ok((writer, reader))
    }
}
