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

/// Windows-only: закрывает зависший Wintun-адаптер с именем `name`, если он
/// остался от предыдущего процесса, убитого без штатного завершения (Drop у
/// `tun`-крейта, закрывающий сессию, тогда не отрабатывает). Без этого
/// следующий запуск переиспользует тот же адаптер (`Adapter::open` внутри
/// `tun` крейта успевает раньше, чем понадобилось бы `create`) и падает на
/// `start_session` с `WintunStartSession failed ... ERROR_ALREADY_INITIALIZED
/// (0x4DF)`, потому что на нём уже висит незакрытая сессия. Используем
/// отдельный крейт `wintun` (не `wintun-bindings`, на котором построен сам
/// `tun`) — обе биндинги грузят один и тот же `wintun.dll` и работают с одним
/// и тем же состоянием драйвера, так что закрытие через одну видно другой.
/// Best-effort: если тут что-то пошло не так (адаптера нет, DLL не нашлась и
/// т.п.) — просто логируем и идём дальше, `create_as_async` ниже создаст
/// адаптер с нуля сам, если найдёт его свободным.
#[cfg(target_os = "windows")]
pub fn cleanup_stale_adapter(name: &str) {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let wintun = unsafe { wintun::load()? };
        if let Ok(adapter) = wintun::Adapter::open(&wintun, name) {
            match std::sync::Arc::try_unwrap(adapter) {
                Ok(adapter) => adapter.delete()?,
                // Кто-то ещё держит Arc — маловероятно (мы только что его
                // открыли в этой же функции), но на всякий случай не рушим
                // best-effort очистку паникой на try_unwrap.
                Err(_) => return Err("adapter handle still referenced".into()),
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        error!(
            "Не удалось очистить старый Wintun-адаптер {}: {} (не критично, пробуем создать заново)",
            name, e
        );
    }
}

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
                Err(io::Error::other(e))
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
