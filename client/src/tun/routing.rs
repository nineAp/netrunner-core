use crate::tun::tun::Tun;
use std::io;
use tracing::{error, info, warn};

#[cfg(any(feature = "linux", feature = "windows"))]
use std::process::Command;

pub fn setup_platform_routing(remote_address: &str) -> io::Result<()> {
    let proxy_ip = remote_address.split(':').next().unwrap_or(remote_address);

    #[cfg(feature = "linux")]
    {
        // 1. Бэкап и получение текущего маршрута по умолчанию
        let _ = Command::new("sudo")
            .args(&["cp", "/etc/resolv.conf", "/etc/resolv.conf.bak"])
            .status();

        let output = Command::new("ip")
            .args(&["route", "show", "default"])
            .output()?;
        let default_route = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if default_route.is_empty() {
            error!("Default route не найден!");
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No default route found",
            ));
        }
        std::fs::write("/tmp/netrunner_default_route", &default_route)?;

        // 2. Парсинг параметров из маршрута по умолчанию
        let parts: Vec<&str> = default_route.split_whitespace().collect();
        let dev = parts
            .iter()
            .position(|&x| x == "dev")
            .and_then(|i| parts.get(i + 1))
            .copied()
            .unwrap_or("eth0");
        let via = parts
            .iter()
            .position(|&x| x == "via")
            .and_then(|i| parts.get(i + 1))
            .copied();

        // 3. Добавляем маршрут до прокси-сервера
        let mut proxy_route = vec!["ip", "route", "add", proxy_ip, "dev", dev];
        if let Some(gw) = via {
            proxy_route.extend_from_slice(&["via", gw]);
        }
        let _ = Command::new("sudo").args(proxy_route).status();

        // 4. Заменяем default маршрут на наш TUN
        let _ = Command::new("sudo")
            .args(&["ip", "route", "del", "default"])
            .status();
        let status = Command::new("sudo")
            .args(&[
                "ip", "route", "add", "default", "via", "10.0.0.2", "dev", "netr0", "metric", "1",
            ])
            .status()?;

        if status.success() {
            info!("Linux TUN default set.");
        }

        // 5. DNS
        std::fs::write("/tmp/resolv.conf.netrunner", "nameserver 10.0.0.2\n")?;
        Command::new("sudo")
            .args(&["cp", "/tmp/resolv.conf.netrunner", "/etc/resolv.conf"])
            .status()?;
    }

    #[cfg(feature = "windows")]
    {
        // Логика Windows
        Command::new("route")
            .args(&[
                "add",
                proxy_ip,
                "mask",
                "255.255.255.255",
                "0.0.0.0",
                "metric",
                "1",
            ])
            .status()?;
        Command::new("netsh")
            .args(&[
                "interface",
                "ipv4",
                "set",
                "address",
                "name=netr0",
                "static",
                "10.0.0.1",
                "255.255.255.0",
                "10.0.0.2",
            ])
            .status()?;

        // DNS
        Command::new("netsh")
            .args(&[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                "name=netr0",
                "static",
                "10.0.0.2",
                "primary",
            ])
            .status()?;
    }

    #[cfg(feature = "mobile")]
    {
        eprintln!("Android/Mobile routing on native side");
    }

    Ok(())
}

pub fn reset_platform_routing() -> io::Result<()> {
    #[cfg(feature = "linux")]
    {
        // 1. Возвращаем дефолтный маршрут из файла
        if let Ok(saved_route) = std::fs::read_to_string("/tmp/netrunner_default_route") {
            let _ = Command::new("sudo")
                .args(&["ip", "route", "del", "default"])
                .status();
            let args: Vec<&str> = saved_route.split_whitespace().collect();
            let _ = Command::new("sudo")
                .args(&["ip", "route", "add"])
                .args(args)
                .status();
        }

        // 2. Удаляем наш специфичный маршрут к прокси
        // (Опционально, если он был добавлен)

        // 3. Восстанавливаем DNS (если есть бэкап)
        let _ = Command::new("sudo")
            .args(&["cp", "/etc/resolv.conf.bak", "/etc/resolv.conf"])
            .status();

        info!("Linux routing restored.");
    }

    #[cfg(feature = "windows")]
    {
        // В Windows можно просто удалить маршрут и интерфейс
        let _ = Command::new("route").args(&["delete", "0.0.0.0"]).status();
        // При переподключении сети (или ipconfig /renew) Windows сам подтянет настройки
        info!("Windows routing reset requested.");
    }

    Ok(())
}
