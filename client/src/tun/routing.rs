use netrunner_logger::{error, info, warn};
use std::io;
use std::process::Command;

fn run_cmd_ext(full_cmd: &str, ignore_errors: bool) -> io::Result<()> {
    let parts = shlex::split(full_cmd)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid syntax"))?;

    if parts.is_empty() {
        return Ok(());
    }

    let status = Command::new(&parts[0]).args(&parts[1..]).status()?;

    if !status.success() && !ignore_errors {
        let err = format!("Command failed: {} with status {}", full_cmd, status);
        error!("{}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn get_active_interface_index() -> Option<u32> {
    // Получаем список интерфейсов через netsh
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains("Connected") && !line.contains("netr0") {
            if let Some(idx_str) = line.split_whitespace().next() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    return Some(idx);
                }
            }
        }
    }
    None
}

pub fn setup_platform_routing(remote_address: &str) -> io::Result<()> {
    let proxy_ip = remote_address.split(':').next().unwrap_or(remote_address);

    #[cfg(target_os = "linux")]
    {
        // 1. Предварительная настройка ядра (rp_filter и пересылка)
        let _ = run_cmd_ext("sysctl -w net.ipv4.conf.all.rp_filter=0", true);
        let _ = run_cmd_ext("sysctl -w net.ipv4.conf.netr0.rp_filter=0", true);
        let _ = run_cmd_ext("sysctl -w net.ipv4.ip_forward=1", true);

        // 3. Маршрутизация (игнорируем ошибки, если правила уже есть)
        let _ = run_cmd_ext("ip rule add fwmark 0x1 table 100", true);
        let _ = run_cmd_ext("ip route add default dev netr0 table 100", true);

        // 4. NFTables
        let _ = run_cmd_ext("nft delete table ip netrunner", true);
        run_cmd_ext("nft add table ip netrunner", false)?;
        run_cmd_ext(
            "nft add chain ip netrunner output { type route hook output priority 0; }",
            false,
        )?;

        let mark_rule = format!(
            "nft add rule ip netrunner output ip daddr != {} oifname != \"netr0\" mark set 0x1",
            proxy_ip
        );
        run_cmd_ext(&mark_rule, false)?;

        // 5. DNS
        let _ = Command::new("resolvectl")
            .args(["dns", "netr0", "10.0.0.2"])
            .status();
        let _ = Command::new("resolvectl")
            .args(["domain", "netr0", "~."])
            .status();

        info!("Linux network auto-configured: RPF=0, MTU=1280, Rules active.");
    }
    #[cfg(target_os = "windows")]
    {
        use std::{process::Command, thread, time::Duration};

        // 1. Инициализация Wintun
        let wintun = unsafe { wintun::load_from_path("wintun.dll") }.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Wintun load error: {}", e))
        })?;

        let adapter = match wintun::Adapter::open(&wintun, "netr0") {
            Ok(a) => a,
            Err(_) => {
                wintun::Adapter::create(&wintun, "netr0", "Wintun Tunnel", None).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("Wintun create error: {}", e))
                })?
            }
        };

        // 2. Получаем индекс активного интерфейса для маршрутизации прокси
        let if_idx = get_active_interface_index().unwrap_or(1);
        info!(
            "Wintun adapter active. Routing proxy traffic via interface index: {}",
            if_idx
        );

        // 3. Добавляем маршрут к IP прокси через ИНДЕКС (самый надежный способ)
        let route_cmd = format!(
            "netsh interface ipv4 add route {}/32 interface={} metric=1",
            proxy_ip, if_idx
        );
        // Игнорируем ошибку, если маршрут уже существует
        let _ = run_cmd_ext(&route_cmd, true);

        // 4. Настраиваем адрес (БЕЗ шлюза 10.0.0.2, чтобы не перехватить весь трафик)
        let addr_cmd =
            "netsh interface ipv4 set address name=\"netr0\" static 10.0.0.1 255.255.255.0";

        // 5. Задаем DNS и применяем настройки
        let dns_cmd = "netsh interface ipv4 set dnsservers name=\"netr0\" static 10.0.0.2 primary validate=no";

        let mut attempt = 0;
        while attempt < 5 {
            if run_cmd_ext(addr_cmd, false).is_ok() {
                let _ = run_cmd_ext(dns_cmd, false);
                break;
            }
            attempt += 1;
            thread::sleep(Duration::from_millis(1000));
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        eprintln!("Android/Mobile routing on native side");
    }
    Ok(())
}

pub fn reset_platform_routing(proxy_ip: Option<&str>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = run_cmd_ext("ip rule del fwmark 0x1 table 100", true);
        let _ = run_cmd_ext("ip route flush table 100", true);
        let _ = run_cmd_ext("nft delete table ip netrunner", true);
        info!("Linux routing reset.");
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(ip) = proxy_ip {
            // Удаляем только маршрут к конкретному IP прокси-сервера.
            // Это гораздо безопаснее, чем удалять маршрут по умолчанию (0.0.0.0).
            let cmd = format!("route delete {}", ip);
            let _ = run_cmd_ext(&cmd, true);
            let _ = run_cmd_ext("netsh interface delete interface name=\"netr0\"", true);
            info!("Windows routing for proxy {} removed.", ip);
        } else {
            error!("Cannot reset Windows routing: proxy_ip is missing.");
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        eprintln!("Android/Mobile routing on native side");
    }
    Ok(())
}
