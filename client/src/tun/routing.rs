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
    let output = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        // Мы ищем строку с "connected", НЕ содержащую виртуальные интерфейсы
        // и НЕ являющуюся нашим туннелем (netr0)
        if line.contains("connected")
            && !line.contains("netr0")
            && !line.contains("vEthernet")
            && !line.contains("Loopback")
            && !line.contains("Bluetooth")
        {
            // Берем индекс из первого столбца (Инд)
            if let Some(idx_str) = line.split_whitespace().next() {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    return Some(idx);
                }
            }
        }
    }
    None
}
#[cfg(target_os = "windows")]
fn get_default_gateway() -> Option<String> {
    let output = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Простой парсинг: ищем строку с 0.0.0.0 и берем IP из колонки шлюза
    stdout
        .lines()
        .find(|line| line.contains("0.0.0.0"))
        .and_then(|line| line.split_whitespace().nth(2))
        .map(|s| s.to_string())
}

pub fn setup_platform_routing(remote_address: &str) -> io::Result<()> {
    let proxy_ip = remote_address.split(':').next().unwrap_or(remote_address);

    #[cfg(target_os = "linux")]
    {
        // 1. Ядро
        let _ = run_cmd_ext("sysctl -w net.ipv4.conf.all.rp_filter=0", true);
        let _ = run_cmd_ext("sysctl -w net.ipv4.conf.netr0.rp_filter=0", true);
        let _ = run_cmd_ext("sysctl -w net.ipv4.ip_forward=1", true);

        // 2. Маршрутизация
        let _ = run_cmd_ext("ip rule add fwmark 0x1 table 100", true);
        let _ = run_cmd_ext("ip route add default dev netr0 table 100", true);

        // 3. NFTables (Чиним ошибку удаления и синтаксис)
        // Добавляем таблицу (если есть — ничего не сделает, если нет — создаст)
        run_cmd_ext("nft add table ip netrunner", true)?;
        // Очищаем таблицу перед работой, чтобы не плодить дубликаты
        run_cmd_ext("nft flush table ip netrunner", true)?;

        run_cmd_ext(
            "nft add chain ip netrunner output { type route hook output priority 0; }",
            false,
        )?;
        run_cmd_ext(
            "nft add chain ip netrunner nat_out { type nat hook output priority -100; }",
            false,
        )?;

        let mark_rule = format!(
            "nft add rule ip netrunner output ip daddr != {} oifname != \"netr0\" mark set 0x1",
            proxy_ip
        );
        run_cmd_ext(&mark_rule, false)?;

        let dns_redir = format!(
            "nft add rule ip netrunner nat_out udp dport 53 ip daddr != {} dnat to 10.0.0.2:53",
            proxy_ip
        );
        run_cmd_ext(&dns_redir, false)?;

        // 4. DNS (resolvectl не знает 'metric', используем стандартный синтаксис)
        let _ = run_cmd_ext("resolvectl dns netr0 10.0.0.2", true);
        let _ = run_cmd_ext("resolvectl domain netr0 ~.", true);

        info!("Linux network: NFTables flushed and re-configured.");
    }
    #[cfg(target_os = "windows")]
    {
        let gateway = get_default_gateway().unwrap_or_else(|| "192.168.1.1".to_string());

        let if_idx = get_active_interface_index().unwrap_or(0);
        if if_idx == 0 {
            warn!("Could not find active interface index, routing might fail.");
        }

        let _ = run_cmd_ext(
            &format!(
                "route add {} mask 255.255.255.255 {} metric 1",
                proxy_ip, gateway
            ),
            true,
        );

        let _ = run_cmd_ext(
            &format!(
                "route add 0.0.0.0 mask 128.0.0.0 10.0.0.2 if {} metric 5",
                if_idx
            ),
            true,
        );
        let _ = run_cmd_ext(
            &format!(
                "route add 128.0.0.0 mask 128.0.0.0 10.0.0.2 if {} metric 5",
                if_idx
            ),
            true,
        );

        // 3. DNS
        let _ = run_cmd_ext(
            &format!("netsh interface ipv4 set dnsservers name=\"netr0\" static 10.0.0.2 primary"),
            true,
        );

        info!(
            "Full tunneling configured: Internet via netr0 (if {}), Proxy Exception via {}",
            if_idx, gateway
        );
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
