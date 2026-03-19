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
fn get_adapter_index(name: &str) -> Option<u32> {
    let output = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "(Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4).ifIndex",
                name
            ),
        ])
        .output()
        .ok()?;

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
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

        // 1. Устанавливаем IP для адаптера
        let _ = run_cmd_ext(
            "netsh interface ipv4 set address name=\"netr0\" static 10.0.0.1 255.255.255.0 none",
            true,
        );

        // 2. Ждем и получаем индекс именно нашего туннеля
        let tun_idx = get_adapter_index("netr0")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Interface netr0 not found"))?;

        // 3. Маршрут-исключение для прокси через физический шлюз
        let _ = run_cmd_ext(
            &format!(
                "route add {} mask 255.255.255.255 {} metric 1",
                proxy_ip, gateway
            ),
            true,
        );

        // 4. Глобальные маршруты через TUN (теперь с правильным if_idx)
        run_cmd_ext(
            &format!(
                "route add 0.0.0.0 mask 128.0.0.0 10.0.0.2 if {} metric 5",
                tun_idx
            ),
            true,
        )?;
        run_cmd_ext(
            &format!(
                "route add 128.0.0.0 mask 128.0.0.0 10.0.0.2 if {} metric 5",
                tun_idx
            ),
            true,
        )?;

        // 5. DNS
        let _ = run_cmd_ext(
            "netsh interface ipv4 set dnsservers name=\"netr0\" static 10.0.0.2 primary",
            true,
        );

        info!(
            "Windows: Routing configured on idx {} via 10.0.0.2",
            tun_idx
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
        // Очищаем глобальные маршруты, иначе интернет не вернется
        let _ = run_cmd_ext("route delete 0.0.0.0 mask 128.0.0.0", true);
        let _ = run_cmd_ext("route delete 128.0.0.0 mask 128.0.0.0", true);

        if let Some(ip) = proxy_ip {
            let _ = run_cmd_ext(&format!("route delete {}", ip), true);
        }

        // Сбрасываем DNS на автоматический (или удаляем наш)
        let _ = run_cmd_ext(
            "netsh interface ipv4 set dnsservers name=\"netr0\" source=dhcp",
            true,
        );

        info!("Windows routing reset complete.");
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        eprintln!("Android/Mobile routing on native side");
    }
    Ok(())
}
