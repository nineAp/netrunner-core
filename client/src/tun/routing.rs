//! Платформенная маршрутизация и kill-switch.
//!
//! Заворачивает системный трафик в TUN-интерфейс и (опционально) режет утечки
//! мимо туннеля. Реализация целиком платформо-зависимая (`cfg`):
//!
//! - **Linux** — `nftables` (таблица `netrunner`): маркировка трафика в TUN,
//!   split-tunneling по UID, DNAT DNS на стек, kill-switch с исключениями для LAN
//!   и самого прокси; плюс policy-routing через `ip rule`/`ip route table 100`.
//! - **Windows** — таблица маршрутов (`route add` половинками `0.0.0.0/1`+`128.0.0.0/1`,
//!   чтобы перебить дефолт, не удаляя его), kill-switch удалением дефолтного
//!   маршрута, восстановление через DHCP-renew.
//! - **Android/iOS** — ничего: маршрутизацию ставит нативная сторона (`VpnService`).
//!
//! [`setup_platform_routing`] ставит правила, [`reset_platform_routing`] —
//! откатывает их при остановке. Все внешние команды идут через [`run_cmd_ext`].

use netrunner_logger::{error, info};
use std::io;

use std::process::Command;

/// Выполняет внешнюю команду (через `shlex`-разбор строки).
///
/// `ignore_errors` — не падать на ненулевом коде возврата (для идемпотентных
/// операций вроде «удалить правило, которого может не быть»). На Windows окно
/// процесса скрывается флагом `CREATE_NO_WINDOW`.
pub fn run_cmd_ext(full_cmd: &str, ignore_errors: bool) -> io::Result<()> {
    let parts = shlex::split(full_cmd)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid syntax"))?;

    if parts.is_empty() {
        return Ok(());
    }

    let mut cmd = Command::new(&parts[0]);
    cmd.args(&parts[1..]);

    // Добавляем логику для скрытия окна на Windows
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // 0x08000000 — это флаг CREATE_NO_WINDOW
        cmd.creation_flags(0x08000000);
    }

    let status = cmd.status()?;

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

    stdout
        .lines()
        .find(|line| line.contains("0.0.0.0"))
        .and_then(|line| line.split_whitespace().nth(2))
        .map(|s| s.to_string())
}

#[cfg(target_os = "linux")]
pub fn get_default_gateway_linux() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace().nth(2).map(|s| s.to_string())
}

/// Ставит платформенные правила маршрутизации: весь трафic → TUN, доступ к
/// прокси сохраняется, при `killswitch` всё прочее блокируется. `excluded_apps`
/// (на Linux — UID) проходят мимо туннеля (split-tunneling).
pub fn setup_platform_routing(
    remote_address: &str,
    killswitch: bool,
    excluded_apps: &[String],
) -> io::Result<()> {
    let proxy_ip = remote_address.split(':').next().unwrap_or(remote_address);

    #[cfg(target_os = "linux")]
    {
        let _ = run_cmd_ext("sysctl -w net.ipv4.conf.all.rp_filter=0", true);
        let _ = run_cmd_ext("sysctl -w net.ipv4.conf.netr0.rp_filter=0", true);
        let _ = run_cmd_ext("sysctl -w net.ipv4.ip_forward=1", true);

        let _ = run_cmd_ext("ip rule add fwmark 0x1 table 100", true);
        let _ = run_cmd_ext("ip route add default dev netr0 table 100", true);

        run_cmd_ext("nft add table ip netrunner", true)?;

        run_cmd_ext("nft flush table ip netrunner", true)?;

        run_cmd_ext(
            "nft add chain ip netrunner output { type route hook output priority 0; }",
            false,
        )?;
        run_cmd_ext(
            "nft add chain ip netrunner nat_out { type nat hook output priority -100; }",
            false,
        )?;

        // 1. Исключения для приложений (Split-Tunneling)
        // Ожидается, что для Linux в excluded_apps передаются UID пользователей
        for uid_str in excluded_apps {
            if let Ok(uid) = uid_str.parse::<u32>() {
                netrunner_logger::info!("Bypassing TUN for UID: {}", uid);
                // Пропускаем трафик этого UID мимо нашего роутинга
                run_cmd_ext(
                    &format!("nft add rule ip netrunner output meta skuid {} accept", uid),
                    false,
                )?;
            }
        }

        // 2. Базовая маркировка трафика для отправки в TUN
        let mark_rule = format!(
            "nft add rule ip netrunner output ip daddr != {} oifname != \"netr0\" mark set 0x1",
            proxy_ip
        );
        run_cmd_ext(&mark_rule, false)?;

        // 3. KILLSWITCH
        if killswitch {
            netrunner_logger::info!("🔒 Killswitch ENABLED (Linux)");
            // Исключения для локальной сети (крайне важно для сохранения доступа к роутеру)
            let lan_bypass = "nft add rule ip netrunner output ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept";
            run_cmd_ext(lan_bypass, false)?;

            // Разрешаем трафик до самого прокси-сервера
            run_cmd_ext(
                &format!(
                    "nft add rule ip netrunner output ip daddr {} accept",
                    proxy_ip
                ),
                false,
            )?;

            // Разрешаем трафик, который УЖЕ внутри туннеля
            run_cmd_ext(
                "nft add rule ip netrunner output oifname \"netr0\" accept",
                false,
            )?;

            // Блокируем всё остальное (Утечки)
            run_cmd_ext("nft add rule ip netrunner output drop", false)?;
        }

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

        let _ = run_cmd_ext("resolvectl dns netr0 10.0.0.2", true);
        let _ = run_cmd_ext("resolvectl domain netr0 ~.", true);

        info!("Linux network: NFTables flushed and re-configured.");
    }

    #[cfg(target_os = "windows")]
    {
        let gateway = get_default_gateway().unwrap_or_else(|| "192.168.1.1".to_string());
        let tun_idx = get_adapter_index("netr0")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Interface netr0 not found"))?;

        // Сохраняем доступ к прокси через физический шлюз
        run_cmd_ext(
            &format!(
                "route add {} mask 255.255.255.255 {} metric 1",
                proxy_ip, gateway
            ),
            true,
        )?;

        // Направляем весь трафик в TUN
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

        // KILLSWITCH: Удаляем дефолтный физический маршрут
        if killswitch {
            netrunner_logger::info!(
                "🔒 Killswitch ENABLED (Windows). Deleting default physical route."
            );
            run_cmd_ext(
                &format!("route delete 0.0.0.0 mask 0.0.0.0 {}", gateway),
                true,
            )?;
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        eprintln!("Android/Mobile routing on native side");
    }
    Ok(())
}

/// Откатывает всё, что поставил [`setup_platform_routing`]: удаляет TUN-интерфейс/
/// правила/таблицы и восстанавливает обычную маршрутизацию (на Windows — через
/// DHCP-renew, если был включён kill-switch).
pub fn reset_platform_routing(_proxy_ip: Option<&str>, _was_killswitch: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = run_cmd_ext("ip link delete netr0", true);
        let _ = run_cmd_ext("ip rule del fwmark 0x1 table 100", true);
        let _ = run_cmd_ext("ip route flush table 100", true);
        let _ = run_cmd_ext("nft delete table ip netrunner", true);
        info!("Linux routing reset.");
    }

    #[cfg(target_os = "windows")]
    {
        let _ = run_cmd_ext("route delete 0.0.0.0 mask 128.0.0.0", true);
        let _ = run_cmd_ext("route delete 128.0.0.0 mask 128.0.0.0", true);

        if let Some(ip) = _proxy_ip {
            let _ = run_cmd_ext(&format!("route delete {}", ip), true);
        }

        let _ = run_cmd_ext(
            "netsh interface ipv4 set dnsservers name=\"netr0\" source=dhcp",
            true,
        );

        if _was_killswitch {
            netrunner_logger::info!(
                "Restoring physical default route (DHCP renew needed or manual restore)"
            );
            // Windows не всегда сама возвращает default route после `route delete`.
            // Оптимальный хак: дернуть DHCP.
            let _ = run_cmd_ext("ipconfig /renew", true);
        }

        info!("Windows routing reset complete.");
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        eprintln!("Android/Mobile routing on native side");
    }
    Ok(())
}
