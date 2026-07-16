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

/// Скрывает консольное окно на Windows для дочернего процесса (`CREATE_NO_WINDOW`).
/// Единая точка для всех внешних вызовов в этом модуле — чтобы не дублировать
/// флаг в каждом месте, где строится `Command`.
#[cfg(target_os = "windows")]
fn hide_console(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    // 0x08000000 — это флаг CREATE_NO_WINDOW
    cmd.creation_flags(0x08000000);
}

#[cfg(not(target_os = "windows"))]
fn hide_console(_cmd: &mut Command) {}

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
    hide_console(&mut cmd);

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
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-Command",
        &format!(
            "(Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4).ifIndex",
            name
        ),
    ]);
    hide_console(&mut cmd);
    let output = cmd.output().ok()?;

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
}

#[cfg(target_os = "windows")]
fn get_default_gateway() -> Option<String> {
    let mut cmd = Command::new("route");
    cmd.args(["print", "0.0.0.0"]);
    hide_console(&mut cmd);
    let output = cmd.output().ok()?;
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

/// Добавляет уже разрешённый (через публичный DNS, см. dns.rs) реальный IP
/// исключённого домена в nftables-set `excluded_ips`, созданный в
/// [`setup_platform_routing`] — вызывается фоновой задачей в engine.rs по мере
/// резолва каждого домена, во время работы туннеля (сам set до этого пуст).
#[cfg(target_os = "linux")]
pub fn allow_excluded_ip_linux(ip: &str) {
    let cmd = format!("nft add element ip netrunner excluded_ips {{ {} }}", ip);
    if let Err(e) = run_cmd_ext(&cmd, true) {
        netrunner_logger::warn!("Failed to add {} to excluded_ips set: {}", ip, e);
    }
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

        // 2. Исключённые домены (split-tunneling по доменам, см. dns.rs/engine.rs):
        // именованный set, который фоновая задача в engine.rs пополняет во время
        // работы (allow_excluded_ip_linux) по мере резолва каждого исключённого
        // домена через публичный DNS. Плюс фиксированный адрес самого публичного
        // резолвера (1.1.1.1) — без этого исключения резолвер сам попал бы под
        // маркировку ниже и ушёл бы в туннель, а не наружу напрямую.
        // Обе rule стоят ДО общей маркировки и ДО killswitch-блока: `accept` —
        // терминальный вердикт, так что пакет никогда не доходит ни до
        // mark-правила, ни до итогового `drop` killswitch'а — исключение
        // работает одинаково и с killswitch включённым, и выключенным.
        run_cmd_ext(
            "nft add set ip netrunner excluded_ips { type ipv4_addr; }",
            true,
        )?;
        run_cmd_ext(
            "nft add rule ip netrunner output ip daddr 1.1.1.1 accept",
            false,
        )?;
        run_cmd_ext(
            "nft add rule ip netrunner output ip daddr @excluded_ips accept",
            false,
        )?;

        // 3. Базовая маркировка трафика для отправки в TUN
        let mark_rule = format!(
            "nft add rule ip netrunner output ip daddr != {} oifname != \"netr0\" mark set 0x1",
            proxy_ip
        );
        run_cmd_ext(&mark_rule, false)?;

        // 4. KILLSWITCH
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

        // Публичный резолвер (1.1.1.1) исключён и здесь: иначе прямой UDP-запрос
        // `resolve_via_public_dns` (dns.rs) сам попал бы под этот DNAT и вернулся
        // бы обратно в наш же fake-DNS обработчик по кругу, так и не дойдя до
        // настоящего 1.1.1.1.
        let dns_redir = format!(
            "nft add rule ip netrunner nat_out udp dport 53 ip daddr != {{ {}, 1.1.1.1 }} dnat to 10.0.0.2:53",
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

        // Тот же приём для публичного DNS-резолвера (1.1.1.1) — фоновая задача
        // в engine.rs (`resolve_via_public_dns`, см. dns.rs) резолвит исключённые
        // домены напрямую через него; без явного host route этот запрос попал
        // бы под общий маршрут "весь трафик -> TUN" ниже и ушёл бы в туннель,
        // а не наружу через физический интерфейс.
        run_cmd_ext(
            &format!(
                "route add 1.1.1.1 mask 255.255.255.255 {} metric 1",
                gateway
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

        let _ = run_cmd_ext("route delete 1.1.1.1", true);

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
