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
        return Err(io::Error::other(err));
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

/// Что именно заворачивается в туннель.
///
/// Появилось вместе с корпоративным (managed) режимом: организация может
/// выдать сотруднику доступ К РЕСУРСАМ, а не «всю сеть через нас». Для
/// частного пользователя режим всегда [`TunnelMode::All`] — ровно прежнее
/// поведение, ничего не меняется.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TunnelMode {
    /// Весь трафик в туннель (классический VPN).
    #[default]
    All,
    /// Только объявленные подсети (ZTNA): личный трафик сотрудника через нас
    /// не идёт вообще. Это не оптимизация, а обещание, которое даётся клиенту
    /// при продаже, — и именно поэтому режим реализован маршрутизацией, а не
    /// фильтрацией «уже внутри туннеля».
    Resources,
    /// Весь трафик, кроме локальной сети (домашний принтер, NAS, роутер).
    BypassLan,
}

/// Диапазоны RFC 1918 + loopback — то, что считается «локальной сетью».
/// Один список на оба места, где он нужен ([`TunnelMode::BypassLan`] и
/// kill-switch), чтобы они не разъехались.
const LAN_RANGES: &str = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";

/// Пропускает только то, что заведомо безопасно подставить в команду.
///
/// Значения приходят с бэкенда (`org_resources.value`, уже нормализованные
/// там), но здесь они попадают в строку, которая исполняется шеллом, — а
/// доверять валидации на другой стороне сети для такого нельзя. Форма
/// проверяется буквально: только цифры, точки и одна косая с длиной префикса.
fn is_safe_cidr(value: &str) -> bool {
    let Some((addr, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(len) = prefix.parse::<u8>() else {
        return false;
    };
    if len > 32 {
        return false;
    }
    let octets: Vec<&str> = addr.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.len() <= 3 && o.parse::<u8>().is_ok())
}

/// Отбрасывает всё, что не прошло [`is_safe_cidr`], с записью в лог.
///
/// Молча пропустить негодное значение нельзя: в режиме [`TunnelMode::Resources`]
/// пустой список означает «в туннель не идёт ничего», и сотрудник получил бы
/// молча неработающий доступ вместо внятной строки в логе.
fn sanitize_cidrs(cidrs: &[String]) -> Vec<String> {
    cidrs
        .iter()
        .filter_map(|c| {
            if is_safe_cidr(c) {
                Some(c.clone())
            } else {
                netrunner_logger::warn!("Отброшена некорректная подсеть ресурса: {:?}", c);
                None
            }
        })
        .collect()
}

/// `10.0.0.0/8` → `255.0.0.0`. Нужна Windows-ветке: `route add` принимает
/// маску, а не длину префикса.
///
/// Без `cfg(windows)` намеренно: функция чистая и покрыта тестами, которые
/// гоняются на Linux в CI, — под `cfg` они бы там просто не компилировались.
fn cidr_to_mask(cidr: &str) -> Option<String> {
    let (_, prefix) = cidr.split_once('/')?;
    let len: u32 = prefix.parse().ok()?;
    if len > 32 {
        return None;
    }
    // Сдвиг на 32 — UB для u32 в Rust (паника в debug), поэтому /0 отдельно.
    let bits: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some(format!(
        "{}.{}.{}.{}",
        bits >> 24,
        (bits >> 16) & 0xFF,
        (bits >> 8) & 0xFF,
        bits & 0xFF
    ))
}

/// Ставит платформенные правила маршрутизации: трафик → TUN (какой именно —
/// решает `mode`), доступ к прокси сохраняется, при `killswitch` всё прочее
/// блокируется. `excluded_apps` (на Linux — UID) проходят мимо туннеля
/// (split-tunneling). `routed_cidrs` используется только в
/// [`TunnelMode::Resources`] — это подсети ресурсов организации.
pub fn setup_platform_routing(
    remote_address: &str,
    killswitch: bool,
    excluded_apps: &[String],
    mode: TunnelMode,
    routed_cidrs: &[String],
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

        // 3. Локальная сеть мимо туннеля — до маркировки, потому что
        // `accept` терминален: домашний принтер и NAS остаются доступны.
        if mode == TunnelMode::BypassLan {
            run_cmd_ext(
                &format!("nft add rule ip netrunner output ip daddr {{ {LAN_RANGES} }} accept"),
                false,
            )?;
        }

        // 4. Маркировка трафика для отправки в TUN — здесь и проходит
        // разница между обычным VPN и корпоративным ZTNA.
        match mode {
            TunnelMode::All | TunnelMode::BypassLan => {
                let mark_rule = format!(
                    "nft add rule ip netrunner output ip daddr != {} oifname != \"netr0\" mark set 0x1",
                    proxy_ip
                );
                run_cmd_ext(&mark_rule, false)?;
            }
            TunnelMode::Resources => {
                // `flags interval` обязателен: без него set хранит только
                // одиночные адреса и не принимает подсети вообще.
                run_cmd_ext(
                    "nft add set ip netrunner tunneled_nets { type ipv4_addr; flags interval; }",
                    true,
                )?;

                let safe = sanitize_cidrs(routed_cidrs);
                if safe.is_empty() {
                    // Пустой список — не ошибка конфигурации, а законное
                    // состояние (админ ещё не выдал ни одного ресурса).
                    // Туннель поднимается, но в него ничего не маршрутизируется.
                    netrunner_logger::warn!(
                        "Режим resources без единой подсети — в туннель не пойдёт ничего"
                    );
                } else {
                    run_cmd_ext(
                        &format!(
                            "nft add element ip netrunner tunneled_nets {{ {} }}",
                            safe.join(", ")
                        ),
                        false,
                    )?;
                    run_cmd_ext(
                        "nft add rule ip netrunner output ip daddr @tunneled_nets oifname != \"netr0\" mark set 0x1",
                        false,
                    )?;
                    netrunner_logger::info!(
                        "🎯 Режим resources: в туннель маршрутизировано подсетей: {}",
                        safe.len()
                    );
                }
            }
        }

        // 5. KILLSWITCH
        //
        // В режиме resources его НЕ ставим, и это не упущение: «резать всё
        // мимо туннеля» там означало бы отрубить сотруднику весь личный
        // интернет, хотя через нас он и не должен идти. Утечки ресурсного
        // трафика при этом всё равно нет — он маркируется в таблицу 100 с
        // единственным маршрутом через netr0, и если интерфейс исчез, пакет
        // просто не находит маршрута. То есть режим fail-closed по построению,
        // а не по отдельному правилу.
        if killswitch && mode != TunnelMode::Resources {
            netrunner_logger::info!("🔒 Killswitch ENABLED (Linux)");
            // Исключения для локальной сети (крайне важно для сохранения доступа к роутеру)
            let lan_bypass =
                format!("nft add rule ip netrunner output ip daddr {{ {LAN_RANGES} }} accept");
            run_cmd_ext(&lan_bypass, false)?;

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

        match mode {
            TunnelMode::All | TunnelMode::BypassLan => {
                // Весь трафик в TUN. Двумя половинками /1, а не заменой
                // дефолта: так исходный маршрут остаётся в таблице и его не
                // надо восстанавливать вручную при отключении.
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

                // Локальная сеть мимо туннеля — явными маршрутами через
                // физический шлюз с меньшей метрикой, чем у половинок выше.
                if mode == TunnelMode::BypassLan {
                    for (net, mask) in [
                        ("10.0.0.0", "255.0.0.0"),
                        ("172.16.0.0", "255.240.0.0"),
                        ("192.168.0.0", "255.255.0.0"),
                    ] {
                        run_cmd_ext(
                            &format!("route add {net} mask {mask} {gateway} metric 1"),
                            true,
                        )?;
                    }
                }
            }
            TunnelMode::Resources => {
                // Маршрут на каждую подсеть ресурса вместо перехвата дефолта.
                // Всё остальное продолжает ходить как ходило — сотрудник даже
                // не замечает, что туннель поднят.
                let safe = sanitize_cidrs(routed_cidrs);
                if safe.is_empty() {
                    netrunner_logger::warn!(
                        "Режим resources без единой подсети — в туннель не пойдёт ничего"
                    );
                }
                for cidr in &safe {
                    let Some(mask) = cidr_to_mask(cidr) else {
                        continue;
                    };
                    let net = cidr.split('/').next().unwrap_or(cidr);
                    run_cmd_ext(
                        &format!("route add {net} mask {mask} 10.0.0.2 if {tun_idx} metric 5"),
                        true,
                    )?;
                }
                netrunner_logger::info!(
                    "🎯 Режим resources: маршрутов в туннель добавлено: {}",
                    safe.len()
                );
            }
        }

        // KILLSWITCH: Удаляем дефолтный физический маршрут.
        // В режиме resources — не трогаем: дефолт там и должен остаться, через
        // него идёт весь личный трафик (см. тот же разбор в Linux-ветке).
        if killswitch && mode != TunnelMode::Resources {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Значения подсетей приходят по сети и попадают в строку, которую
    /// исполняет шелл. Проверяем именно отсев, а не «формат красивый».
    #[test]
    fn only_well_formed_cidrs_pass() {
        for good in ["10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0", "10.1.2.3/32"] {
            assert!(is_safe_cidr(good), "отверг корректное {good}");
        }
        for bad in [
            "10.0.0.0",             // без префикса
            "10.0.0.0/33",          // префикс вне диапазона
            "10.0.0.0/8; rm -rf /", // инъекция команды
            "10.0.0.0/8 accept",    // инъекция правила nft
            "gitlab.corp/24",       // не адрес
            "999.0.0.0/8",          // октет вне диапазона
            "10.0.0/8",             // мало октетов
            "10.0.0.0.0/8",         // много октетов
            "",
            "/8",
        ] {
            assert!(!is_safe_cidr(bad), "принял негодное {bad:?}");
        }
    }

    #[test]
    fn sanitize_drops_bad_and_keeps_good() {
        let input = vec![
            "10.0.0.0/8".to_string(),
            "не подсеть".to_string(),
            "192.168.0.0/16".to_string(),
        ];
        assert_eq!(
            sanitize_cidrs(&input),
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
    }

    #[test]
    fn prefix_length_converts_to_mask() {
        assert_eq!(cidr_to_mask("10.0.0.0/8").as_deref(), Some("255.0.0.0"));
        assert_eq!(
            cidr_to_mask("192.168.1.0/24").as_deref(),
            Some("255.255.255.0")
        );
        assert_eq!(
            cidr_to_mask("10.1.2.3/32").as_deref(),
            Some("255.255.255.255")
        );
        // /0 — отдельная ветка: сдвиг u32 на 32 в Rust это паника в debug.
        assert_eq!(cidr_to_mask("0.0.0.0/0").as_deref(), Some("0.0.0.0"));
        assert_eq!(cidr_to_mask("10.0.0.0/33"), None);
        assert_eq!(cidr_to_mask("10.0.0.0"), None);
    }

    /// Режим по умолчанию обязан остаться прежним поведением: частный
    /// пользователь ничего не должен заметить от появления корпоративного.
    #[test]
    fn default_mode_is_full_tunnel() {
        assert_eq!(TunnelMode::default(), TunnelMode::All);
    }
}
