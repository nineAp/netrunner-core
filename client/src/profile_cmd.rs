//! `netrunner-client profile …` — снятие и проверка браузерных профилей.
//!
//! Сценарий «записать → сёрфить → получить профиль»:
//!
//! ```text
//! sudo netrunner-client profile record --out chrome.json      # (VPN выключен!)
//!   … откройте в браузере несколько разных сайтов, нажмите Ctrl+C …
//! netrunner-client --config client.toml --browser-profile chrome.json
//! ```
//!
//! Запись читает сырой сокет (нужен root либо `CAP_NET_RAW`), берёт только
//! начало TLS-соединений, собирает по ним профиль и пишет JSON, который
//! движок читает при старте.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use netrunner_core::pcap::{analyze, Analysis, CapturedProfile, ProfileOptions};

#[derive(Subcommand)]
pub enum ProfileAction {
    /// Записать трафик браузера и собрать профиль (Linux, нужен root/CAP_NET_RAW).
    Record(RecordArgs),
    /// Собрать профиль из готового файла захвата (.pcap/.pcapng).
    Build(BuildArgs),
    /// Проверить JSON-профиль и показать сводку.
    Check {
        /// Файл профиля (один объект либо массив).
        file: PathBuf,
    },
}

#[derive(Args)]
pub struct Select {
    /// Имя профиля.
    #[arg(long)]
    name: Option<String>,
    /// Брать только соединения с SNI, содержащим эту подстроку.
    #[arg(long)]
    sni: Option<String>,
    /// Брать только соединения от этого клиентского IP.
    #[arg(long)]
    client: Option<std::net::IpAddr>,
    /// Брать группу с этим JA4 (по умолчанию — самую многочисленную).
    #[arg(long)]
    ja4: Option<String>,
}

#[derive(Args)]
pub struct RecordArgs {
    /// Куда записать JSON-профиль.
    #[arg(long, short, value_name = "FILE")]
    out: PathBuf,
    /// Сохранить ещё и сырой захват (для Wireshark/повторного разбора).
    #[arg(long, value_name = "FILE")]
    save_pcap: Option<PathBuf>,
    /// Интерфейс (eth0, wlan0, lo…). По умолчанию — все.
    #[arg(long)]
    iface: Option<String>,
    /// TCP-порт(ы) TLS. Можно повторять.
    #[arg(long = "port", default_values_t = [443u16])]
    ports: Vec<u16>,
    /// Остановить запись через столько секунд.
    #[arg(long, default_value_t = 120)]
    seconds: u64,
    /// Остановиться, когда набрано столько соединений одного отпечатка
    /// (0 — не останавливаться, ждать Ctrl+C или таймера).
    #[arg(long, default_value_t = 12)]
    stop_after: usize,
    #[command(flatten)]
    select: Select,
}

#[derive(Args)]
pub struct BuildArgs {
    /// Файл захвата.
    capture: PathBuf,
    /// Куда записать JSON-профиль.
    #[arg(long, short, value_name = "FILE")]
    out: PathBuf,
    #[command(flatten)]
    select: Select,
}

pub async fn run(action: ProfileAction) -> Result<()> {
    match action {
        ProfileAction::Record(a) => record(a).await,
        ProfileAction::Build(a) => build(a),
        ProfileAction::Check { file } => check(file),
    }
}

fn options(s: &Select, default_name: &str) -> ProfileOptions {
    ProfileOptions {
        name: Some(s.name.clone().unwrap_or_else(|| default_name.to_owned())),
        sni_contains: s.sni.clone(),
        client_ip: s.client,
        ja4: s.ja4.clone(),
    }
}

fn build(a: BuildArgs) -> Result<()> {
    let bytes = std::fs::read(&a.capture)
        .with_context(|| format!("не удалось прочитать {}", a.capture.display()))?;
    let analysis = analyze(&bytes).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    finish(&analysis, &options(&a.select, "captured"), &a.out)
}

/// Строит профиль, сохраняет JSON, печатает сводку.
fn finish(analysis: &Analysis, opt: &ProfileOptions, out: &PathBuf) -> Result<()> {
    for w in &analysis.warnings {
        eprintln!("предупреждение: {w}");
    }
    let profile = analysis
        .build_profile(opt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let spec = profile.to_spec();
    // Гарантия: записываем только то, что движок примет.
    let warnings = spec
        .validate()
        .map_err(|e| anyhow::anyhow!("снятый профиль непригоден: {e}"))?;
    std::fs::write(out, spec.to_json())
        .with_context(|| format!("не удалось записать {}", out.display()))?;
    print_summary(&profile, &warnings);
    eprintln!("\nПрофиль записан: {}", out.display());
    eprintln!("Запуск с ним:    netrunner-client --config client.toml --browser-profile {}", out.display());
    Ok(())
}

fn print_summary(p: &CapturedProfile, validate_warnings: &[String]) {
    eprintln!("\n── Профиль «{}» ──", p.name);
    eprintln!("JA4:                  {}", p.ja4);
    eprintln!("ClientHello в основе: {}", p.hellos_used);
    eprintln!(
        "Перемешивание:        {} ({})",
        if p.shuffle_extensions { "да" } else { "нет" },
        p.shuffle_evidence
    );
    if !p.ech_payload_lengths.is_empty() {
        eprintln!("ECH payload, байт:    {:?}", p.ech_payload_lengths);
    }
    for g in &p.other_groups {
        eprintln!("другой отпечаток:     {} ({} шт., SNI {:?})", g.ja4, g.hellos, g.sni_sample);
    }
    for n in p.notes.iter().chain(validate_warnings) {
        eprintln!("внимание: {n}");
    }
}

fn check(file: PathBuf) -> Result<()> {
    let text = std::fs::read_to_string(&file)
        .with_context(|| format!("не удалось прочитать {}", file.display()))?;
    let specs = netrunner_core::browser_profile::parse_specs(&text)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut failed = false;
    for s in &specs {
        match s.validate() {
            Ok(warnings) => {
                eprintln!("✔ {}: профиль применим", s.name);
                for w in warnings {
                    eprintln!("  внимание: {w}");
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("✘ {}: {e}", s.name);
            }
        }
    }
    if failed {
        bail!("есть непригодные профили");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn record(a: RecordArgs) -> Result<()> {
    use netrunner_core::pcap::capture::{record, CaptureConfig, CaptureError};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let cfg = CaptureConfig {
        iface: a.iface.clone(),
        ports: a.ports.clone(),
        max_duration: (a.seconds > 0).then(|| Duration::from_secs(a.seconds)),
        stop_after_hellos: (a.stop_after > 0).then_some(a.stop_after),
        ..Default::default()
    };
    eprintln!(
        "Запись TLS-трафика (порты {:?}, интерфейс {}).\n\
         1) ОТКЛЮЧИТЕ VPN (иначе запишется наш собственный туннель);\n\
         2) откройте в браузере 3–5 РАЗНЫХ сайтов (желательно в новых вкладках);\n\
         3) нажмите Ctrl+C, когда хватит. Авто-остановка: {} с{}.\n",
        a.ports,
        a.iface.as_deref().unwrap_or("все"),
        a.seconds,
        if a.stop_after > 0 {
            format!(" или {} соединений одного отпечатка", a.stop_after)
        } else {
            String::new()
        }
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_signal = stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stop_signal.store(true, Ordering::Relaxed);
    });

    let stop_rec = stop.clone();
    let rec = tokio::task::spawn_blocking(move || {
        record(&cfg, &stop_rec, &mut |p| {
            eprint!(
                "\r  {:>3} с | пакетов {:>6} | соединений {:>3} | ClientHello {:>3} | отпечатков {} (лучший: {})   ",
                p.elapsed.as_secs(),
                p.packets_kept,
                p.tcp_flows,
                p.client_hellos,
                p.groups,
                p.best_group_hellos
            );
        })
    })
    .await
    .context("поток записи завершился аварийно")?
    .map_err(|e: CaptureError| anyhow::anyhow!(e.to_string()))?;
    eprintln!();

    if let Some(path) = &a.save_pcap {
        std::fs::write(path, rec.to_pcap())
            .with_context(|| format!("не удалось записать {}", path.display()))?;
        eprintln!("Захват сохранён: {}", path.display());
    }
    if rec.is_empty() {
        bail!(
            "ничего не записано: проверьте порт ({:?}), интерфейс и что браузер действительно \
             ходил в сеть",
            a.ports
        );
    }
    let analysis = rec.analyze();
    if analysis.client_hellos.is_empty() {
        bail!(
            "в записи нет TLS ClientHello. Частые причины: включён VPN/прокси; браузер использует \
             QUIC (запустите его с --disable-quic) или другой порт (--port); запись начата после \
             открытия соединений — откройте новые вкладки/сайты"
        );
    }
    finish(&analysis, &options(&a.select, "recorded"), &a.out)
}

#[cfg(not(target_os = "linux"))]
async fn record(_a: RecordArgs) -> Result<()> {
    bail!(
        "запись трафика поддерживается только на Linux; снимите захват в Wireshark/tcpdump и \
         выполните `netrunner-client profile build <файл.pcap> --out profile.json`"
    )
}
