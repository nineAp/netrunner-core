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
use netrunner_core::decoy::CoverFlight;
use netrunner_core::nrxp::shape::MIN_SAMPLES as SHAPE_MIN;
use netrunner_core::pcap::{
    analyze_many, Analysis, CapturedProfile, CapturedQuic, ProfileOptions, VerifyReport, DEFAULT_SAMPLES,
};

#[derive(Subcommand)]
pub enum ProfileAction {
    /// Записать трафик браузера и собрать профиль (Linux, нужен root/CAP_NET_RAW).
    Record(RecordArgs),
    /// Собрать профиль из готового файла захвата (.pcap/.pcapng).
    Build(BuildArgs),
    /// Объединить несколько файлов профилей в один пул (массив).
    Merge(MergeArgs),
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
    /// Снять профиль для КАЖДОГО отпечатка в захвате (Chrome + Firefox…) и
    /// записать массив: сессии будут брать из него по хешу.
    #[arg(long, conflicts_with = "ja4")]
    all: bool,
    /// С `--all`: минимум соединений на отпечаток (одиночные — случайные
    /// клиенты вроде curl; перемешивание по ним не определить).
    #[arg(long, default_value_t = 2, requires = "all")]
    min_hellos: usize,
    /// Брать QUIC-группу с этим JA4 (по умолчанию — самую многочисленную).
    #[arg(long)]
    quic_ja4: Option<String>,
    /// Не снимать QUIC-блок (UDP-нога останется на встроенном Initial).
    #[arg(long)]
    no_quic: bool,
    /// Записать длины записей первого flight'а сервера (для `--cover-flight`
    /// узла). Нужен `--flight-sni`: откройте в браузере свой decoy-домен.
    #[arg(long, value_name = "FILE", requires = "flight_sni")]
    flight_out: Option<PathBuf>,
    /// Домен (подстрока SNI), чей ответ измерять для `--flight-out`.
    #[arg(long, value_name = "HOST")]
    flight_sni: Option<String>,
}

#[derive(Args)]
pub struct MergeArgs {
    /// Файлы профилей (каждый — объект либо массив).
    #[arg(required = true, num_args = 1..)]
    files: Vec<PathBuf>,
    /// Куда записать объединённый пул.
    #[arg(long, short, value_name = "FILE")]
    out: PathBuf,
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
    /// Остановиться, когда набрано столько TCP-соединений одного отпечатка (если
    /// пошёл QUIC — ещё и его, до 15 с ожидания). 0 — ждать только Ctrl+C или таймера.
    #[arg(long, default_value_t = 12)]
    stop_after: usize,
    #[command(flatten)]
    select: Select,
}

#[derive(Args)]
pub struct BuildArgs {
    /// Файл(ы) захвата. Несколько файлов разбираются как один (например, прогон
    /// с QUIC и прогон с `--disable-quic`).
    #[arg(required = true, num_args = 1..)]
    captures: Vec<PathBuf>,
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
        ProfileAction::Merge(a) => merge(a),
        ProfileAction::Check { file } => check(file),
    }
}

fn options(s: &Select, default_name: &str) -> ProfileOptions {
    ProfileOptions {
        name: Some(s.name.clone().unwrap_or_else(|| default_name.to_owned())),
        sni_contains: s.sni.clone(),
        client_ip: s.client,
        ja4: s.ja4.clone(),
        quic_ja4: s.quic_ja4.clone(),
    }
}

fn build(a: BuildArgs) -> Result<()> {
    let files = a
        .captures
        .iter()
        .map(|p| std::fs::read(p).with_context(|| format!("не удалось прочитать {}", p.display())))
        .collect::<Result<Vec<_>>>()?;
    let refs: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
    let analysis = analyze_many(&refs).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    finish(&analysis, &a.select, "captured", &a.out)
}

/// Строит профиль(и), проверяет их движком, сохраняет JSON, печатает сводку.
fn finish(analysis: &Analysis, sel: &Select, default_name: &str, out: &PathBuf) -> Result<()> {
    for w in &analysis.warnings {
        eprintln!("предупреждение: {w}");
    }
    let opt = options(sel, default_name);
    let profiles = if sel.all {
        analysis
            .build_profiles(&opt, sel.min_hellos)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
    } else {
        vec![analysis
            .build_profile(&opt)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?]
    };

    // QUIC-блок: Chrome и другие говорят по UDP/443; из тех же Initial'ов
    // берётся ClientHello, транспортные параметры и раскладка пакетов.
    let mut profiles = profiles;
    let mut quic_reports = Vec::new();
    if !sel.no_quic {
        let quics = if sel.all {
            analysis.build_quics(&opt, sel.min_hellos).ok()
        } else {
            analysis.build_quic(&opt).ok().map(|q| vec![q])
        };
        if let Some(quics) = quics {
            for (i, q) in quics.iter().enumerate() {
                match profiles.get_mut(i) {
                    Some(p) => p.quic = Some(q.spec.clone()),
                    None => eprintln!(
                        "предупреждение: QUIC-отпечаток {} ({} соед.) не к чему прикрепить — профилей TCP меньше",
                        q.ja4, q.flows_used
                    ),
                }
            }
            quic_reports = quics;
        } else if analysis.quic_flows.is_empty() {
            eprintln!(
                "QUIC: клиентских Initial в записи нет (UDP-нога останется на встроенном Initial). \
                 Чтобы снять и его, не отключайте QUIC в браузере и откройте сайты с HTTP/3 (google.com, youtube.com)."
            );
        }
    }

    let mut specs = Vec::new();
    let mut unfaithful = Vec::new();
    for profile in &profiles {
        let spec = profile.to_spec();
        // Гарантия 1: записываем только то, что движок примет.
        let warnings = spec
            .validate()
            .map_err(|e| anyhow::anyhow!("снятый профиль «{}» непригоден: {e}", profile.name))?;
        // Гарантия 2: движок воспроизводит то, что видел у браузера.
        let report = analysis.verify_profile(profile, DEFAULT_SAMPLES);
        print_summary(profile, &warnings, report.as_ref());
        if report.as_ref().is_some_and(|r| !r.ok()) {
            unfaithful.push(profile.name.clone());
        }
        specs.push(spec);
    }
    for q in &quic_reports {
        let report = analysis.verify_quic(q, DEFAULT_SAMPLES);
        print_quic_summary(q, report.as_ref());
        if report.as_ref().is_some_and(|r| !r.ok()) {
            unfaithful.push(format!("{} (QUIC)", q.spec.hello.name));
        }
    }

    let json = if sel.all {
        netrunner_core::browser_profile::ProfileSpec::pool_to_json(&specs)
    } else {
        specs[0].to_json()
    };
    std::fs::write(out, json).with_context(|| format!("не удалось записать {}", out.display()))?;
    eprintln!("\nПрофилей записано: {} → {}", specs.len(), out.display());

    if let (Some(path), Some(host)) = (&sel.flight_out, &sel.flight_sni) {
        write_flight(analysis, host, path)?;
    }
    eprintln!("Запуск с ним:    netrunner-client --config client.toml --browser-profile {}", out.display());
    if !unfaithful.is_empty() {
        bail!(
            "профиль записан, но движок его НЕ воспроизводит ({}): см. ✘ выше — такой профиль \
             выдаст себя на первом же соединении",
            unfaithful.join(", ")
        );
    }
    Ok(())
}

/// Измеряет первый flight сервера и пишет файл для `netrunner-server --cover-flight`.
fn write_flight(analysis: &Analysis, host: &str, path: &PathBuf) -> Result<()> {
    let m = analysis.measured_flight(host).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let (flight, warnings) = CoverFlight::from_records(m.records.clone())
        .map_err(|e| anyhow::anyhow!("измеренный flight непригоден: {e}"))?;
    std::fs::write(path, flight.to_json())
        .with_context(|| format!("не удалось записать {}", path.display()))?;
    eprintln!(
        "\n── Cover-flight «{host}» ──\nзаписи: {:?} (по {} из {} полных рукопожатий)",
        m.records, m.seen, m.total
    );
    if m.distinct > 1 {
        eprintln!(
            "внимание: у домена {} разных набора длин (балансировщик/разные цепочки); взят самый частый",
            m.distinct
        );
    }
    for w in warnings {
        eprintln!("внимание: {w}");
    }
    eprintln!("Записан: {}\nНа узле: netrunner-server --cover-flight {}", path.display(), path.display());
    Ok(())
}

fn print_quic_summary(q: &CapturedQuic, verify: Option<&VerifyReport>) {
    let layout: Vec<String> = q
        .spec
        .initial_packets
        .iter()
        .map(|p| format!("{} Б CRYPTO в датаграмме {}", p.crypto, p.datagram))
        .collect();
    eprintln!("\n── QUIC «{}» ──", q.spec.hello.name);
    eprintln!("JA4:                  {}", q.ja4);
    eprintln!("Соединений в основе:  {}", q.flows_used);
    eprintln!("Initial-пакеты:       {} ({})", q.spec.initial_packets.len(), layout.join("; "));
    eprintln!(
        "SCID {} Б, номер пакета {} Б, транспортных параметров {}",
        q.spec.scid_len,
        q.spec.pn_len,
        q.spec.transport_params.len()
    );
    match verify {
        Some(r) if r.ok() => eprintln!(
            "Самопроверка:         ✔ движок воспроизводит QUIC Initial ({} сборок: JA4 {}, порядков расширений {})",
            r.samples, r.ja4_got, r.order_variants
        ),
        Some(r) => {
            for pr in &r.problems {
                eprintln!("Самопроверка:         ✘ {pr}");
            }
        }
        None => eprintln!("Самопроверка:         — (нет эталона)"),
    }
    for n in &q.notes {
        eprintln!("внимание: {n}");
    }
}

fn print_summary(p: &CapturedProfile, validate_warnings: &[String], verify: Option<&VerifyReport>) {
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
        // SNI посещённых сайтов в файл не попадает и на экран не выводится.
        eprintln!("другой отпечаток:     {} ({} шт.)", g.ja4, g.hellos);
    }
    if p.shape_up.len() >= SHAPE_MIN && p.shape_down.len() >= SHAPE_MIN {
        eprintln!(
            "Форма трафика:        записей {}↑ / {}↓ → {} / {} квантилей (длины TLS-записей браузера)",
            p.shape_records.0, p.shape_records.1, p.shape_up.len(), p.shape_down.len()
        );
    }
    match verify {
        Some(r) if r.ok() => eprintln!(
            "Самопроверка:         ✔ движок воспроизводит профиль ({} сборок: JA4 совпал, порядков расширений {}, длины ECH {:?})",
            r.samples, r.order_variants, r.ech_lengths_seen
        ),
        Some(r) => {
            for pr in &r.problems {
                eprintln!("Самопроверка:         ✘ {pr}");
            }
        }
        None => eprintln!("Самопроверка:         — (нет эталонного ClientHello)"),
    }
    for n in p.notes.iter().chain(validate_warnings) {
        eprintln!("внимание: {n}");
    }
}

fn merge(a: MergeArgs) -> Result<()> {
    use netrunner_core::browser_profile::parse_specs;
    let mut out: Vec<netrunner_core::browser_profile::ProfileSpec> = Vec::new();
    for f in &a.files {
        let text = std::fs::read_to_string(f)
            .with_context(|| format!("не удалось прочитать {}", f.display()))?;
        let specs = parse_specs(&text).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
        for s in specs {
            s.validate().map_err(|e| anyhow::anyhow!("{}: профиль «{}» непригоден: {e}", f.display(), s.name))?;
            let ja4 = s.meta.as_ref().and_then(|m| m.get("ja4")).and_then(|v| v.as_str()).map(str::to_owned);
            // Один отпечаток дважды в пуле не нужен: он лишь исказит доли.
            if ja4.is_some()
                && out.iter().any(|o| {
                    o.meta.as_ref().and_then(|m| m.get("ja4")).and_then(|v| v.as_str()) == ja4.as_deref()
                })
            {
                eprintln!("пропущен дубль отпечатка {} («{}», {})", ja4.unwrap_or_default(), s.name, f.display());
                continue;
            }
            let mut s = s;
            let base = s.name.clone();
            let mut n = 2;
            while out.iter().any(|o| o.name == s.name) {
                s.name = format!("{base}_{n}");
                n += 1;
            }
            out.push(s);
        }
    }
    let json = netrunner_core::browser_profile::ProfileSpec::pool_to_json(&out);
    std::fs::write(&a.out, json).with_context(|| format!("не удалось записать {}", a.out.display()))?;
    eprintln!(
        "Пул из {} профилей → {}: {}",
        out.len(),
        a.out.display(),
        out.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
    );
    Ok(())
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
                "\r  {:>3} с | пакетов {:>6} | TCP-соединений {:>3} | ClientHello {:>3} + QUIC {:>3} | отпечатков {} (лучший: {})   ",
                p.elapsed.as_secs(),
                p.packets_kept,
                p.tcp_flows,
                p.client_hellos,
                p.quic_hellos,
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
        eprintln!(
            "Захват сохранён: {}\nвнимание: в сыром захвате есть IP-адреса и имена всех сайтов, которые \
             открывал браузер (SNI). Не публикуйте его и не пересылайте; в JSON-профиль это не попадает.",
            path.display()
        );
    }
    if rec.is_empty() {
        bail!(
            "ничего не записано: проверьте порт ({:?}), интерфейс и что браузер действительно \
             ходил в сеть",
            a.ports
        );
    }
    let analysis = rec.analyze();
    if analysis.client_hellos.is_empty() && !analysis.quic_flows.is_empty() {
        bail!(
            "в записи только QUIC ({} соединений), а профиль строится на TLS-over-TCP, к которому QUIC-блок \
             прикрепляется. Откройте в браузере и сайты по TCP (первое посещение сайта всегда идёт по TCP; \
             либо сделайте второй прогон с --disable-quic и передайте оба файла: \
             `profile build quic.pcap tcp.pcap --out profile.json`)",
            analysis.quic_flows.len()
        );
    }
    if analysis.client_hellos.is_empty() {
        bail!(
            "в записи нет TLS ClientHello. Частые причины: включён VPN/прокси; браузер использует \
             QUIC (запустите его с --disable-quic) или другой порт (--port); запись начата после \
             открытия соединений — откройте новые вкладки/сайты"
        );
    }
    finish(&analysis, &a.select, "recorded", &a.out)
}

#[cfg(not(target_os = "linux"))]
async fn record(_a: RecordArgs) -> Result<()> {
    bail!(
        "запись трафика поддерживается только на Linux; снимите захват в Wireshark/tcpdump и \
         выполните `netrunner-client profile build <файл.pcap> --out profile.json`"
    )
}
