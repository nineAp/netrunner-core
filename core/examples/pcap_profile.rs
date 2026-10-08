//! Снятие браузерного профиля с файла захвата.
//!
//! ```bash
//! sudo tcpdump -i any -w chrome.pcap 'tcp port 443'      # откройте 2+ сайта в браузере
//! cargo run -p netrunner-core --features pcap --example pcap_profile -- chrome.pcap \
//!     --name CHROME_141 [--sni example.com] [--client 192.168.1.10] [--ja4 <hash>] \
//!     [--json] [--list]
//! ```
//!
//! Печатает сводку по захвату, найденные отпечатки (`--list` — только их),
//! замечания о том, чего наш сборщик `ClientHello` воспроизвести не умеет, и
//! готовый Rust-код профиля (или JSON с `--json`). Если в захвате виден ответ
//! сервера, добавляется длина записей его первого flight'а (для `CoverFlight`).

use netrunner_core::pcap::{analyze, ProfileOptions};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut path = None;
    let mut opt = ProfileOptions::default();
    let (mut json, mut list) = (false, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--name" => opt.name = args.next(),
            "--sni" => opt.sni_contains = args.next(),
            "--client" => {
                opt.client_ip = args.next().and_then(|s| s.parse().ok());
                if opt.client_ip.is_none() {
                    die("--client: expected an IP address");
                }
            }
            "--ja4" => opt.ja4 = args.next(),
            "--json" => json = true,
            "--list" => list = true,
            "-h" | "--help" => {
                eprintln!("usage: pcap_profile <capture.pcap|pcapng> [--name NAME] [--sni SUBSTR] [--client IP] [--ja4 HASH] [--json] [--list]");
                return;
            }
            _ if path.is_none() => path = Some(a),
            _ => die(&format!("unexpected argument: {a}")),
        }
    }
    let Some(path) = path else {
        die("capture file is required (see --help)")
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let a = analyze(&bytes).unwrap_or_else(|e| die(&e.to_string()));

    eprintln!(
        "{path}: {} packets, {} TCP flows, {} TLS ClientHello, {} ServerHello",
        a.packets,
        a.tcp_flows,
        a.client_hellos.len(),
        a.server_flights.len()
    );
    for w in &a.warnings {
        eprintln!("warning: {w}");
    }

    if list {
        for h in &a.client_hellos {
            println!(
                "{}:{} -> {}:{}  sni={:<32} len={} ech={:?} ja4={}",
                h.client.ip,
                h.client.port,
                h.server.ip,
                h.server.port,
                h.sni.as_deref().unwrap_or("-"),
                h.record_payload_len,
                h.ech,
                netrunner_core::pcap::ja4(h)
            );
        }
        return;
    }

    let p = a.build_profile(&opt).unwrap_or_else(|e| die(&e.to_string()));
    if json {
        println!("{}", p.to_json());
        return;
    }
    println!("{}", p.to_rust_source());
    for g in &p.other_groups {
        eprintln!(
            "other fingerprint: {} ({} hellos, sni {:?})",
            g.ja4, g.hellos, g.sni_sample
        );
    }
    // Первый flight сервера для соединения, давшего эталонный ClientHello.
    if let Some(f) = a
        .client_hellos
        .iter()
        .filter(|h| netrunner_core::pcap::ja4(h) == p.ja4)
        .find_map(|h| a.flight_for(h))
    {
        println!(
            "// Первый flight сервера (suite {:#06x}): {}",
            f.server_hello.cipher_suite,
            f.to_rust_source()
        );
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}
