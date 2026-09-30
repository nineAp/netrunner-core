//! Печатает наш QUIC Initial (или серверный flight) в hexdump, который
//! понимает `text2pcap`, — чтобы независимый парсер (Wireshark/`tshark`)
//! подтвердил, что это НАСТОЯЩИЙ QUIC (Этап 4 исследования).
//!
//! Собирать/запускать только с фичей:
//!
//! ```bash
//! # Клиентский Initial → проверяем, что tshark видит QUIC + SNI + ALPN h3:
//! cargo run -q -p netrunner-core --features dev-dump --example quic_initial_dump \
//!     -- client www.example.com > initial.hex
//! text2pcap -u 51000,443 initial.hex initial.pcap
//! tshark -r initial.pcap -Y quic -V | grep -iE "quic|server name|alpn|h3"
//!
//! # Серверный flight (Initial+Handshake), направление сервер→клиент:
//! cargo run -q -p netrunner-core --features dev-dump --example quic_initial_dump \
//!     -- server > flight.hex
//! text2pcap -u 443,51000 flight.hex flight.pcap
//! tshark -r flight.pcap -Y quic -V
//! ```
//!
//! Ожидаемо для `client`: строки `QUIC`, `Server Name: www.example.com`,
//! `ALPN … h3`. Это подтверждает #9 (Initial расшифровывается стандартными
//! ключами) и #10 (внутри валидный h3-ClientHello) вне нашего собственного теста.

use std::env;

/// text2pcap-формат: `<offset hex> <по 16 hex-байт>`; сброс offset в 0 = новый
/// пакет.
fn hexdump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let mut line = format!("{:06x}", i * 16);
        for b in chunk {
            line.push_str(&format!(" {:02x}", b));
        }
        println!("{line}");
    }
    println!();
}

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "client".to_string());
    match mode.as_str() {
        "server" => {
            for pkt in netrunner_core::devtools::quic_server_flight() {
                hexdump(&pkt);
            }
        }
        _ => {
            let sni = env::args().nth(2).unwrap_or_else(|| "www.example.com".to_string());
            hexdump(&netrunner_core::devtools::quic_client_initial(&sni));
        }
    }
}
