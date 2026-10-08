//! # Разбор захватов трафика (`pcap`) и снятие браузерного профиля
//!
//! Профили [`BrowserProfile`](crate::tlseng) — «рецепты» отпечатка: списки
//! шифров, групп, подписей, порядок расширений. Их значения нельзя вспоминать
//! по памяти — они должны сниматься **с провода настоящего браузера**. Этот
//! блок делает именно это: читает файл захвата, собирает TCP-потоки, достаёт
//! `ClientHello` (и ответ сервера) и вычисляет по ним профиль.
//!
//! ```text
//! файл .pcap / .pcapng ─▶ reader ─▶ net (L2/L3/L4) ─▶ tcp (потоки)
//!        ─▶ tls (записи, ClientHello/ServerHello) ─▶ profile (CapturedProfile)
//!                                                  └▶ fingerprint (JA3 / JA4)
//! ```
//!
//! ## Что умеет
//!
//! * `pcap` (µs/ns, любой порядок байт) и `pcapng` (несколько секций/интерфейсов,
//!   `if_tsresol`); канальные уровни Ethernet (+VLAN), Linux cooked v1/v2,
//!   raw IP, BSD loopback; IPv4/IPv6 (расширенные заголовки); TCP с
//!   переупорядочиванием, ретрансмитами и переносом номера через 2³².
//! * Все `ClientHello` соединений **без потерь**: порядок расширений, GREASE,
//!   `key_share`, ALPS, ECH, паддинг, версия в заголовке записи.
//! * Отпечатки JA3 и JA4; группировка клиентов по JA4.
//! * Сборка [`CapturedProfile`]: поля `BrowserProfile`, готовый Rust-код,
//!   JSON, и список [`notes`](CapturedProfile::notes) — чего сборщик
//!   воспроизвести не умеет.
//! * Первый flight сервера (длины записей `ApplicationData` до ответа клиента)
//!   — исходные данные для [`CoverFlight`](crate::decoy::CoverFlight).
//!
//! ## Чего нет
//!
//! Расшифровки (TLS 1.3 после `ServerHello` закрыт — и не нужен), QUIC
//! (Initial-пакеты лишь подсчитываются), TCP Fast Open/Segmentation Offload
//! артефактов сверх разумного. Захват должен содержать **начало** соединения.
//!
//! ## Как снять захват
//!
//! ```bash
//! sudo tcpdump -i any -w chrome.pcap 'tcp port 443'   # затем откройте сайт в браузере
//! cargo run -p netrunner-core --features pcap --example pcap_profile -- chrome.pcap --name CHROME_141
//! ```
//!
//! Чтобы поймать перемешивание расширений, нужно **минимум два** соединения
//! браузера (откройте два разных сайта). Подробнее — `docs/PCAP_PROFILE.md`.

#[cfg(target_os = "linux")]
pub mod capture;
mod fingerprint;
mod net;
mod profile;
mod reader;
mod tcp;
mod tls;

pub use fingerprint::{ja3_hash, ja3_string, ja4, md5_hex};
pub use net::{Transport, UdpDatagram};
pub use profile::{select_hellos, CapturedProfile, FingerprintGroup, ProfileOptions};
pub use reader::{read_packets, write_pcap, Packet};
pub use tcp::{assemble_flows, Endpoint, Flow, Stream};
pub use tls::{
    handshake_messages, is_grease, parse_client_hello, parse_server_hello, split_records,
    ClientHelloInfo, HandshakeMsg, KeyShareEntry, RawExtension, RecordInfo, ServerHelloInfo,
};

use std::fmt;

/// Ошибки чтения захвата.
#[derive(Debug)]
pub enum PcapError {
    /// Файл оборван там, где этого быть не должно.
    Truncated(&'static str),
    /// Неизвестное магическое число.
    BadMagic([u8; 4]),
    /// Структура контейнера повреждена.
    Malformed(&'static str),
    /// Формат распознан, но не поддерживается.
    Unsupported(String),
    /// В захвате нет ни одного пригодного `ClientHello`.
    NoClientHello,
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(w) => write!(f, "capture truncated: {w}"),
            Self::BadMagic(m) => write!(
                f,
                "not a pcap/pcapng file (magic {:02x}{:02x}{:02x}{:02x})",
                m[0], m[1], m[2], m[3]
            ),
            Self::Malformed(w) => write!(f, "malformed capture: {w}"),
            Self::Unsupported(w) => write!(f, "unsupported: {w}"),
            Self::NoClientHello => write!(
                f,
                "no TLS ClientHello matched in the capture (check filters; the capture must \
                 contain the start of a TLS connection)"
            ),
        }
    }
}

impl std::error::Error for PcapError {}

/// Первый flight сервера в TLS-соединении.
#[derive(Debug, Clone)]
pub struct ServerFlight {
    pub client: Endpoint,
    pub server: Endpoint,
    pub server_hello: ServerHelloInfo,
    /// Все записи сервера после `ServerHello`, пока клиент не заговорил
    /// зашифрованно: `(content_type, length)`.
    pub records: Vec<(u8, u16)>,
    /// Длины записей `ApplicationData` первого flight'а — то, что имитирует
    /// [`CoverFlight`](crate::decoy::CoverFlight) (для TLS 1.3: `EncryptedExtensions`,
    /// `Certificate`, `CertificateVerify`, `Finished`).
    pub cover_records: Vec<usize>,
    /// Сервер прислал `ChangeCipherSpec` после `ServerHello`.
    pub ccs_seen: bool,
}

impl ServerFlight {
    /// Длины записей как `CoverFlight` ядра.
    pub fn cover_flight(&self) -> crate::decoy::CoverFlight {
        crate::decoy::CoverFlight {
            records: self.cover_records.clone(),
        }
    }

    /// Rust-выражение `CoverFlight`.
    pub fn to_rust_source(&self) -> String {
        format!(
            "CoverFlight {{ records: vec!{:?} }}",
            self.cover_records
        )
    }
}

/// Итог разбора захвата.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub packets: usize,
    pub tcp_flows: usize,
    pub tls_flows: usize,
    /// Все найденные `ClientHello` в порядке времени.
    pub client_hellos: Vec<ClientHelloInfo>,
    /// Ответы серверов (по одному на соединение, где виден `ServerHello`).
    pub server_flights: Vec<ServerFlight>,
    /// UDP-датаграммы, похожие на QUIC Initial (не разбираются).
    pub quic_initials: usize,
    /// Замечания по самому захвату (дыры, обрезка, фрагментация).
    pub warnings: Vec<String>,
}

impl Analysis {
    /// Ответ сервера для данного `ClientHello`.
    pub fn flight_for(&self, hello: &ClientHelloInfo) -> Option<&ServerFlight> {
        self.server_flights
            .iter()
            .find(|f| f.client == hello.client && f.server == hello.server)
    }

    /// Строит профиль по фильтрам `opt`.
    pub fn build_profile(&self, opt: &ProfileOptions) -> Result<CapturedProfile, PcapError> {
        let (hellos, summary) = select_hellos(&self.client_hellos, opt);
        let mut profile =
            CapturedProfile::from_hellos(&hellos, opt).ok_or(PcapError::NoClientHello)?;
        profile.other_groups = summary
            .into_iter()
            .filter(|g| g.ja4 != profile.ja4)
            .collect();
        if !profile.other_groups.is_empty() {
            profile.notes.push(format!(
                "в захвате есть ещё {} групп(ы) отпечатков (другие клиенты/режимы): см. other_groups; \
                 уточните --sni/--client/--ja4",
                profile.other_groups.len()
            ));
        }
        Ok(profile)
    }
}

/// Разбирает захват целиком.
pub fn analyze(bytes: &[u8]) -> Result<Analysis, PcapError> {
    let packets = read_packets(bytes)?;
    Ok(analyze_packets(&packets))
}

/// Разбор уже прочитанных пакетов (живой захват, `capture::record`).
pub fn analyze_packets(packets: &[Packet<'_>]) -> Analysis {
    let mut a = Analysis {
        packets: packets.len(),
        ..Default::default()
    };

    for pk in packets {
        if let Some(Transport::Udp(u)) = net::decode(pk.link_type, pk.data) {
            // QUIC long header: старший бит и fixed bit, тип Initial = 0b00.
            if (u.dport == 443 || u.sport == 443)
                && u.payload.len() >= 1200
                && u.payload[0] & 0xc0 == 0xc0
                && u.payload[0] & 0x30 == 0
            {
                a.quic_initials += 1;
            }
        }
    }

    let flows = assemble_flows(packets);
    a.tcp_flows = flows.len();

    for flow in &flows {
        let c_recs = split_records(&flow.c2s);
        if c_recs.first().map(|r| r.content_type) != Some(tls::CT_HANDSHAKE) {
            continue;
        }
        let msgs = handshake_messages(&flow.c2s, &c_recs);
        let Some(ch) = msgs
            .iter()
            .find_map(|m| parse_client_hello(m, flow.client, flow.server))
        else {
            continue;
        };
        a.tls_flows += 1;
        if flow.c2s.gap {
            a.warnings.push(format!(
                "{}:{}: потерян TCP-сегмент в потоке клиента — часть данных после дыры отброшена",
                flow.client.ip, flow.client.port
            ));
        }
        if ch.fragmented {
            a.warnings.push(format!(
                "{}:{}: ClientHello разбит на несколько TLS-записей",
                flow.client.ip, flow.client.port
            ));
        }
        let c_first_app = c_recs
            .iter()
            .find(|r| r.content_type == tls::CT_APPDATA)
            .map(|r| r.ts_nanos);
        a.client_hellos.push(ch);

        if let Some(f) = server_flight(flow, c_first_app) {
            a.server_flights.push(f);
        }
    }
    a.client_hellos.sort_by_key(|h| h.ts_nanos);
    if a.client_hellos.is_empty() && a.quic_initials > 0 {
        a.warnings.push(format!(
            "найдено {} QUIC Initial-пакетов, но TLS-over-TCP нет: QUIC не разбирается \
             (запретите QUIC в браузере: --disable-quic)",
            a.quic_initials
        ));
    }
    a
}

fn server_flight(flow: &Flow, client_first_app_ts: Option<u64>) -> Option<ServerFlight> {
    let recs = split_records(&flow.s2c);
    let msgs = handshake_messages(&flow.s2c, &recs);
    let sh_msg = msgs.iter().find(|m| m.msg_type == 0x02)?;
    let server_hello = parse_server_hello(sh_msg)?;

    // Конец записи(ей) ServerHello: сумма записей, его несущих, от первой записи.
    let first_hs = recs.iter().position(|r| r.content_type == tls::CT_HANDSHAKE)?;
    let end_idx = first_hs + sh_msg.record_count;
    let after = &recs[end_idx.min(recs.len())..];

    let mut records = Vec::new();
    let mut cover = Vec::new();
    let mut ccs_seen = false;
    for r in after {
        if let Some(t_c) = client_first_app_ts {
            if r.ts_nanos >= t_c {
                break;
            }
        }
        records.push((r.content_type, r.length));
        match r.content_type {
            tls::CT_CCS => ccs_seen = true,
            tls::CT_APPDATA => cover.push(r.length as usize),
            _ => {}
        }
    }
    // Нет временной привязки (SPB-пакеты без меток): берём непрерывный блок
    // ApplicationData сразу после hello.
    if client_first_app_ts.is_none() || (cover.is_empty() && records.is_empty()) {
        records.clear();
        cover.clear();
        for r in after {
            match r.content_type {
                tls::CT_CCS => {
                    ccs_seen = true;
                    records.push((r.content_type, r.length));
                }
                tls::CT_APPDATA => {
                    records.push((r.content_type, r.length));
                    cover.push(r.length as usize);
                }
                _ if !cover.is_empty() => break,
                _ => records.push((r.content_type, r.length)),
            }
        }
    }
    Some(ServerFlight {
        client: flow.client,
        server: flow.server,
        server_hello,
        records,
        cover_records: cover,
        ccs_seen,
    })
}

/// Удобная обёртка: файл → профиль.
pub fn profile_from_capture(
    bytes: &[u8],
    opt: &ProfileOptions,
) -> Result<(CapturedProfile, Analysis), PcapError> {
    let a = analyze(bytes)?;
    let p = a.build_profile(opt)?;
    Ok((p, a))
}

#[cfg(test)]
mod tests;
