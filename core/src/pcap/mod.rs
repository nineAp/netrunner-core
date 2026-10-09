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
pub mod quic;
mod quic_profile;
mod reader;
mod tcp;
mod tls;
mod verify;

pub use fingerprint::{ja3_hash, ja3_string, ja4, md5_hex};
pub use tls::is_grease as is_grease_ext;
pub use net::{Transport, UdpDatagram};
pub use profile::{select_hellos, CapturedProfile, FingerprintGroup, ProfileOptions};
pub use reader::{read_packets, write_pcap, Packet};
pub use tcp::{assemble_flows, Endpoint, Flow, Stream};
pub use quic_profile::{verify_quic, CapturedQuic};
pub use verify::{VerifyReport, DEFAULT_SAMPLES};
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
    /// Нет полного рукопожатия TLS 1.3 с ответом сервера для выбранного SNI.
    NoServerFlight,
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
            Self::NoServerFlight => write!(
                f,
                "no complete TLS 1.3 handshake with the requested SNI (resumed sessions and TLS 1.2 \
                 do not show the certificate flight); open the site in a fresh tab"
            ),
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

/// Длины TLS-записей `ApplicationData` одного соединения после рукопожатия.
#[derive(Debug, Clone)]
pub struct FlowShape {
    pub client: Endpoint,
    pub server: Endpoint,
    /// Клиент → сервер (без `Finished`).
    pub up: Vec<u16>,
    /// Сервер → клиент (без первого flight'а и билетов сессии).
    pub down: Vec<u16>,
}

/// Первый flight сервера, измеренный по захвату.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredFlight {
    pub records: Vec<usize>,
    /// Сколько соединений дали именно этот набор.
    pub seen: usize,
    /// Сколько подходящих соединений всего.
    pub total: usize,
    /// Сколько различных наборов длин встретилось.
    pub distinct: usize,
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
    /// Длины записей `ApplicationData` после рукопожатия, по соединениям TLS 1.3.
    pub flow_shapes: Vec<FlowShape>,
    /// UDP-датаграммы, похожие на клиентский QUIC Initial.
    pub quic_initials: usize,
    /// QUIC-соединения клиента: Initial-пакеты и собранный `ClientHello`.
    pub quic_flows: Vec<quic::QuicFlow>,
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
        // Форма трафика — по соединениям именно этой группы отпечатков.
        let (mut up, mut down) = (Vec::new(), Vec::new());
        for fs in &self.flow_shapes {
            if hellos.iter().any(|h| h.client == fs.client && h.server == fs.server) {
                up.extend_from_slice(&fs.up);
                down.extend_from_slice(&fs.down);
            }
        }
        profile.shape_records = (up.len(), down.len());
        profile.shape_up = crate::nrxp::shape::compress(up);
        profile.shape_down = crate::nrxp::shape::compress(down);
        for (name, n, v) in [("клиент→сервер", profile.shape_records.0, &profile.shape_up), ("сервер→клиент", profile.shape_records.1, &profile.shape_down)] {
            if v.len() < crate::nrxp::shape::MIN_SAMPLES {
                profile.notes.push(format!(
                    "форма трафика {name}: наблюдений {n} (нужно ≥ {}) — для этого направления не применяется; \
                     посёрфите дольше или откройте страницы потяжелее",
                    crate::nrxp::shape::MIN_SAMPLES
                ));
            }
        }
        profile.other_groups = summary
            .into_iter()
            .filter(|g| g.ja4 != profile.ja4)
            .collect();
        if !profile.other_groups.is_empty() {
            profile.notes.push(format!(
                "в захвате есть ещё {} групп(ы) отпечатков (другие клиенты/режимы): см. other_groups; \
                 уточните --sni/--client/--ja4 либо снимите все сразу (--all)",
                profile.other_groups.len()
            ));
        }
        Ok(profile)
    }

    /// Строит по профилю на **каждую** группу отпечатков (JA4) с не менее чем
    /// `min_hellos` соединениями. Имена — `<name>`, `<name>_2`, `<name>_3`…
    /// по убыванию числа соединений. Фильтры `sni`/`client` из `opt` действуют,
    /// `ja4` игнорируется.
    pub fn build_profiles(
        &self,
        opt: &ProfileOptions,
        min_hellos: usize,
    ) -> Result<Vec<CapturedProfile>, PcapError> {
        let base = opt.name.clone().unwrap_or_else(|| "captured".into());
        let (_, mut groups) = select_hellos(&self.client_hellos, &ProfileOptions { ja4: None, ..opt.clone() });
        groups.retain(|g| g.hellos >= min_hellos.max(1));
        groups.sort_by_key(|g| std::cmp::Reverse(g.hellos));
        if groups.is_empty() {
            return Err(PcapError::NoClientHello);
        }
        let mut out = Vec::new();
        for (i, g) in groups.iter().enumerate() {
            let mut p = self.build_profile(&ProfileOptions {
                name: Some(if i == 0 { base.clone() } else { format!("{base}_{}", i + 1) }),
                ja4: Some(g.ja4.clone()),
                ..opt.clone()
            })?;
            // В режиме «все группы» соседние отпечатки — не замечание, а соседние профили.
            p.other_groups.clear();
            p.notes.retain(|n| !n.starts_with("в захвате есть ещё"));
            out.push(p);
        }
        Ok(out)
    }

    /// Измеренный первый flight сервера для соединений с SNI, содержащим
    /// `sni_contains` (обычно — собственный decoy-домен узла).
    ///
    /// Берутся только полные рукопожатия TLS 1.3: у возобновлённого сеанса нет
    /// `Certificate`, у TLS 1.2 записи не зашифрованы. Из них выбирается самый
    /// частый набор длин; если наборы различаются (балансировщик с разными
    /// цепочками), это возвращается в [`MeasuredFlight::distinct`].
    pub fn measured_flight(&self, sni_contains: &str) -> Result<MeasuredFlight, PcapError> {
        let mut counts: Vec<(Vec<usize>, usize)> = Vec::new();
        let mut total = 0usize;
        for h in &self.client_hellos {
            if !h.sni.as_ref().is_some_and(|s| s.contains(sni_contains)) || h.has_ext(0x0029) {
                continue;
            }
            let Some(f) = self.flight_for(h) else { continue };
            if f.server_hello.selected_version != Some(0x0304) || f.cover_records.is_empty() {
                continue;
            }
            total += 1;
            match counts.iter_mut().find(|(r, _)| *r == f.cover_records) {
                Some((_, n)) => *n += 1,
                None => counts.push((f.cover_records.clone(), 1)),
            }
        }
        counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let distinct = counts.len();
        let (records, seen) = counts.into_iter().next().ok_or(PcapError::NoServerFlight)?;
        Ok(MeasuredFlight { records, seen, total, distinct })
    }

    /// Эталонный `ClientHello` профиля: первое полное рукопожатие с тем же JA4.
    pub fn reference_hello(&self, profile: &CapturedProfile) -> Option<&ClientHelloInfo> {
        self.client_hellos
            .iter()
            .find(|h| ja4(h) == profile.ja4 && !h.has_ext(0x0029))
            .or_else(|| self.client_hellos.iter().find(|h| ja4(h) == profile.ja4))
    }

    /// Проверяет, что движок воспроизводит этот профиль (см. [`VerifyReport`]).
    pub fn verify_profile(&self, profile: &CapturedProfile, samples: usize) -> Option<VerifyReport> {
        Some(profile.verify(self.reference_hello(profile)?, samples))
    }
}

/// Разбирает захват целиком.
pub fn analyze(bytes: &[u8]) -> Result<Analysis, PcapError> {
    let packets = read_packets(bytes)?;
    Ok(analyze_packets(&packets))
}

/// Разбирает несколько файлов захвата как один (например, прогон с QUIC и прогон
/// с `--disable-quic`). Пакеты объединяются по времени.
pub fn analyze_many(files: &[&[u8]]) -> Result<Analysis, PcapError> {
    let mut all: Vec<Packet<'_>> = Vec::new();
    for f in files {
        all.extend(read_packets(f)?);
    }
    all.sort_by_key(|p| p.ts_nanos);
    Ok(analyze_packets(&all))
}

/// Разбор уже прочитанных пакетов (живой захват, `capture::record`).
pub fn analyze_packets(packets: &[Packet<'_>]) -> Analysis {
    let mut a = Analysis {
        packets: packets.len(),
        ..Default::default()
    };

    let mut qc = quic::QuicCollector::default();
    for pk in packets {
        if let Some(Transport::Udp(u)) = net::decode(pk.link_type, pk.data) {
            // Клиентский QUIC Initial: длинный заголовок типа Initial, версия 1, любой
            // порт (запись идёт и на нестандартные `--port`). Ответы серверов (с порта
            // 443) расшифровываются другими ключами и молча пропускаются.
            let p = u.payload;
            if p.len() >= 100
                && p[0] & 0xc0 == 0xc0
                && p[0] & 0x30 == 0
                && p[1..5] == quic::QUIC_V1.to_be_bytes()
            {
                a.quic_initials += 1;
                qc.push(
                    pk.ts_nanos,
                    Endpoint { ip: u.src, port: u.sport },
                    Endpoint { ip: u.dst, port: u.dport },
                    u.payload,
                );
            }
        }
    }
    let (quic_flows, skipped_versions, undecryptable) = qc.finish();
    for v in skipped_versions {
        a.warnings.push(format!(
            "QUIC версии {v:#010x} не поддерживается (разбирается только версия 1)"
        ));
    }
    // Ответы серверов тоже Initial'ы, но другими ключами: их провал — норма, и о нём
    // стоит говорить, только если не нашлось ни одного клиентского.
    if undecryptable > 0 && quic_flows.is_empty() {
        a.warnings.push(format!("{undecryptable} QUIC Initial не расшифровались (повреждены или не QUIC)"));
    }
    a.quic_flows = quic_flows;

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
            if f.server_hello.selected_version == Some(0x0304) {
                if let Some(shape) = flow_shape(flow, &c_recs, c_first_app) {
                    a.flow_shapes.push(shape);
                }
            }
            a.server_flights.push(f);
        }
    }
    a.client_hellos.sort_by_key(|h| h.ts_nanos);
    a
}

/// Длины `ApplicationData` после рукопожатия TLS 1.3: у клиента — после
/// `Finished` (первая запись), у сервера — после первого flight'а и билетов.
fn flow_shape(flow: &Flow, c_recs: &[tls::RecordInfo], c_first_app: Option<u64>) -> Option<FlowShape> {
    let t_finished = c_first_app?;
    let up: Vec<u16> = c_recs
        .iter()
        .filter(|r| r.content_type == tls::CT_APPDATA)
        .skip(1) // Finished
        .map(|r| r.length)
        .collect();
    let s_recs = split_records(&flow.s2c);
    let mut down: Vec<u16> = s_recs
        .iter()
        .filter(|r| r.content_type == tls::CT_APPDATA && r.ts_nanos >= t_finished)
        .map(|r| r.length)
        .collect();
    // NewSessionTicket: пара небольших записей сразу после Finished клиента.
    let tickets = down.iter().take(2).take_while(|l| **l < 600).count();
    down.drain(..tickets);
    (!up.is_empty() || !down.is_empty()).then_some(FlowShape {
        client: flow.client,
        server: flow.server,
        up,
        down,
    })
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
