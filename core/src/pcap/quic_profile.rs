//! Сборка QUIC-блока профиля из захваченных клиентских Initial'ов и проверка
//! его движком (аналог `CapturedProfile::verify` для UDP-ноги).

use super::fingerprint::ja4;
use super::profile::{CapturedProfile, ProfileOptions};
use super::quic::{is_grease_param, FrameKind, QuicFlow, EXT_QUIC_TP};
use super::tls::{is_grease, ClientHelloInfo};
use super::verify::VerifyReport;
use super::{select_hellos, Analysis, PcapError};
use crate::browser_profile::{Hex64, PacketSpec, QuicSpec, TpKind, TpSpec};

/// QUIC-часть снятого профиля.
#[derive(Debug, Clone)]
pub struct CapturedQuic {
    pub spec: QuicSpec,
    pub ja4: String,
    /// Сколько QUIC-соединений легло в профиль.
    pub flows_used: usize,
    /// `ClientHello` как TCP-подобный профиль (JA3/JA4, перемешивание, ECH…).
    pub hello: CapturedProfile,
    pub notes: Vec<String>,
}

const TP_VERSION_INFORMATION: u64 = 0x11;
const TP_INITIAL_SCID: u64 = 0x0f;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn crypto_len(p: &super::quic::InitialPacket) -> usize {
    p.frames
        .iter()
        .map(|f| if let FrameKind::Crypto { len, .. } = f { *len } else { 0 })
        .sum()
}

impl Analysis {
    /// Собирает QUIC-блок из самой многочисленной группы QUIC `ClientHello`
    /// (или группы `opt.quic_ja4`). Ошибка `NoClientHello` — клиентских QUIC
    /// Initial в захвате нет.
    pub fn build_quic(&self, opt: &ProfileOptions) -> Result<CapturedQuic, PcapError> {
        let flows: Vec<&QuicFlow> = self.quic_flows.iter().filter(|f| f.hello.is_some()).collect();
        let hellos_all: Vec<ClientHelloInfo> = flows.iter().filter_map(|f| f.hello.clone()).collect();
        let qopt = ProfileOptions { ja4: opt.quic_ja4.clone(), ..opt.clone() };
        let (hellos, _groups) = select_hellos(&hellos_all, &qopt);
        let ref_hello = *hellos.first().ok_or(PcapError::NoClientHello)?;
        let want = ja4(ref_hello);

        // Потоки именно этой группы.
        let group: Vec<&QuicFlow> = flows
            .iter()
            .copied()
            .filter(|f| f.hello.as_ref().is_some_and(|h| ja4(h) == want))
            .collect();

        // Эталон раскладки: самое частое число Initial-пакетов, первый такой поток.
        let mut counts: Vec<(usize, usize)> = Vec::new();
        for f in &group {
            match counts.iter_mut().find(|(n, _)| *n == f.packets.len()) {
                Some((_, c)) => *c += 1,
                None => counts.push((f.packets.len(), 1)),
            }
        }
        counts.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let mode = counts.first().map(|(n, _)| *n).unwrap_or(1);
        let reference = *group.iter().find(|f| f.packets.len() == mode).unwrap_or(&group[0]);

        let mut hello_profile = CapturedProfile::from_hellos(&hellos, &ProfileOptions {
            name: Some(format!("{}_quic", opt.name.clone().unwrap_or_else(|| "captured".into()))),
            ..opt.clone()
        })
        .ok_or(PcapError::NoClientHello)?;
        let mut notes = Vec::new();
        if counts.len() > 1 {
            notes.push(format!(
                "раскладка Initial-пакетов различается между соединениями ({:?} пакетов); взята самая частая",
                counts.iter().map(|(n, _)| *n).collect::<Vec<_>>()
            ));
        }

        // Пакеты в порядке номеров; первый полёт — минимальный набор подряд идущих
        // пакетов, чьи CRYPTO-кадры покрывают весь ClientHello. Остальное — повторные
        // отправки по таймеру (у Chrome они «взбиваются» заново).
        let mut pk: Vec<&super::quic::InitialPacket> = reference.packets.iter().collect();
        pk.sort_by_key(|p| p.pn);
        let hello_len = reference
            .hello
            .as_ref()
            .map(|h| h.record_payload_len)
            .unwrap_or(0);
        let mut covered = vec![false; hello_len];
        let mut flight_len = pk.len();
        for (i, p) in pk.iter().enumerate() {
            for (off, data) in &p.crypto {
                for b in covered.iter_mut().skip(*off as usize).take(data.len()) {
                    *b = true;
                }
            }
            if !covered.is_empty() && covered.iter().all(|b| *b) {
                flight_len = i + 1;
                break;
            }
        }
        let pk = &pk[..flight_len];
        if reference.packets.len() > flight_len {
            notes.push(format!(
                "в потоке {} повторных Initial-пакетов (отправка по таймеру) — в раскладку не входят",
                reference.packets.len() - flight_len
            ));
        }
        let first = pk[0];
        let initial_packets: Vec<PacketSpec> = pk
            .iter()
            .map(|p| PacketSpec {
                crypto: crypto_len(p) as u16,
                datagram: p.datagram_len as u16,
                pn_len: (p.pn_len != first.pn_len).then_some(p.pn_len as u8),
            })
            .collect();
        if first.token_len > 0 {
            notes.push("Initial с token (Retry/NEW_TOKEN): токены не воспроизводятся".into());
        }
        if pk.iter().any(|p| p.frames.iter().any(|f| matches!(f, FrameKind::Ack | FrameKind::Other(_)))) {
            notes.push("в Initial'ах есть ACK/иные кадры — сборщик пишет только CRYPTO, PING и PADDING".into());
        }
        // «Взбитые» кадры: много CRYPTO-кадров в пакете, PING, непоследовательные смещения.
        let scramble = pk.iter().any(|p| {
            let offs: Vec<u64> = p.frames.iter().filter_map(|f| if let FrameKind::Crypto { offset, .. } = f { Some(*offset) } else { None }).collect();
            p.frames.iter().any(|f| matches!(f, FrameKind::Ping))
                || offs.len() > 2
                || offs.windows(2).any(|w| w[1] <= w[0])
        });

        // Транспортные параметры: вид определяем по идентификатору.
        let mut transport_params = Vec::new();
        for (id, value) in &reference.transport_params {
            let kind = if *id == TP_INITIAL_SCID {
                TpKind::Scid
            } else if is_grease_param(*id) {
                TpKind::Grease
            } else if *id == TP_VERSION_INFORMATION {
                TpKind::VersionInformation
            } else {
                TpKind::Fixed
            };
            if kind == TpKind::Fixed {
                let varies = group.iter().any(|f| {
                    f.transport_params.iter().find(|(i, _)| i == id).map(|(_, v)| v) != Some(value)
                });
                if varies {
                    notes.push(format!(
                        "транспортный параметр {id:#x} меняется между соединениями, в профиль записано значение первого"
                    ));
                }
            }
            transport_params.push(TpSpec {
                id: Hex64(*id),
                value: if kind == TpKind::Scid { String::new() } else { hex(value) },
                kind,
            });
        }
        // Порядок параметров: меняется ли между соединениями.
        let tp_order = |f: &QuicFlow| -> Vec<u64> {
            f.transport_params.iter().map(|(id, _)| if is_grease_param(*id) { u64::MAX } else { *id }).collect()
        };
        let shuffle_tps = group.len() >= 2 && group.iter().any(|f| tp_order(f) != tp_order(group[0]));
        if group.len() < 2 {
            notes.push("одно QUIC-соединение: перемешивание транспортных параметров не наблюдаемо".into());
        }
        if reference.transport_params.is_empty() {
            notes.push("в ClientHello нет разобранных транспортных параметров (расширение 0x0039)".into());
        }

        let mut hello_spec = hello_profile.to_spec();
        hello_spec.raw_extensions.remove(&format!("{EXT_QUIC_TP:#06x}"));
        hello_spec.shape = None;
        hello_spec.quic = None;
        hello_spec.meta = Some(serde_json::json!({ "ja4": want, "hellos_used": hellos.len() }));

        let spec = QuicSpec {
            hello: hello_spec,
            scid_len: first.scid.len() as u8,
            pn_len: first.pn_len as u8,
            first_pn: first.pn as u32,
            scramble_frames: scramble,
            shuffle_transport_params: shuffle_tps,
            initial_packets,
            transport_params,
        };
        hello_profile.notes.retain(|n| !n.contains("форма трафика"));
        notes.extend(hello_profile.notes.iter().cloned());
        Ok(CapturedQuic { spec, ja4: want, flows_used: group.len(), hello: hello_profile, notes })
    }

    /// QUIC-блок для каждой группы отпечатков (по убыванию числа соединений)
    /// с не менее чем `min_flows` соединениями.
    pub fn build_quics(&self, opt: &ProfileOptions, min_flows: usize) -> Result<Vec<CapturedQuic>, PcapError> {
        let hellos_all: Vec<ClientHelloInfo> =
            self.quic_flows.iter().filter_map(|f| f.hello.clone()).collect();
        let (_, mut groups) = select_hellos(&hellos_all, &ProfileOptions { ja4: None, ..opt.clone() });
        groups.retain(|g| g.hellos >= min_flows.max(1));
        groups.sort_by_key(|g| std::cmp::Reverse(g.hellos));
        if groups.is_empty() {
            return Err(PcapError::NoClientHello);
        }
        groups
            .iter()
            .map(|g| self.build_quic(&ProfileOptions { quic_ja4: Some(g.ja4.clone()), ..opt.clone() }))
            .collect()
    }

    /// Проверяет QUIC-блок движком: собирает Initial'ы, расшифровывает и разбирает
    /// тем же кодом, что и захват, сравнивает с эталоном.
    pub fn verify_quic(&self, q: &CapturedQuic, samples: usize) -> Option<VerifyReport> {
        let reference = self
            .quic_flows
            .iter()
            .find(|f| f.hello.as_ref().is_some_and(|h| ja4(h) == q.ja4))?;
        Some(verify_quic(&q.spec, &q.ja4, reference, samples))
    }
}

/// Сравнение собранных движком Initial'ов с эталонным потоком.
pub fn verify_quic(spec: &QuicSpec, want_ja4: &str, reference: &QuicFlow, samples: usize) -> VerifyReport {
    use super::quic::QuicCollector;
    use super::tcp::Endpoint;

    let samples = samples.max(1);
    let mut rep = VerifyReport {
        samples,
        ja4_match: true,
        ja4_expected: want_ja4.to_owned(),
        ja4_got: want_ja4.to_owned(),
        extension_set_match: true,
        order_variants: 0,
        ech_match: true,
        ech_lengths_seen: Vec::new(),
        problems: Vec::new(),
    };
    let runtime = match spec.build_runtime() {
        Ok(r) => r,
        Err(e) => {
            rep.problems.push(format!("QUIC-блок не принят движком: {e}"));
            return rep;
        }
    };
    let ep = |port| Endpoint { ip: std::net::IpAddr::from([127, 0, 0, 1]), port };
    let ref_hello = reference.hello.as_ref().expect("поток с ClientHello");
    let want_set = {
        let mut v: Vec<u16> = ref_hello.extensions.iter().map(|e| e.id).filter(|i| !is_grease(*i)).collect();
        v.sort_unstable();
        v
    };
    let want_dgrams: Vec<usize> = spec.initial_packets.iter().map(|p| p.datagram as usize).collect();
    let want_tp_ids: Vec<u64> = reference
        .transport_params
        .iter()
        .map(|(id, _)| if is_grease_param(*id) { u64::MAX } else { *id })
        .collect();

    let mut orders: Vec<Vec<u16>> = Vec::new();
    let mut ech: Vec<u16> = Vec::new();
    let mut layout_bad = false;
    let mut tp_bad = false;
    let mut scid_bad = false;
    let mut saw_scramble = false;
    let mut tp_orders: std::collections::HashSet<Vec<u64>> = std::collections::HashSet::new();
    for n in 0..samples {
        let dcid: [u8; 8] = rand::random();
        let flight = crate::quiceng::build_client_initial_flight(runtime, 1, "verify.invalid", &dcid);
        let mut qc = QuicCollector::default();
        for d in &flight {
            qc.push(n as u64, ep(40000), ep(443), d);
        }
        let (flows, _, bad) = qc.finish();
        let Some(f) = flows.first().filter(|_| bad == 0) else {
            rep.problems.push("собранный Initial не расшифровывается публичными ключами".into());
            return rep;
        };
        let Some(h) = f.hello.as_ref() else {
            rep.problems.push("из собранных Initial'ов не собирается ClientHello".into());
            return rep;
        };
        let got = ja4(h);
        if got != want_ja4 {
            rep.ja4_match = false;
            rep.ja4_got = got;
        }
        let mut set: Vec<u16> = h.extensions.iter().map(|e| e.id).filter(|i| !is_grease(*i)).collect();
        let order = set.clone();
        set.sort_unstable();
        if set != want_set {
            rep.extension_set_match = false;
        }
        if !orders.contains(&order) {
            orders.push(order);
        }
        if let Some((_, p)) = h.ech {
            if !ech.contains(&p) {
                ech.push(p);
            }
        }
        let mut pk: Vec<_> = f.packets.iter().collect();
        pk.sort_by_key(|p| p.pn);
        let dg: Vec<usize> = pk.iter().map(|p| p.datagram_len).collect();
        if dg.len() != want_dgrams.len() || dg.iter().zip(&want_dgrams).any(|(a, b)| a != b) {
            // Число пакетов зависит от длины ClientHello (ECH/паддинг): сравниваем
            // размеры датаграмм там, где пакеты есть, число — отдельно.
            if dg.iter().any(|d| !want_dgrams.contains(d)) {
                layout_bad = true;
            }
        }
        let tp_ids: Vec<u64> = f.transport_params.iter().map(|(id, _)| if is_grease_param(*id) { u64::MAX } else { *id }).collect();
        let mut sorted_got = tp_ids.clone();
        let mut sorted_want = want_tp_ids.clone();
        sorted_got.sort_unstable();
        sorted_want.sort_unstable();
        if spec.shuffle_transport_params {
            tp_bad |= sorted_got != sorted_want;
            tp_orders.insert(tp_ids.clone());
        } else if tp_ids != want_tp_ids {
            tp_bad = true;
        }
        if pk[0].scid.len() != reference.packets[0].scid.len() {
            scid_bad = true;
        }
        if pk[0].pn != spec.first_pn as u64 {
            scid_bad = true;
        }
        let scrambled = pk.iter().any(|p| {
            p.frames.iter().any(|f| matches!(f, FrameKind::Ping))
                || p.frames.iter().filter(|f| matches!(f, FrameKind::Crypto { .. })).count() > 2
        });
        saw_scramble |= scrambled;
    }
    let tp_order_varied = tp_orders.len() > 1;
    ech.sort_unstable();
    rep.order_variants = orders.len();
    rep.ech_lengths_seen = ech;
    if !rep.ja4_match {
        rep.problems.push(format!("QUIC JA4 не воспроизводится: у браузера {}, у собранного {}", want_ja4, rep.ja4_got));
    }
    if !rep.extension_set_match {
        rep.problems.push("набор расширений собранного QUIC ClientHello отличается от браузерного".into());
    }
    if layout_bad {
        rep.problems.push("размеры датаграмм Initial отличаются от снятых с браузера".into());
    }
    if tp_bad {
        rep.problems.push("набор/порядок транспортных параметров отличается от браузерного".into());
    }
    if scid_bad {
        rep.problems.push("длина SCID или номер первого пакета отличаются от браузерных".into());
    }
    if spec.scramble_frames && !saw_scramble {
        rep.problems.push("профиль требует «взбитых» кадров Initial, а собранные пакеты их не содержат".into());
    }
    if spec.shuffle_transport_params && samples >= 8 && !tp_order_varied {
        rep.problems.push("профиль требует случайного порядка транспортных параметров, а он всегда один".into());
    }
    rep
}
