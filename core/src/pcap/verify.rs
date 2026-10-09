//! Самопроверка снятого профиля: «воспроизводит ли наш сборщик то, что мы
//! увидели у браузера».
//!
//! Профиль, прошедший `validate`, лишь **применим** к протоколу. Здесь проверяется
//! другое: `ClientHello`, который движок соберёт по этому профилю, разбирается
//! тем же парсером, что и захват, и сравнивается с эталоном. Расхождение (другой
//! JA4, потерянное расширение, не тот набор длин ECH) видно сразу при записи, а не
//! на первом соединении через DPI.

use super::fingerprint::{ja3_hash, ja4};
use super::profile::CapturedProfile;
use super::tcp::{Endpoint, Stream};
use super::tls::{handshake_messages, is_grease, parse_client_hello, split_records, ClientHelloInfo};
use crate::crypto::SessionKeys;
use crate::tlseng::ClientHello;

/// Сколько `ClientHello` собирать при проверке: хватает, чтобы увидеть
/// перемешивание и разброс длины ECH.
pub const DEFAULT_SAMPLES: usize = 24;

/// Итог проверки.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub samples: usize,
    /// JA4 эталона и собранных hello совпали во всех образцах.
    pub ja4_match: bool,
    pub ja4_expected: String,
    pub ja4_got: String,
    /// Набор расширений (без GREASE) совпал с эталоном во всех образцах.
    pub extension_set_match: bool,
    /// Сколько различных порядков расширений встретилось.
    pub order_variants: usize,
    /// Все длины ECH-payload принадлежат наблюдавшемуся набору.
    pub ech_match: bool,
    pub ech_lengths_seen: Vec<u16>,
    /// Что не сошлось (пусто — профиль воспроизводится).
    pub problems: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Разбирает `ClientHello` из готовых байт TLS-записи (то, что отдаёт сборщик).
pub(crate) fn parse_wire_hello(wire: &[u8]) -> Option<ClientHelloInfo> {
    let stream = Stream {
        bytes: wire.to_vec(),
        marks: vec![(0, 0)],
        gap: false,
        syn: false,
    };
    let ep = |port| Endpoint {
        ip: std::net::IpAddr::from([127, 0, 0, 1]),
        port,
    };
    let recs = split_records(&stream);
    let msgs = handshake_messages(&stream, &recs);
    msgs.iter().find_map(|m| parse_client_hello(m, ep(1), ep(443)))
}

fn extension_set(h: &ClientHelloInfo) -> Vec<u16> {
    let mut v: Vec<u16> = h
        .extensions
        .iter()
        .map(|e| e.id)
        .filter(|id| !is_grease(*id))
        .collect();
    v.sort_unstable();
    v
}

impl CapturedProfile {
    /// Собирает `samples` `ClientHello` по этому профилю и сравнивает с эталоном.
    /// `reference` — эталонное hello из захвата.
    pub fn verify(&self, reference: &ClientHelloInfo, samples: usize) -> VerifyReport {
        let samples = samples.max(1);
        let mut rep = VerifyReport {
            samples,
            ja4_match: true,
            ja4_expected: self.ja4.clone(),
            ja4_got: self.ja4.clone(),
            extension_set_match: true,
            order_variants: 0,
            ech_match: true,
            ech_lengths_seen: Vec::new(),
            problems: Vec::new(),
        };
        let Some(profile) = self.to_browser_profile() else {
            rep.problems.push("профиль не принят движком (см. profile check)".into());
            return rep;
        };

        let want_set = extension_set(reference);
        let want_ja3 = ja3_hash(reference);
        let mut orders: Vec<Vec<u16>> = Vec::new();
        let mut ech: Vec<u16> = Vec::new();
        let mut ja3_same = true;

        for _ in 0..samples {
            let keys = SessionKeys::new(true);
            let wire = ClientHello::make_client_hello(profile, "verify.invalid", &keys);
            let Some(got) = parse_wire_hello(&wire) else {
                rep.problems.push("собранный ClientHello не разбирается парсером".into());
                return rep;
            };
            let j = ja4(&got);
            if j != self.ja4 {
                rep.ja4_match = false;
                rep.ja4_got = j;
            }
            if extension_set(&got) != want_set {
                rep.extension_set_match = false;
            }
            if ja3_hash(&got) != want_ja3 {
                ja3_same = false;
            }
            let order: Vec<u16> = got.extensions.iter().map(|e| e.id).filter(|i| !is_grease(*i)).collect();
            if !orders.contains(&order) {
                orders.push(order);
            }
            if let Some((_, payload)) = got.ech {
                if !ech.contains(&payload) {
                    ech.push(payload);
                }
            }
        }
        ech.sort_unstable();
        rep.order_variants = orders.len();
        rep.ech_lengths_seen = ech.clone();

        if !rep.ja4_match {
            rep.problems.push(format!(
                "JA4 не воспроизводится: у браузера {}, у собранного {}",
                self.ja4, rep.ja4_got
            ));
        }
        if !rep.extension_set_match {
            rep.problems.push("набор расширений собранного hello отличается от браузерного".into());
        }
        if self.shuffle_extensions {
            // Порядков 18!, образцов мало: хотя бы два разных обязаны встретиться.
            if samples >= 8 && rep.order_variants < 2 {
                rep.problems.push("профиль требует перемешивания, а порядок расширений всегда один".into());
            }
        } else {
            if rep.order_variants > 1 {
                rep.problems.push("профиль без перемешивания, а порядок расширений меняется".into());
            }
            if !ja3_same {
                rep.problems.push("JA3 отличается от браузерного при неизменном порядке расширений".into());
            }
        }
        if !self.ech_payload_lengths.is_empty() {
            rep.ech_match = ech.iter().all(|l| self.ech_payload_lengths.contains(l));
            if !rep.ech_match {
                rep.problems.push(format!(
                    "длины ECH вне наблюдавшегося набора {:?}: {:?}",
                    self.ech_payload_lengths, ech
                ));
            }
        }
        rep
    }
}
