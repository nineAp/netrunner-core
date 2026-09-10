//! Профиль QUIC-отпечатка — тот же приём, что [`crate::tlseng::BrowserProfile`],
//! только для полей, которых у TLS-over-TCP не бывает: версия QUIC и политика
//! длины Destination Connection ID.
//!
//! **Честно, как и в `tlseng`.** Значения ниже не сняты с живого захвата —
//! это отправная точка, которую нужно сверить с `chrome://net-export`/qlog
//! реального Chrome прежде чем полагаться на них как на калиброванную
//! мимикрию (см. `docs/UDP_LEG_RESEARCH.md` §4.3/§7).

pub(crate) struct QuicProfile {
    /// Версия QUIC на проводе (RFC 9000 — версия 1).
    pub(crate) version: u32,
    /// Длина Destination Connection ID вне первого (Initial) пакета сессии —
    /// у short-header пакетов эта длина нигде на проводе не пишется, обе
    /// стороны обязаны знать её заранее (см. `ShortHeaderPacket::decode`).
    /// Chrome использует 8 байт.
    pub(crate) dcid_len: u8,
}

impl QuicProfile {
    pub(crate) const CHROME: Self = Self {
        version: 1,
        dcid_len: 8,
    };

    /// Пул из одного профиля — не недосмотр, та же причина, что у
    /// `BrowserProfile::ALL`: ротация имеет смысл только между профилями,
    /// каждый из которых сам по себе неотличим от живого браузера, а второй
    /// такой профиль здесь пока не откалиброван.
    pub(crate) const ALL: &'static [&'static Self] = &[&Self::CHROME];

    /// Один стабильный профиль на всю жизнь туннельной сессии — см.
    /// `BrowserProfile::for_session` за тем, почему смена отпечатка посреди
    /// сессии хуже константного отпечатка.
    pub(crate) fn for_session(session_id: &str) -> &'static Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session_id.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % Self::ALL.len();
        Self::ALL[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_session_is_deterministic() {
        let a = QuicProfile::for_session("abc") as *const QuicProfile;
        let b = QuicProfile::for_session("abc") as *const QuicProfile;
        assert_eq!(a, b);
    }
}
