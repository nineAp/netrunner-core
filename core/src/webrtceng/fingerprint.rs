//! Профиль RTP/SRTP-отпечатка — тот же приём, что
//! [`crate::tlseng::BrowserProfile`] и [`crate::quiceng::QuicProfile`],
//! только для полей кодека: тип полезной нагрузки (RTP `PT`), частота
//! дискретизации и приращение таймстампа на пакет.
//!
//! **Честно.** Значения — типичные для WebRTC-стека браузеров (Opus,
//! динамический payload type 111, 48 кГц, кадры по 20 мс), но не сняты с
//! живого захвата конкретного продукта (Meet/Zoom/Discord у каждого свой
//! набор — см. `docs/UDP_LEG_RESEARCH.md` §5.4, открытый вопрос №1). Это
//! отправная точка, а не калиброванная мимикрия.

pub(crate) struct WebrtcProfile {
    /// RTP payload type (RFC 3551 §6: 96..127 — динамический диапазон,
    /// значение согласовывается в SDP; 111 — общепринятое де-факто значение
    /// для Opus в браузерных стеках).
    pub(crate) payload_type: u8,
    /// Частота дискретизации в Гц — определяет масштаб приращения таймстампа.
    pub(crate) clock_rate: u32,
    /// На сколько отсчётов увеличивается RTP timestamp на каждый пакет.
    /// Для Opus при кадрах 20 мс и 48 кГц: `48000 * 0.020 = 960`.
    pub(crate) timestamp_increment: u32,
}

impl WebrtcProfile {
    pub(crate) const OPUS_48K: Self = Self {
        payload_type: 111,
        clock_rate: 48_000,
        timestamp_increment: 960,
    };

    /// Видеопрофиль (VP8, динамический PT=96, тактовая 90 кГц — RFC 7741 §6.1).
    /// Именно он используется физической ногой: большие пакеты (~1.2 КБ) с
    /// timestamp по РЕАЛЬНОМУ времени и заголовочным расширением (X=1)
    /// правдоподобнее для медиатрафика в мегабиты, чем аудио-Opus с крошечными
    /// кадрами (bug #16). `timestamp_increment` для видео не используется —
    /// timestamp считается из тактовой и настоящего времени (см. `WebrtcTx`).
    pub(crate) const VP8_VIDEO: Self = Self {
        payload_type: 96,
        clock_rate: 90_000,
        timestamp_increment: 0,
    };

    /// Пул из одного профиля — та же причина, что у `BrowserProfile::ALL` и
    /// `QuicProfile::ALL`: расширять пул стоит только откалиброванными по
    /// живому захвату профилями, а не количеством ради количества.
    pub(crate) const ALL: &'static [&'static Self] = &[&Self::VP8_VIDEO];

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
        let a = WebrtcProfile::for_session("abc") as *const WebrtcProfile;
        let b = WebrtcProfile::for_session("abc") as *const WebrtcProfile;
        assert_eq!(a, b);
    }
}
