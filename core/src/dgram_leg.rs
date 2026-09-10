//! Выбор движка мимикрии для UDP-ноги: [`crate::quiceng`] или
//! [`crate::webrtceng`], с равным приоритетом и без регулярности в
//! чередовании — ровно то, что зафиксировано в
//! `docs/UDP_LEG_RESEARCH.md` §1/§2.
//!
//! Здесь — **только** сама политика выбора. Она сознательно не завязана на
//! неё жизненный цикл ноги (когда его подъём/эвикт/фолбэк на raw UDP или на
//! TCP — следующий шаг, требующий трогать `net::connection::muxer`), поэтому
//! это отдельный, маленький, легко тестируемый файл, а не метод где-то
//! внутри `Muxer`.
//!
//! ## Почему обычный `Bernoulli(0.5)`, а не что-то более "случайное"
//!
//! Честная монета уже не создаёт паттерна — паттерн создаёт именно
//! round-robin (строгое чередование quic/webrtc/quic/webrtc — само по себе
//! наблюдаемый признак, арифметическая прогрессия по времени, ровно как
//! было с равномерным разбросом старта TCP-ног, см.
//! `ClientHandler::connect`). Любая попытка "улучшить" случайность (не
//! допускать двух одинаковых подряд, выравнивать доли по факту) вносит
//! корреляцию, которой у честной монеты нет, — то есть делает
//! последовательность БОЛЕЕ предсказуемой, а не менее. Поэтому здесь именно
//! `rand`, без какой-либо балансировки.
//!
//! Источник случайности — обычный CSPRNG рантайма, не что-то выведенное из
//! секрета сессии: HKDF от `auth_key`/`datagram_root` работало бы без
//! отдельного RNG, но тогда выбор стал бы детерминированной функцией от
//! материала, который в некоторых сценариях компрометации известен —
//! обычный RNG проще и не хуже.

use bytes::Bytes;
use rand::RngExt;

use crate::nrxp::{Frame, FrameType, TlsError};
use crate::{quiceng, rawdgram, webrtceng};

/// Какой движок мимикрии используется для одной попытки установки UDP-ноги.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DgramEngineKind {
    Quic,
    WebRtc,
}

/// Исходящая сторона UDP-ноги, независимо от того, какой движок выбран —
/// единая точка вызова для клиентской/серверной оркестровки (`net::connection`),
/// которой не нужно знать, какой конкретно это движок, только что кадр надо
/// отправить.
pub(crate) enum DgramTx {
    Quic(quiceng::QuicTx),
    WebRtc(webrtceng::WebrtcTx),
    Raw(rawdgram::RawDgramTx),
}

impl DgramTx {
    pub(crate) fn seal(
        &mut self,
        stream_id: u32,
        frame_type: FrameType,
        payload: Bytes,
    ) -> Result<Bytes, TlsError> {
        match self {
            // `marker=false`: без мимикрии всплесков (см.
            // `docs/UDP_LEG_RESEARCH.md` §9) отмечать нечего — ни один
            // реальный кадр кодека мы не производим, а значит и границы
            // кадра, которую отмечает этот бит, у нас тоже нет.
            Self::WebRtc(tx) => tx.seal(stream_id, frame_type, payload, false),
            Self::Quic(tx) => tx.seal(stream_id, frame_type, payload),
            Self::Raw(tx) => tx.seal(stream_id, frame_type, payload),
        }
    }
}

/// Входящая сторона UDP-ноги — зеркало [`DgramTx`].
pub(crate) enum DgramRx {
    Quic(quiceng::QuicRx),
    WebRtc(webrtceng::WebrtcRx),
    Raw(rawdgram::RawDgramRx),
}

impl DgramRx {
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<Frame, TlsError> {
        match self {
            Self::Quic(rx) => rx.open(wire),
            Self::WebRtc(rx) => rx.open(wire).map(|(_header, frame)| frame),
            Self::Raw(rx) => rx.open(wire),
        }
    }
}

/// Куда клиент кладёт свой Destination Connection ID в исходящих
/// `quiceng`-пакетах (и, зеркально, где сервер его ищет во входящих от
/// клиента) — первая половина `leg_token`. Вторая половина — то же самое
/// для направления сервер→клиент. Деление пополам — не что-то, что нужно
/// пересчитывать: обе стороны выводят один и тот же 16-байтный `leg_token`
/// независимо (см. `crypto::datagram_keys`), поэтому синхронизировать
/// достаточно само соглашение о том, какая половина чья, — и оно здесь,
/// в одном месте, а не продублировано в клиентском и серверном коде.
pub(crate) fn quic_dcid_client(leg_token: &[u8; 16]) -> [u8; 8] {
    leg_token[0..8]
        .try_into()
        .expect("slice is exactly 8 bytes")
}

pub(crate) fn quic_dcid_server(leg_token: &[u8; 16]) -> [u8; 8] {
    leg_token[8..16]
        .try_into()
        .expect("slice is exactly 8 bytes")
}

/// То же самое для RTP SSRC — 4 байта вместо 8, из ДРУГОЙ части токена
/// (0..4 / 4..8), чтобы `webrtceng` и `quiceng`, если бы им пришлось жить в
/// одной сессии одновременно, не делили один и тот же под-срез. Сейчас это
/// не происходит (выбирается ровно один движок на попытку), но соглашение
/// не завязано на это специально.
pub(crate) fn webrtc_ssrc_client(leg_token: &[u8; 16]) -> u32 {
    u32::from_be_bytes(
        leg_token[0..4]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    )
}

pub(crate) fn webrtc_ssrc_server(leg_token: &[u8; 16]) -> u32 {
    u32::from_be_bytes(
        leg_token[4..8]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    )
}

/// Бросает монету. Вызывается один раз на попытку установки UDP-ноги (см.
/// докстринг модуля и `docs/UDP_LEG_RESEARCH.md` §2 за обсуждением
/// альтернативных горизонтов фиксации выбора — "раз на сессию" против
/// "на каждую попытку" — решение о том, какой из них использовать при
/// подключении жизненного цикла, ещё не принято).
pub(crate) fn choose_engine() -> DgramEngineKind {
    if rand::rng().random_bool(0.5) {
        DgramEngineKind::Quic
    } else {
        DgramEngineKind::WebRtc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demux_ids_are_client_server_symmetric_and_distinct() {
        let token = [0xAAu8; 16]; // не 0/не константный паттерн байт был бы честнее, но здесь важна только позиция среза
        let mut token = token;
        for (i, b) in token.iter_mut().enumerate() {
            *b = i as u8;
        }

        assert_eq!(quic_dcid_client(&token), [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(quic_dcid_server(&token), [8, 9, 10, 11, 12, 13, 14, 15]);
        assert_ne!(quic_dcid_client(&token), quic_dcid_server(&token));

        assert_eq!(webrtc_ssrc_client(&token), u32::from_be_bytes([0, 1, 2, 3]));
        assert_eq!(webrtc_ssrc_server(&token), u32::from_be_bytes([4, 5, 6, 7]));
        assert_ne!(webrtc_ssrc_client(&token), webrtc_ssrc_server(&token));
    }

    #[test]
    fn both_engines_appear_over_many_draws() {
        // Не строгая гарантия равномерности (это честная монета, не
        // детерминированная развёртка), но у обоих вариантов есть
        // практически равная возможность появиться — 200 бросков с шансом
        // не увидеть один из вариантов исчезающе мал (2 × 0.5^200).
        let mut saw_quic = false;
        let mut saw_webrtc = false;
        for _ in 0..200 {
            match choose_engine() {
                DgramEngineKind::Quic => saw_quic = true,
                DgramEngineKind::WebRtc => saw_webrtc = true,
            }
        }
        assert!(saw_quic, "expected at least one Quic draw in 200 attempts");
        assert!(
            saw_webrtc,
            "expected at least one WebRtc draw in 200 attempts"
        );
    }
}
