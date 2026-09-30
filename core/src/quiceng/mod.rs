//! # Движок QUIC-маскировки (`quiceng`)
//!
//! Ровно та же задача, что решает [`crate::tlseng`] для TCP-ноги, но для
//! UDP: чтобы туннельный трафик по форме был неотличим от QUIC/HTTP-3.
//! Устроен по образу и подобию `tlseng` — тот же принцип «профиль +
//! отдельный слой (де)сериализации», та же честность в комментариях насчёт
//! того, что калибровано по спецификации, а что нужно сверять с живым
//! захватом.
//!
//! ## Состав блока
//!
//! | Файл            | Ответственность                                                      |
//! |------------------|----------------------------------------------------------------------|
//! | [`fingerprint`]  | [`QuicProfile`] — версия QUIC, длина Connection ID.                  |
//! | [`header`]       | [`header::QuicTx`]/[`header::QuicRx`] — 1-RTT пакет (RFC 9000 §17.3.1) + header protection (RFC 9001 §5.4) поверх [`crate::nrxp::datagram`]. |
//! | [`initial`]      | Клиентский Initial-пакет (RFC 9000 §17.2.2), несущий наш `ClientHello`. |
//! | [`real`]         | Точка расширения под настоящий QUIC (`DecoyMode::SelfHosted`) — не реализовано, см. докстринг файла. |
//!
//! ## Две маскировки, как и у TCP-ноги
//!
//! Ровно то же различие, что [`crate::tlseng::decoy::DecoyMode`] уже проводит
//! для TCP: если decoy — чужой сайт (`Relay`), у нас нет ни его QUIC-стека,
//! ни его сертификата, и остаётся мимикрия ([`QuicMode::Mimicry`]: наш AEAD,
//! наш `ClientHello`, форма QUIC). Если decoy — домен самого узла
//! (`SelfHosted`), сертификат настоящий, и можно говорить настоящим QUIC
//! ([`QuicMode::Real`], см. [`real`] за тем, что там пока не реализовано).
//!
//! ## Приёмник в вызывающем коде обязан переиспользовать [`crate::tlseng`]
//!
//! `initial::build_client_initial` намеренно строит `ClientHello` через
//! [`crate::nrxp::TlsBridge::wrap_client_hello`] — тот же вызов, что и
//! TCP-нога. Initial-пакеты QUIC расшифровывает кто угодно (ключи выводятся
//! из публичной соли и открытого Connection ID, см. докстринг [`initial`]),
//! поэтому наш `ClientHello` внутри обязан быть той же настоящей мимикрией
//! под браузер, а не отдельной, хуже откалиброванной подделкой.

mod client_hello;
mod fingerprint;
mod header;
mod initial;
#[cfg(not(target_arch = "wasm32"))]
mod real;

pub(crate) use fingerprint::QuicProfile;
pub(crate) use header::{QuicRx, QuicTx};
pub(crate) use initial::{build_client_initial, build_server_initial_flight};
// Никто пока не вызывает — `QuicMode::Real` не подключён к жизненному циклу
// ноги (см. докстринг модуля `real`, там же — что именно для этого нужно).
// Экспорт оставлен как обозначенная точка расширения, а не удалён вместе с
// предупреждением: `real_dial`/`NotYetImplemented`/`RealQuicTarget` — ровно
// то, что понадобится вызвать первым, когда до этого дойдут руки.
#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_imports)]
pub(crate) use real::{dial as real_dial, NotYetImplemented, RealQuicTarget};

use crate::tlseng::decoy::DecoyMode;

/// Как эта UDP-нога говорит "QUIC": честно или взаймы (см. докстринг модуля,
/// раздел "Две маскировки").
pub(crate) enum QuicMode {
    /// Сайт-донор чужой — изображаем QUIC поверх собственного AEAD.
    Mimicry,
    /// Домен наш — говорим настоящим протоколом (см. [`real`], пока не
    /// реализовано).
    Real,
}

impl QuicMode {
    pub(crate) fn for_decoy(mode: DecoyMode) -> Self {
        match mode {
            DecoyMode::Relay => Self::Mimicry,
            DecoyMode::SelfHosted => Self::Real,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_decoy_means_mimicry_and_self_hosted_means_real() {
        assert!(matches!(
            QuicMode::for_decoy(DecoyMode::Relay),
            QuicMode::Mimicry
        ));
        assert!(matches!(
            QuicMode::for_decoy(DecoyMode::SelfHosted),
            QuicMode::Real
        ));
    }
}
