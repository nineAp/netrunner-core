//! Инструментальные эмиттеры для РУЧНОЙ проверки формата (не прод-путь).
//!
//! Гейтится фичей `dev-dump` (см. `Cargo.toml`) — в обычные сборки/тесты не
//! попадает. Существует ради Этапа 4 исследования: убедиться сторонним
//! парсером (Wireshark/`tshark -Y quic`), что наш QUIC Initial —
//! **настоящий** QUIC, а не только по нашему собственному тесту.
//!
//! Использование см. в `examples/quic_initial_dump.rs`.

/// Демо-CID для проверки в Wireshark. Прод-путь (`build_decorative_initial`)
/// шлёт SCID нулевой длины, как Chrome; здесь SCID НЕнулевой — только чтобы
/// tshark в синтетическом (однонаправленном) захвате смог связать клиентский и
/// серверный Initial и вывести ключи серверного пакета из исходного DCID. На
/// сам формат/крипту это не влияет.
const DEMO_DCID: [u8; 8] = [0x11u8; 8];
const DEMO_SCID: [u8; 8] = [0x22u8; 8];

/// Клиентский QUIC Initial. Должен расшифровываться публичными Initial-ключами и
/// разбираться в валидный `ClientHello` с ALPN `h3`, `quic_transport_parameters`
/// и заданным SNI (bug #9/#10).
pub fn quic_client_initial(sni: &str) -> Vec<u8> {
    crate::quiceng::build_client_initial(
        &crate::quiceng::QuicProfile::CHROME,
        sni,
        &DEMO_DCID,
        &DEMO_SCID,
    )
    .to_vec()
}

/// Серверный декоративный flight (Initial с ACK+ServerHello, затем Handshake) —
/// ключи выводятся из исходного клиентского DCID, DCID ответа = SCID клиента
/// (bug #12).
pub fn quic_server_flight() -> Vec<Vec<u8>> {
    crate::quiceng::build_server_initial_flight(
        &crate::quiceng::QuicProfile::CHROME,
        &DEMO_DCID,
        &DEMO_SCID,
    )
    .into_iter()
    .map(|b| b.to_vec())
    .collect()
}
