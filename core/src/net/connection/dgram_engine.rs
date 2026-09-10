//! Оркестровка физической UDP-ноги.
//!
//! Две ПОЛНОСТЬЮ разные роли живут в одном файле, потому что они делят
//! почти весь низкоуровневый код (запечатывание/распечатывание кадров,
//! пишущий цикл, keepalive) и расходятся только в том, откуда берётся
//! адрес пира:
//!
//! - **Клиент** ([`attempt_client_datagram_leg`]) — один `connect()`-нутый
//!   сокет на единственного известного пира. Пробует ровно ОДИН движок
//!   мимикрии (см. [`crate::dgram_leg::choose_engine`]), при неудаче —
//!   голый UDP; при неудаче и этого — остаётся на TCP. Одна попытка на
//!   жизнь сессии, без агрессивных ретраев (см. `docs/UDP_LEG_RESEARCH.md` §1).
//! - **Сервер** ([`run_datagram_listener`]) — один общий сокет на ВСЕ
//!   сессии процесса; классифицирует входящую датаграмму по первому байту
//!   (диапазоны QUIC short header / RTP-подобных / всё остальное — см.
//!   `quiceng`/`webrtceng` за тем, откуда взялись именно эти границы),
//!   находит сессию по демультиплексирующему ключу в [`SessionManager`] и
//!   либо продолжает уже установленную ногу, либо поднимает её на первой же
//!   успешно расшифрованной датаграмме.
//!
//! ## Почему PING/PONG не через `StreamHandler`/`muxer.send_control`
//!
//! Тот путь заточен под TCP-семантику (`select_leg`, конкретная нога по
//! `leg_id` из `Muxer::legs`) — UDP-нога туда не входит вообще (см. докстринг
//! `Muxer::datagram_leg`). Поэтому у неё свой, полностью локальный
//! keepalive: читающая сторона, увидев `PING`, сама кладёt `PONG` в канал
//! пишущей стороны ЭТОЙ ЖЕ ноги, а не проксирует через общую инфраструктуру
//! TCP-контроля.
//!
//! ## Почему живость отмечается на КАЖДЫЙ кадр, а не только на PONG
//!
//! Нога, по которой прямо сейчас идут настоящие данные, очевидно жива —
//! ждать для этого отдельного PONG'а нет смысла (в отличие от TCP-ног,
//! которым нужно РАЗЛИЧАТЬ несколько ног по качеству — см.
//! `Muxer::selection_load_factor` — у UDP-ноги альтернатив для сравнения
//! нет, вопрос только "жива или нет").

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use netrunner_logger::{debug, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::crypto::DatagramKeyMaterial;
use crate::dgram_leg::{self, DgramEngineKind, DgramRx, DgramTx};
use crate::net::connection::connection::{DgramSessionEntry, SessionManager};
use crate::net::connection::handler::{RemoteOpener, StreamHandler};
use crate::net::connection::muxer::{MuxMessage, Muxer};
use crate::net::{NetworkConfig, DATAGRAM_LEG_HANDSHAKE_TIMEOUT};
use crate::nrxp::{DatagramRx as CoreDatagramRx, DatagramTx as CoreDatagramTx, Frame, FrameType};
use crate::{quiceng, rawdgram, webrtceng};

const PING: &[u8] = b"PING";
const PONG: &[u8] = b"PONG";
/// С запасом над максимальным реальным пакетом (заголовок + `nrxp::Frame` +
/// AEAD-тег редко подбирается к MTU) — не оптимизация, а простая защита от
/// обрезания при чтении.
const RECV_BUF_LEN: usize = 2048;

// ============================================================================
// Общее: как физически уходят исходящие датаграммы
// ============================================================================

/// У клиента сокет один и `connect()`-нут на единственного сервера — можно
/// просто `send()`. У сервера сокет один общий на все сессии, а адрес пира
/// каждой сессии свой и может меняться (роуминг за NAT) — поэтому читается
/// заново на каждую отправку, а не захватывается один раз.
enum DgramTransport {
    Connected(Arc<UdpSocket>),
    Shared(Arc<UdpSocket>, Arc<ArcSwap<SocketAddr>>),
}

impl DgramTransport {
    async fn send(&self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Connected(socket) => socket.send(bytes).await,
            Self::Shared(socket, peer) => socket.send_to(bytes, **peer.load()).await,
        }
    }
}

/// Пишущий цикл одной UDP-ноги (общий для клиента и сервера): раз в
/// [`crate::net::HEALTH_CHECK_INTERVAL`] шлёт `PING` (тот же интервал, что и
/// у TCP-ног — не заводим отдельную константу ради одной ноги; заодно это и
/// NAT-keepalive), плюс всё, что кладут в `control_rx`/`data_rx` (см.
/// `Muxer::send_to_network`/`select_udp_leg`). Завершается, когда закрыт
/// любой из каналов (`Muxer` сняла ногу) или отменён токен.
async fn run_datagram_writer(
    mut tx: DgramTx,
    transport: DgramTransport,
    mut control_rx: mpsc::Receiver<MuxMessage>,
    mut data_rx: mpsc::Receiver<MuxMessage>,
    token: CancellationToken,
) {
    let mut hb_interval = tokio::time::interval(crate::net::HEALTH_CHECK_INTERVAL);
    hb_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Первый тик у `interval` срабатывает немедленно — нам не нужен PING в
    // ту же миллисекунду, что и подъём ноги (первая настоящая датаграмма его
    // и так подтвердит).
    hb_interval.tick().await;

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = hb_interval.tick() => {
                if let Ok(sealed) = tx.seal(0, FrameType::Heartbeat, Bytes::from_static(PING)) {
                    let _ = transport.send(&sealed).await;
                }
            }
            msg = control_rx.recv() => {
                let Some(msg) = msg else { break };
                if let Ok(sealed) = tx.seal(msg.stream_id, msg.frame_type, msg.data) {
                    let _ = transport.send(&sealed).await;
                }
            }
            msg = data_rx.recv() => {
                let Some(msg) = msg else { break };
                if let Ok(sealed) = tx.seal(msg.stream_id, msg.frame_type, msg.data) {
                    let _ = transport.send(&sealed).await;
                }
            }
        }
    }
}

/// Решает, что делать с уже РАСШИФРОВАННЫМ кадром: `PING` — немедленно
/// отвечает `PONG` через `control_tx` этой же ноги; `PONG`/прочий
/// `Heartbeat` — не делает ничего сверх (живость отмечает вызывающий, см.
/// докстринг модуля); всё остальное — отдаёт `handler`'у, как и любой
/// другой кадр `UdpData` (см. `StreamHandler::handle` — он не знает и не
/// должен знать, по какому физическому транспорту приехал кадр).
///
/// Принимает уже открытый [`Frame`], а не сырые байты + `&mut DgramRx`,
/// намеренно: и клиентский читатель, и серверный демультиплексор ОБЯЗАНЫ
/// расшифровать датаграмму раньше, чем решат, установлена ли уже нога (см.
/// [`process_datagram`]) — двойной вызов `rx.open` на одну и ту же датаграмму
/// не только лишняя работа, а ещё и лишний шанс разъехаться в поведении
/// между "первой" и "уже установленной" веткой.
async fn dispatch_open_frame(
    frame: Frame,
    control_tx: &mpsc::Sender<MuxMessage>,
    handler: &StreamHandler,
) {
    if frame.header.frame_type == FrameType::Heartbeat {
        if frame.payload.as_ref() == PING {
            let _ = control_tx.try_send(MuxMessage {
                stream_id: 0,
                frame_type: FrameType::Heartbeat,
                data: Bytes::from_static(PONG),
            });
        }
    } else {
        handler.handle(frame).await;
    }
}

// ============================================================================
// Клиент
// ============================================================================

/// Собирает `(DgramTx, DgramRx)` конкретного движка мимикрии из корня
/// UDP-ноги. `is_client` решает, какую половину `leg_token` класть в СВОИ
/// исходящие пакеты (см. `dgram_leg::{quic_dcid_client,...}`).
fn build_mimicry_pair(
    kind: &DgramEngineKind,
    datagram_root: [u8; 32],
    is_client: bool,
) -> (DgramTx, DgramRx) {
    match kind {
        DgramEngineKind::Quic => {
            let tx_material = DatagramKeyMaterial::derive_from_root(datagram_root, is_client);
            let rx_material = DatagramKeyMaterial::derive_from_root(datagram_root, is_client);
            let leg_token = tx_material.leg_token();
            let hp_tx = tx_material.hp_key_tx();
            let hp_rx = rx_material.hp_key_rx();
            let dcid_out = if is_client {
                dgram_leg::quic_dcid_client(&leg_token)
            } else {
                dgram_leg::quic_dcid_server(&leg_token)
            };
            let tx = quiceng::QuicTx::new(
                CoreDatagramTx::new(tx_material),
                hp_tx,
                Bytes::copy_from_slice(&dcid_out),
            );
            let rx = quiceng::QuicRx::new(
                CoreDatagramRx::new(rx_material),
                hp_rx,
                quiceng::QuicProfile::CHROME.dcid_len as usize,
            );
            (DgramTx::Quic(tx), DgramRx::Quic(rx))
        }
        DgramEngineKind::WebRtc => {
            let tx_material = DatagramKeyMaterial::derive_from_root(datagram_root, is_client);
            let rx_material = DatagramKeyMaterial::derive_from_root(datagram_root, is_client);
            let leg_token = tx_material.leg_token();
            let ssrc_out = if is_client {
                dgram_leg::webrtc_ssrc_client(&leg_token)
            } else {
                dgram_leg::webrtc_ssrc_server(&leg_token)
            };
            let tx = webrtceng::WebrtcTx::new(
                CoreDatagramTx::new(tx_material),
                &webrtceng::WebrtcProfile::OPUS_48K,
                ssrc_out,
            );
            let rx = webrtceng::WebrtcRx::new(CoreDatagramRx::new(rx_material));
            (DgramTx::WebRtc(tx), DgramRx::WebRtc(rx))
        }
    }
}

fn build_raw_pair(datagram_root: [u8; 32], is_client: bool) -> (DgramTx, DgramRx) {
    let tx_material = DatagramKeyMaterial::derive_from_root(datagram_root, is_client);
    let rx_material = DatagramKeyMaterial::derive_from_root(datagram_root, is_client);
    (
        DgramTx::Raw(rawdgram::RawDgramTx::new(CoreDatagramTx::new(tx_material))),
        DgramRx::Raw(rawdgram::RawDgramRx::new(CoreDatagramRx::new(rx_material))),
    )
}

/// Шлёт первую (само-аутентифицирующую, см. `docs/UDP_LEG_RESEARCH.md` §1)
/// датаграмму и ждёт ЛЮБОЙ успешно расшифрованный ответ до
/// [`DATAGRAM_LEG_HANDSHAKE_TIMEOUT`]. `decorative_first` — для `quiceng`:
/// поддельный QUIC Initial-пакет, отправляется первым, но никогда не
/// обрабатывается сервером как содержательный (см. `quiceng::initial` за
/// тем, что настоящий QUIC вообще расшифровывает Initial кто угодно, а наш
/// сервер их попросту игнорирует — реальные ключи идут не оттуда).
async fn try_establish(
    mut tx: DgramTx,
    mut rx: DgramRx,
    socket: &UdpSocket,
    decorative_first: Option<Bytes>,
) -> Option<(DgramTx, DgramRx)> {
    if let Some(decorative) = decorative_first {
        let _ = socket.send(&decorative).await;
    }

    let hello = tx
        .seal(0, FrameType::Heartbeat, Bytes::from_static(PING))
        .ok()?;
    socket.send(&hello).await.ok()?;

    let mut buf = [0u8; RECV_BUF_LEN];
    let deadline = tokio::time::Instant::now() + DATAGRAM_LEG_HANDSHAKE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let n = tokio::time::timeout(remaining, socket.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        if rx.open(&buf[..n]).is_ok() {
            return Some((tx, rx));
        }
        // Мусор/повтор/не тот пакет — ждём дальше до дедлайна, не сдаёмся
        // из-за одной нераспознанной датаграммы (сеть уже что-то доставляет,
        // это обнадёживает больше, чем пугает).
    }
}

/// Точка входа клиента — см. докстринг модуля. Вызывается один раз на
/// сессию (см. `Muxer::try_claim_datagram_leg_token` в точке вызова,
/// `ClientHandler::establish_leg`), не переиспользуется при реконнекте
/// какой-либо TCP-ноги.
pub(crate) async fn attempt_client_datagram_leg(
    muxer: Arc<Muxer>,
    udp_addr: SocketAddr,
    decoy_sni: Arc<str>,
    session_id: String,
    datagram_root: [u8; 32],
) {
    let bind_addr: SocketAddr = if udp_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "Datagram leg: bind failed, staying TCP-only");
            return;
        }
    };
    if let Err(e) = socket.connect(udp_addr).await {
        debug!(error = %e, "Datagram leg: connect failed, staying TCP-only");
        return;
    }
    let socket = Arc::new(socket);

    let kind = dgram_leg::choose_engine();
    let (tx, rx) = build_mimicry_pair(&kind, datagram_root, true);
    let decorative_initial = match kind {
        DgramEngineKind::Quic => {
            // Синтетический одноразовый `SessionKeys` — ТОЛЬКО ради
            // правдоподобного `ClientHello` внутри Initial-пакета (см.
            // `quiceng::initial`'s module docs за тем, почему это не тот
            // материал, из которого выводятся настоящие ключи ноги). Никогда
            // не используется ни для чего, кроме этого одного пакета.
            let throwaway_keys = crate::crypto::SessionKeys::new(true);
            let leg_token = DatagramKeyMaterial::derive_from_root(datagram_root, true).leg_token();
            let dcid = dgram_leg::quic_dcid_client(&leg_token);
            let scid: [u8; 8] = rand::random();
            Some(quiceng::build_client_initial(
                &quiceng::QuicProfile::CHROME,
                &decoy_sni,
                &throwaway_keys,
                &dcid,
                &scid,
            ))
        }
        DgramEngineKind::WebRtc => None,
    };

    let established = match try_establish(tx, rx, &socket, decorative_initial).await {
        Some(pair) => Some(pair),
        None => {
            debug!(
                ?session_id,
                "Datagram leg: mimicry engine failed, trying raw UDP"
            );
            let (raw_tx, raw_rx) = build_raw_pair(datagram_root, true);
            try_establish(raw_tx, raw_rx, &socket, None).await
        }
    };

    let Some((tx, rx)) = established else {
        debug!(
            ?session_id,
            "Datagram leg: no engine reached the server, staying TCP-only"
        );
        return;
    };
    info!(?session_id, "🌐 Physical UDP leg established");

    let cap = NetworkConfig::global().channel_capacity;
    let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
    let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);
    muxer.set_datagram_leg(control_tx.clone(), data_tx);
    // `try_establish` уже доказал живой раунд-трип (иначе мы бы сюда не
    // дошли) — отмечаем это НЕМЕДЛЕННО, а не ждём, пока читающая задача
    // ниже сама получит следующую датаграмму и её заметит. Без этого между
    // регистрацией ноги и первым тиком читателя было настоящее окно, в
    // котором `select_udp_leg` считал свежесозданную ногу недостаточно
    // свежей (см. `datagram_leg_is_fresh`) и — если TCP-ног тоже ещё нет —
    // `send_to_network` первого же кадра падал с "No active legs" (поймано
    // интеграционным тестом `established_leg_actually_carries_application_data_end_to_end`,
    // не гипотетически).
    muxer.mark_datagram_leg_alive();

    // Клиент никогда сам не открывает соединения к целям — `opener: None`,
    // тот же контракт, что и у `StreamHandler` TCP-ног клиента.
    let handler = Arc::new(StreamHandler::new(muxer.clone(), None));
    // Тот же токен, что и у TCP-ног: смена сети должна убивать и UDP-ногу
    // тоже (старый сокет на старом интерфейсе не отдаст ошибку сам по себе).
    let token = muxer.network_epoch_token();

    tokio::spawn(run_datagram_writer(
        tx,
        DgramTransport::Connected(socket.clone()),
        control_rx,
        data_rx,
        token.clone(),
    ));
    tokio::spawn(run_client_datagram_reader(
        rx, socket, muxer, handler, control_tx, token,
    ));
}

async fn run_client_datagram_reader(
    mut rx: DgramRx,
    socket: Arc<UdpSocket>,
    muxer: Arc<Muxer>,
    handler: Arc<StreamHandler>,
    control_tx: mpsc::Sender<MuxMessage>,
    token: CancellationToken,
) {
    let mut buf = [0u8; RECV_BUF_LEN];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            res = socket.recv(&mut buf) => {
                let Ok(n) = res else { break };
                if let Ok(frame) = rx.open(&buf[..n]) {
                    dispatch_open_frame(frame, &control_tx, &handler).await;
                    muxer.mark_datagram_leg_alive();
                }
            }
        }
    }
    muxer.clear_datagram_leg();
}

// ============================================================================
// Сервер
// ============================================================================

/// Состояние ноги ПОСЛЕ первой успешно расшифрованной датаграммы: адрес
/// пира (обновляется на каждый последующий успех — роуминг за NAT/сменой
/// сети клиента бесплатен, потому что подлинность каждый раз перепроверяет
/// AEAD, а не запоминается по первому впечатлению), плюс всё, что нужно
/// читающей стороне для ответа/диспетчеризации.
pub(crate) struct EstablishedDgramSession {
    peer_addr: Arc<ArcSwap<SocketAddr>>,
    control_tx: mpsc::Sender<MuxMessage>,
    handler: Arc<StreamHandler>,
}

/// Классифицирует первый байт входящей датаграммы по тем же диапазонам,
/// которые задают сами форматы (RFC 9000 §17.3.1 для QUIC short header,
/// RFC 7983 для RTP/RTCP) — не наша договорённость, а следствие того, как
/// устроены байты на проводе (см. `quiceng`/`webrtceng` module docs).
enum WireGuess {
    /// QUIC short header (1-RTT) — `0x40..=0x7F` до протекции заголовка,
    /// протекция трогает только младшие 5 бит, старшие два (`01`) остаются
    /// видны.
    QuicShort,
    /// QUIC long header (Initial и другие) — `0xC0..=0xFF`. Никогда не
    /// обрабатывается: настоящие ключи идут не оттуда (см.
    /// `attempt_client_datagram_leg`'s `decorative_first`).
    QuicLong,
    /// RTP/RTCP — `128..=191` (версия RTP=2 в двух старших битах).
    Rtp,
    /// Всё остальное — голый UDP-фолбэк, весь `leg_token` в открытую в
    /// первых 16 байтах.
    Raw,
}

fn guess_wire_kind(first_byte: u8) -> WireGuess {
    if first_byte & 0xC0 == 0xC0 {
        WireGuess::QuicLong
    } else if (0x40..=0x7F).contains(&first_byte) {
        WireGuess::QuicShort
    } else if (128..=191).contains(&first_byte) {
        WireGuess::Rtp
    } else {
        WireGuess::Raw
    }
}

/// Один общий UDP-сокет на все сессии процесса — точка входа сервера. Живёт
/// рядом с TCP-`accept`-циклом (см. `server/src/network.rs`), не заменяет
/// его: TCP остаётся обязательным транспортом, эта нога — опциональной
/// надстройкой поверх уже установленных сессий (см. докстринг
/// [`SessionManager::register_datagram_session`]).
///
/// Принимает уже забинженный сокет, а не адрес: так вызывающий код узнаёт
/// реальный порт (важно для эфемерных `:0` — см. тесты этого модуля и
/// симметричный приём в `server/src/network.rs` для TCP-`accept`-цикла) без
/// гонки `bind` → `local_addr` → отдельный `bind` внутри задачи.
pub async fn run_datagram_listener(
    socket: UdpSocket,
    session_manager: Arc<SessionManager>,
    token: CancellationToken,
) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    info!(bind_addr = ?socket.local_addr(), "🌐 UDP datagram leg listener bound");
    let mut buf = [0u8; RECV_BUF_LEN];

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("UDP datagram leg listener: shutdown signal received");
                break;
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "UDP datagram leg listener: recv error");
                        continue;
                    }
                };
                handle_server_datagram(&session_manager, &socket, peer, &buf[..n]).await;
            }
        }
    }
    Ok(())
}

async fn handle_server_datagram(
    session_manager: &SessionManager,
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    wire: &[u8],
) {
    let Some(&first) = wire.first() else { return };

    match guess_wire_kind(first) {
        WireGuess::QuicLong => {
            // Декоративный Initial — намеренно ничего не делаем (см.
            // докстринг `WireGuess::QuicLong`), не тратим на него AEAD.
        }
        WireGuess::QuicShort => {
            let dcid_len = quiceng::QuicProfile::CHROME.dcid_len as usize;
            if wire.len() < 1 + dcid_len {
                return;
            }
            let mut dcid = [0u8; 8];
            dcid.copy_from_slice(&wire[1..1 + dcid_len]);
            if let Some(mut entry) = session_manager.dgram_quic_entry(&dcid) {
                process_datagram(&mut entry, socket, peer, wire).await;
            }
        }
        WireGuess::Rtp => {
            if wire.len() < 12 {
                return;
            }
            let ssrc = u32::from_be_bytes(wire[8..12].try_into().unwrap());
            if let Some(mut entry) = session_manager.dgram_webrtc_entry(&ssrc) {
                process_datagram(&mut entry, socket, peer, wire).await;
            }
        }
        WireGuess::Raw => {
            if wire.len() < 16 {
                return;
            }
            let mut leg_token = [0u8; 16];
            leg_token.copy_from_slice(&wire[0..16]);
            if let Some(mut entry) = session_manager.dgram_raw_entry(&leg_token) {
                process_datagram(&mut entry, socket, peer, wire).await;
            }
        }
    }
}

async fn process_datagram(
    entry: &mut DgramSessionEntry,
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    wire: &[u8],
) {
    // Расшифровываем РОВНО ОДИН раз, до какого-либо решения об установлении —
    // и решение "устанавливать ли ногу", и решение "отвечать ли PONG" зависят
    // от одного и того же результата, а не от двух независимых попыток.
    let frame = match entry.rx.open(wire) {
        Ok(frame) => frame,
        Err(_) => return, // мусор/повтор/чужая эпоха — молча отбрасываем, ногу не трогаем
    };

    match &entry.established {
        Some(est) => {
            // Роуминг: доверяем последнему АУТЕНТИФИЦИРОВАННОМУ источнику —
            // подлинность уже перепроверил AEAD выше, это не "поверили заголовку".
            est.peer_addr.store(Arc::new(peer));
        }
        None => {
            // Первая успешная датаграмма этой сессии — поднимаем ногу СРАЗУ,
            // до диспетчеризации самого кадра ниже: иначе первый же PING
            // клиента остался бы без ответа (писатель, если бы его завели
            // ПОСЛЕ этого блока, ответил бы только на следующий таймер
            // keepalive — гонка с таймаутом клиентской попытки, реальный баг,
            // словленный именно интеграционным тестом этого модуля).
            let peer_addr = Arc::new(ArcSwap::from(Arc::new(peer)));
            let opener = Arc::new(RemoteOpener {
                muxer: entry.muxer.clone(),
            });
            let handler = Arc::new(StreamHandler::new(entry.muxer.clone(), Some(opener)));

            let cap = NetworkConfig::global().channel_capacity;
            let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
            let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);
            entry.muxer.set_datagram_leg(control_tx.clone(), data_tx);

            let tx = build_matching_tx(&entry.rx, entry.datagram_root);
            let token = entry.muxer.network_epoch_token();
            tokio::spawn(run_datagram_writer(
                tx,
                DgramTransport::Shared(socket.clone(), peer_addr.clone()),
                control_rx,
                data_rx,
                token,
            ));

            info!(session_id = %entry.muxer.session_id(), "🌐 Physical UDP leg established (server side)");
            entry.established = Some(EstablishedDgramSession {
                peer_addr,
                control_tx,
                handler,
            });
        }
    }

    let est = entry
        .established
        .as_ref()
        .expect("just populated above on the None branch");
    dispatch_open_frame(frame, &est.control_tx, &est.handler).await;
    entry.muxer.mark_datagram_leg_alive();
}

/// Строит `DgramTx`, симметричный уже собранному `entry.rx` (тот же
/// движок), на серверную половину `leg_token`/HP-ключей (`is_client=false`).
fn build_matching_tx(rx: &DgramRx, datagram_root: [u8; 32]) -> DgramTx {
    match rx {
        DgramRx::Quic(_) => {
            let material = DatagramKeyMaterial::derive_from_root(datagram_root, false);
            let hp = material.hp_key_tx();
            let leg_token = material.leg_token();
            DgramTx::Quic(quiceng::QuicTx::new(
                CoreDatagramTx::new(material),
                hp,
                Bytes::copy_from_slice(&dgram_leg::quic_dcid_server(&leg_token)),
            ))
        }
        DgramRx::WebRtc(_) => {
            let material = DatagramKeyMaterial::derive_from_root(datagram_root, false);
            let leg_token = material.leg_token();
            DgramTx::WebRtc(webrtceng::WebrtcTx::new(
                CoreDatagramTx::new(material),
                &webrtceng::WebrtcProfile::OPUS_48K,
                dgram_leg::webrtc_ssrc_server(&leg_token),
            ))
        }
        DgramRx::Raw(_) => {
            let material = DatagramKeyMaterial::derive_from_root(datagram_root, false);
            DgramTx::Raw(rawdgram::RawDgramTx::new(CoreDatagramTx::new(material)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::connection::connection::SessionManager;
    use std::time::Duration;

    /// Гоняет полную установку UDP-ноги через настоящие loopback-сокеты:
    /// сервер слушает, клиент пробует один из движков мимикрии (или голый
    /// UDP, если оба заняты сетью, которой тут нет) и ждёт ответа. Синтетический
    /// `datagram_root` вместо настоящего TCP-хендшейка — путь
    /// "хендшейк → datagram_root" уже покрыт тестами `crypto::session` и
    /// `crypto::datagram_keys`; здесь проверяется слой ПОСЛЕ него — то, что
    /// раньше нельзя было протестировать без реальных сокетов.
    async fn establish_leg_case(force_engine: Option<DgramEngineKind>) {
        crate::net::NetworkConfig::init_global(1500);
        let datagram_root = [0x42u8; 32];

        let session_manager = Arc::new(SessionManager::new());
        let server_muxer = Arc::new(Muxer::new(false, "srv-test".into()));
        session_manager.register_datagram_session(&server_muxer, datagram_root);

        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener_socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let listener_token = token.clone();
        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            let _ = run_datagram_listener(listener_socket, sm_clone, listener_token).await;
        });

        let client_muxer = Arc::new(Muxer::new(true, "cli-test".into()));

        match force_engine {
            None => {
                attempt_client_datagram_leg(
                    client_muxer.clone(),
                    listen_addr,
                    Arc::from("example.com"),
                    "cli-test".into(),
                    datagram_root,
                )
                .await;
            }
            Some(kind) => {
                // Обходим случайный выбор — тестируем каждый движок отдельно,
                // а не полагаемся на то, что за разумное число прогонов
                // выпадут оба (см. `dgram_leg::tests` за тем, где ЭТО уже
                // проверяется статистически).
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                socket.connect(listen_addr).await.unwrap();
                let (tx, rx) = build_mimicry_pair(&kind, datagram_root, true);
                let Some((tx, rx)) = try_establish(tx, rx, &socket, None).await else {
                    panic!("{kind:?} failed to establish over real loopback sockets");
                };

                let cap = crate::net::NetworkConfig::global().channel_capacity;
                let (control_tx, control_rx) = mpsc::channel(cap);
                let (data_tx, data_rx) = mpsc::channel(cap);
                client_muxer.set_datagram_leg(control_tx.clone(), data_tx);
                let handler = Arc::new(StreamHandler::new(client_muxer.clone(), None));
                let socket = Arc::new(socket);
                tokio::spawn(run_datagram_writer(
                    tx,
                    DgramTransport::Connected(socket.clone()),
                    control_rx,
                    data_rx,
                    token.clone(),
                ));
                tokio::spawn(run_client_datagram_reader(
                    rx,
                    socket,
                    client_muxer.clone(),
                    handler,
                    control_tx,
                    token.clone(),
                ));
            }
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            client_muxer.datagram_leg_stats().is_some(),
            "client must have a native UDP leg registered"
        );
        assert!(
            server_muxer.datagram_leg_stats().is_some(),
            "server must have established the leg on the first authenticated packet"
        );

        token.cancel();
    }

    #[tokio::test]
    async fn client_and_server_establish_a_real_udp_leg_quic() {
        establish_leg_case(Some(DgramEngineKind::Quic)).await;
    }

    #[tokio::test]
    async fn client_and_server_establish_a_real_udp_leg_webrtc() {
        establish_leg_case(Some(DgramEngineKind::WebRtc)).await;
    }

    #[tokio::test]
    async fn client_and_server_establish_a_real_udp_leg_via_the_public_entry_point() {
        establish_leg_case(None).await;
    }

    /// Отличается от `establish_leg_case` тем, что не останавливается на
    /// подтверждённой живости (PING/PONG) — гоняет НАСТОЯЩИЙ прикладной
    /// кадр через `Muxer::send_to_network` (тот же путь, которым реальный
    /// пользовательский UDP-трафик уходит из `bridge.rs`) и проверяет, что
    /// он доходит до зарегистрированного потока-получателя на другой
    /// стороне. Живости мало: она доказывает, что keepalive-цикл сам с
    /// собой работает, а не что `select_udp_leg`/`dispatch_to_local`
    /// корректно проводят чужой кадр через всю цепочку.
    #[tokio::test]
    async fn established_leg_actually_carries_application_data_end_to_end() {
        crate::net::NetworkConfig::init_global(1500);
        let datagram_root = [0x77u8; 32];

        let session_manager = Arc::new(SessionManager::new());
        let server_muxer = Arc::new(Muxer::new(false, "srv-data-test".into()));
        session_manager.register_datagram_session(&server_muxer, datagram_root);

        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener_socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let listener_token = token.clone();
        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            let _ = run_datagram_listener(listener_socket, sm_clone, listener_token).await;
        });

        let client_muxer = Arc::new(Muxer::new(true, "cli-data-test".into()));
        attempt_client_datagram_leg(
            client_muxer.clone(),
            listen_addr,
            Arc::from("example.com"),
            "cli-data-test".into(),
            datagram_root,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            client_muxer.datagram_leg_stats().is_some(),
            "leg must be up before we can even attempt to send data over it"
        );

        let (server_stream_tx, mut server_stream_rx) = mpsc::channel::<Bytes>(8);
        let stream_id: u32 = 4242;
        let _stream_token = server_muxer.register_stream(stream_id, server_stream_tx);

        client_muxer
            .send_to_network(MuxMessage {
                stream_id,
                frame_type: FrameType::UdpData,
                data: Bytes::from_static(b"hello over the real udp leg"),
            })
            .await
            .expect("send_to_network must succeed once the native leg is up");

        let received = tokio::time::timeout(Duration::from_secs(2), server_stream_rx.recv())
            .await
            .expect("must receive the payload within the timeout")
            .expect("stream channel must not close underneath us");
        assert_eq!(&received[..], b"hello over the real udp leg");

        token.cancel();
    }

    /// Два независимых клиента бьются в ОДИН И ТОТ ЖЕ слушатель одновременно
    /// (ровно то, что настоящий сервер видит — общий сокет на все сессии
    /// процесса, см. докстринг [`run_datagram_listener`]). Проверяет не
    /// только то, что обе ноги поднимаются, но и что данные сессии A не
    /// утекают в сессию B — единственный способ по-настоящему проверить
    /// демультиплексирующие карты `SessionManager`, а не просто то, что они
    /// заполняются.
    #[tokio::test]
    async fn two_concurrent_sessions_on_one_listener_do_not_cross_wire() {
        crate::net::NetworkConfig::init_global(1500);
        let root_a = [0xAAu8; 32];
        let root_b = [0xBBu8; 32];

        let session_manager = Arc::new(SessionManager::new());
        let server_muxer_a = Arc::new(Muxer::new(false, "srv-a".into()));
        let server_muxer_b = Arc::new(Muxer::new(false, "srv-b".into()));
        session_manager.register_datagram_session(&server_muxer_a, root_a);
        session_manager.register_datagram_session(&server_muxer_b, root_b);

        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener_socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let listener_token = token.clone();
        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            let _ = run_datagram_listener(listener_socket, sm_clone, listener_token).await;
        });

        let client_muxer_a = Arc::new(Muxer::new(true, "cli-a".into()));
        let client_muxer_b = Arc::new(Muxer::new(true, "cli-b".into()));

        tokio::join!(
            attempt_client_datagram_leg(
                client_muxer_a.clone(),
                listen_addr,
                Arc::from("example.com"),
                "cli-a".into(),
                root_a,
            ),
            attempt_client_datagram_leg(
                client_muxer_b.clone(),
                listen_addr,
                Arc::from("example.com"),
                "cli-b".into(),
                root_b,
            ),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(client_muxer_a.datagram_leg_stats().is_some());
        assert!(client_muxer_b.datagram_leg_stats().is_some());
        assert!(server_muxer_a.datagram_leg_stats().is_some());
        assert!(server_muxer_b.datagram_leg_stats().is_some());

        let (tx_a, mut rx_a) = mpsc::channel::<Bytes>(8);
        let (tx_b, mut rx_b) = mpsc::channel::<Bytes>(8);
        let _t1 = server_muxer_a.register_stream(1, tx_a);
        let _t2 = server_muxer_b.register_stream(1, tx_b);

        client_muxer_a
            .send_to_network(MuxMessage {
                stream_id: 1,
                frame_type: FrameType::UdpData,
                data: Bytes::from_static(b"from-a"),
            })
            .await
            .unwrap();
        client_muxer_b
            .send_to_network(MuxMessage {
                stream_id: 1,
                frame_type: FrameType::UdpData,
                data: Bytes::from_static(b"from-b"),
            })
            .await
            .unwrap();

        let got_a = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        let got_b = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &got_a[..],
            b"from-a",
            "session A's stream must receive session A's payload"
        );
        assert_eq!(
            &got_b[..],
            b"from-b",
            "session B's stream must receive session B's payload, not A's"
        );

        token.cancel();
    }

    /// Ни один другой тест этого файла не задевает реальный путь отказа: во
    /// всех остальных сервер регистрирует все три движка и первая же
    /// попытка (какой бы движок ни выбрал `choose_engine`) успешна. Здесь
    /// сервер-заглушка нарочно отвечает ТОЛЬКО на голый UDP — имитация сети,
    /// которая режет QUIC-/RTP-подобную форму, — и клиент обязан честно
    /// прождать полный таймаут мимикрии, прежде чем откатиться.
    #[tokio::test]
    async fn client_falls_back_to_raw_when_the_mimicry_engine_gets_no_reply() {
        crate::net::NetworkConfig::init_global(1500);
        let datagram_root = [0x99u8; 32];

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let stub_token = token.clone();
        tokio::spawn(async move {
            let (mut stub_tx, mut stub_rx) = build_raw_pair(datagram_root, false);
            let mut buf = [0u8; RECV_BUF_LEN];
            loop {
                tokio::select! {
                    _ = stub_token.cancelled() => break,
                    res = socket.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        // QUIC-/RTP-подобные пакеты не парсятся этим (голым)
                        // `stub_rx` и молча отбрасываются — сеть, которая
                        // режет мимикрию, выглядит отсюда РОВНО так же:
                        // пакеты уходят в никуда, ответа не будет.
                        if let Ok(frame) = stub_rx.open(&buf[..n]) {
                            if frame.header.frame_type == FrameType::Heartbeat
                                && frame.payload.as_ref() == PING
                            {
                                if let Ok(pong) =
                                    stub_tx.seal(0, FrameType::Heartbeat, Bytes::from_static(PONG))
                                {
                                    let _ = socket.send_to(&pong, peer).await;
                                }
                            }
                        }
                    }
                }
            }
        });

        let client_muxer = Arc::new(Muxer::new(true, "cli-fallback-test".into()));
        let started = tokio::time::Instant::now();
        attempt_client_datagram_leg(
            client_muxer.clone(),
            listen_addr,
            Arc::from("example.com"),
            "cli-fallback-test".into(),
            datagram_root,
        )
        .await;
        let elapsed = started.elapsed();

        assert!(
            client_muxer.datagram_leg_stats().is_some(),
            "client must have fallen back to raw UDP and established the leg despite the mimicry engine going unanswered"
        );
        assert!(
            elapsed >= DATAGRAM_LEG_HANDSHAKE_TIMEOUT,
            "fallback must only trigger after the mimicry attempt genuinely timed out, took {elapsed:?}"
        );

        token.cancel();
    }

    #[tokio::test]
    async fn a_stale_server_registration_is_a_no_op() {
        // Вторая регистрация той же сессии (как если бы вторая TCP-нога тоже
        // завершила хендшейк) не должна ничего сломать или перезаписать.
        let datagram_root_a = [0x11u8; 32];
        let datagram_root_b = [0x22u8; 32];
        let session_manager = SessionManager::new();
        let muxer = Arc::new(Muxer::new(false, "race-test".into()));

        session_manager.register_datagram_session(&muxer, datagram_root_a);
        let token_after_first = muxer.datagram_leg_token();
        session_manager.register_datagram_session(&muxer, datagram_root_b);

        assert_eq!(
            muxer.datagram_leg_token(),
            token_after_first,
            "second registration must not overwrite the winning leg_token"
        );
    }
}
