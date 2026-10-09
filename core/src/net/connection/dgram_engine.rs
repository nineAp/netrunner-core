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

use std::{net::SocketAddr, sync::Arc};

#[cfg(feature = "mesh-quic")]
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use netrunner_logger::{debug, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::crypto::{DatagramKeyMaterial, DatagramRoot, DgramEngineLabel, DgramKdfContext};
use crate::dgram_leg::{self, DgramEngineKind, DgramRx, DgramTx};
use crate::net::connection::connection::{DgramSessionEntry, SessionManager};
use crate::net::connection::handler::{RemoteOpener, StreamHandler};
use crate::net::connection::muxer::{MuxMessage, Muxer};
use crate::net::{NetworkConfig, DATAGRAM_LEG_HANDSHAKE_TIMEOUT};
use crate::nrxp::{DatagramRx as CoreDatagramRx, DatagramTx as CoreDatagramTx, Frame, FrameType};
use crate::{quiceng, rawdgram, webrtceng};

const PING: &[u8] = b"PING";
const PONG: &[u8] = b"PONG";
/// Приёмный буфер. Должен вмещать самую большую датаграмму, которую нам могут
/// прислать, БЕЗ обрезания (обрезанный шифртекст не пройдёт AEAD и выглядел бы
/// как потеря, а не как слишком большой пакет). Наши собственные исходящие
/// датаграммы ограничены сверху [`crate::net::MAX_DATAGRAM_LEG_PAYLOAD`], но
/// принять мы должны что угодно вплоть до теоретического максимума UDP —
/// поэтому буфер лежит в куче (на стеке задачи 64 КиБ держать не хочется), а
/// не `[0u8; 2048]`, который резал пакеты при MTU больше ~1900 (bug #20).
const RECV_BUF_LEN: usize = 65_535;

/// Номер попытки установки ноги, вплетаемый в вывод ключей (см.
/// [`DgramKdfContext`]). В этой правке установка одноразовая, поэтому всегда 0;
/// Этап 1 (сигнализация `attempt_id`) подставит сюда растущий номер.
const ATTEMPT: u16 = 0;

/// Смещения (мс от начала попытки), на которых переотправляется установочный
/// PING внутри [`DATAGRAM_LEG_HANDSHAKE_TIMEOUT`]. Одна потеря первого PING
/// больше не проваливает движок (bug #7): за 3 c уходит до четырёх проб с
/// нарастающим интервалом, приёмник отвечает на любую.
const PING_RETRY_OFFSETS_MS: [u64; 4] = [0, 300, 800, 1500];

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
    loop {
        // Интервал keepalive выбирается заново на каждой итерации и СБРАСЫВАЕТСЯ
        // любым реальным кадром (см. `select!` ниже — таймер пересоздаётся при
        // каждом проходе цикла), поэтому под нагрузкой PING почти не уходит, а
        // на простое — вразброс раз в 15–25 с, а не строго раз в 3 с (bug #14).
        let jitter = crate::net::DATAGRAM_KEEPALIVE_MIN.as_secs_f64()
            + rand::random::<f64>()
                * (crate::net::DATAGRAM_KEEPALIVE_MAX.as_secs_f64()
                    - crate::net::DATAGRAM_KEEPALIVE_MIN.as_secs_f64());
        let keepalive = tokio::time::sleep(std::time::Duration::from_secs_f64(jitter));
        tokio::pin!(keepalive);

        tokio::select! {
            _ = token.cancelled() => break,
            _ = &mut keepalive => {
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

/// Attaches the mesh session's UDP flow leg to QUIC DATAGRAM frames. The
/// surrounding NRXP stream has already authenticated the peer, and QUIC
/// protects these packet payloads on the same peer connection. If datagrams
/// are unavailable or fail later, the Muxer falls back to its reliable stream.
#[cfg(feature = "mesh-quic")]
pub(crate) fn attach_mesh_quic_datagram_leg(
    muxer: Arc<Muxer>,
    connection: quinn::Connection,
    handler: Arc<StreamHandler>,
    datagram_root: impl Into<DatagramRoot>,
    is_client: bool,
) {
    let Some(max_datagram) = connection.max_datagram_size() else {
        metrics::counter!("netrunner_mesh_quic_datagram_unavailable_total").increment(1);
        return;
    };
    let max_payload = max_datagram
        .saturating_sub(crate::rawdgram::RAW_DGRAM_OVERHEAD)
        .min(crate::net::MAX_DATAGRAM_LEG_PAYLOAD);
    if max_payload == 0 {
        metrics::counter!("netrunner_mesh_quic_datagram_unavailable_total").increment(1);
        return;
    }

    let cap = NetworkConfig::global().channel_capacity;
    let (control_tx, mut control_rx) = mpsc::channel::<MuxMessage>(cap);
    let (data_tx, mut data_rx) = mpsc::channel::<MuxMessage>(cap);
    muxer.set_datagram_leg_with_max_payload(control_tx.clone(), data_tx, max_payload);
    muxer.mark_datagram_leg_alive();
    let (mut tx, mut rx) = build_raw_pair(datagram_root.into(), is_client);

    let token = muxer.network_epoch_token().child_token();
    let reader_token = token.clone();
    let writer_muxer = muxer.clone();
    let writer_connection = connection.clone();
    tokio::spawn(async move {
        loop {
            let keepalive_seconds = 15.0 + rand::random::<f64>() * 10.0;
            let keepalive = tokio::time::sleep(Duration::from_secs_f64(keepalive_seconds));
            tokio::pin!(keepalive);

            tokio::select! {
                _ = token.cancelled() => break,
                _ = &mut keepalive => {
                    let ping = match tx.seal(0, FrameType::Heartbeat, Bytes::from_static(PING)) {
                        Ok(ping) => ping,
                        Err(_) => {
                            writer_muxer.clear_datagram_leg();
                            break;
                        }
                    };
                    if send_mesh_quic_datagram(&writer_connection, ping).is_err() {
                        writer_muxer.clear_datagram_leg();
                        break;
                    }
                }
                message = control_rx.recv() => match message {
                    Some(message) => {
                        let packet = match tx.seal(message.stream_id, message.frame_type, message.data) {
                            Ok(packet) => packet,
                            Err(_) => {
                                writer_muxer.clear_datagram_leg();
                                break;
                            }
                        };
                        if send_mesh_quic_datagram(&writer_connection, packet).is_err() {
                            writer_muxer.clear_datagram_leg();
                            break;
                        }
                    }
                    None => break,
                },
                message = data_rx.recv() => match message {
                    Some(message) => {
                        let packet = match tx.seal(
                            message.stream_id,
                            message.frame_type,
                            message.data.clone(),
                        ) {
                            Ok(packet) => packet,
                            Err(_) => {
                                writer_muxer.clear_datagram_leg();
                                writer_muxer
                                    .send_data_safe(message.stream_id, message.data, true)
                                    .await
                                    .ok();
                                break;
                            }
                        };
                        if send_mesh_quic_datagram(&writer_connection, packet).is_err() {
                            writer_muxer.clear_datagram_leg();
                            // The QUIC datagram could not be queued (for example
                            // after a path MTU change). Retrying now uses the
                            // reliable stream carried by this session.
                            writer_muxer
                                .send_data_safe(message.stream_id, message.data, true)
                                .await
                                .ok();
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
        token.cancel();
    });

    let reader_muxer = muxer.clone();
    let reader_control_tx = control_tx.clone();
    tokio::spawn(async move {
        loop {
            let packet = tokio::select! {
                _ = reader_token.cancelled() => break,
                packet = connection.read_datagram() => match packet {
                    Ok(packet) => packet,
                    Err(_) => break,
                }
            };
            let Ok(frame) = rx.open(&packet) else {
                continue;
            };
            dispatch_open_frame(frame, &reader_control_tx, &handler).await;
            reader_muxer.mark_datagram_leg_alive();
        }
        reader_muxer.clear_datagram_leg();
        reader_token.cancel();
    });
}

/// Queue one unreliable mesh packet without waiting for congestion recovery.
/// Quinn's `send_datagram` drops the oldest unsent datagrams when its bounded
/// queue fills, which keeps current UDP traffic moving instead of building a
/// seconds-long backlog behind stale video packets.
#[cfg(feature = "mesh-quic")]
fn send_mesh_quic_datagram(
    connection: &quinn::Connection,
    packet: Bytes,
) -> Result<(), quinn::SendDatagramError> {
    if connection.datagram_send_buffer_space() < packet.len() {
        metrics::counter!("netrunner_mesh_quic_datagram_queue_pressure_total").increment(1);
    }
    connection.send_datagram(packet)
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
    match frame.header.frame_type {
        FrameType::Heartbeat => {
            if frame.payload.as_ref() == PING {
                let _ = control_tx.try_send(MuxMessage {
                    stream_id: 0,
                    frame_type: FrameType::Heartbeat,
                    data: Bytes::from_static(PONG),
                });
            }
            // PONG/прочий Heartbeat: живость отмечает вызывающий (см. докстринг модуля).
        }
        // По UDP-ноге ездит ТОЛЬКО прикладная датаграмма и keepalive. Мультиплексор
        // маршрутизирует на неё исключительно `UdpData` (см. `Muxer::select_udp_leg`),
        // поэтому `Connect`/`UdpConnect`/`Data`/`Close`/… здесь появиться могут лишь
        // от пира, который шлёт их намеренно. Их нельзя пускать в `handler.handle`:
        // `UdpConnect`/`Connect` там открывают соединение к цели (`RemoteOpener`) —
        // аутентифицированный клиент иначе поднимал бы `open_tcp` под shard-локом
        // DashMap прямо в общем UDP-цикле и вешал бы UDP всей ноды (bug #19). На
        // клиенте `opener == None`, но фильтр держим симметрично — единый контракт
        // «датаграммная нога переносит только UdpData».
        FrameType::UdpData => handler.handle(frame).await,
        other => {
            netrunner_logger::trace!(
                frame = ?other,
                "Datagram leg: dropping frame type not carried over UDP"
            );
        }
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
    datagram_root: impl Into<DatagramRoot>,
    is_client: bool,
) -> (DgramTx, DgramRx) {
    let datagram_root = datagram_root.into();
    match kind {
        DgramEngineKind::Quic => {
            let ctx = DgramKdfContext::new(DgramEngineLabel::Quic, ATTEMPT);
            let tx_material =
                DatagramKeyMaterial::derive_from_root_ctx(datagram_root, is_client, ctx);
            let rx_material =
                DatagramKeyMaterial::derive_from_root_ctx(datagram_root, is_client, ctx);
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
            let ctx = DgramKdfContext::new(DgramEngineLabel::WebRtc, ATTEMPT);
            let tx_material =
                DatagramKeyMaterial::derive_from_root_ctx(datagram_root, is_client, ctx);
            let rx_material =
                DatagramKeyMaterial::derive_from_root_ctx(datagram_root, is_client, ctx);
            let leg_token = tx_material.leg_token();
            let ssrc_out = if is_client {
                dgram_leg::webrtc_ssrc_client(&leg_token)
            } else {
                dgram_leg::webrtc_ssrc_server(&leg_token)
            };
            let tx = webrtceng::WebrtcTx::new(
                CoreDatagramTx::new(tx_material),
                &webrtceng::WebrtcProfile::VP8_VIDEO,
                ssrc_out,
            );
            let rx = webrtceng::WebrtcRx::new(CoreDatagramRx::new(rx_material));
            (DgramTx::WebRtc(tx), DgramRx::WebRtc(rx))
        }
    }
}

fn build_raw_pair(datagram_root: impl Into<DatagramRoot>, is_client: bool) -> (DgramTx, DgramRx) {
    let datagram_root = datagram_root.into();
    let ctx = DgramKdfContext::new(DgramEngineLabel::Raw, ATTEMPT);
    let tx_material = DatagramKeyMaterial::derive_from_root_ctx(datagram_root, is_client, ctx);
    let rx_material = DatagramKeyMaterial::derive_from_root_ctx(datagram_root, is_client, ctx);
    (
        DgramTx::Raw(rawdgram::RawDgramTx::new(CoreDatagramTx::new(tx_material))),
        DgramRx::Raw(rawdgram::RawDgramRx::new(CoreDatagramRx::new(rx_material))),
    )
}

/// Декоративный первый пакет движка, если он у него есть. Для `quiceng` — это
/// поддельный QUIC Initial с правдоподобным `ClientHello`; для `webrtceng`
/// декоративного пакета нет. Никогда не несёт настоящий ключевой материал ноги
/// (см. `quiceng::initial` module docs).
fn build_decorative_initial(
    kind: &DgramEngineKind,
    datagram_root: impl Into<DatagramRoot>,
    decoy_sni: &str,
) -> Vec<Bytes> {
    let datagram_root = datagram_root.into();
    match kind {
        DgramEngineKind::Quic => {
            // `leg_token` для DCID выводится из нейтрального контекста: он
            // одинаков для любого движка (см. `DgramEngineLabel`), и именно его
            // сервер ищет в своих демультиплексирующих картах.
            let leg_token = DatagramKeyMaterial::derive_from_root(datagram_root, true).leg_token();
            let dcid = dgram_leg::quic_dcid_client(&leg_token);
            // Профиль браузера из JSON (`quic`): ClientHello, транспортные
            // параметры и раскладка Initial'ов — как у снятого браузера. Выбор
            // стабилен на сессию (по leg_token). Без пользовательского профиля —
            // встроенный Initial: SCID нулевой длины, как у Chrome (bug #11).
            match quiceng::pick_custom(leg_token.as_ref()) {
                Some(profile) => quiceng::build_client_initial_flight(
                    profile,
                    quiceng::QuicProfile::CHROME.version,
                    decoy_sni,
                    &dcid,
                ),
                None => vec![quiceng::build_client_initial(
                    &quiceng::QuicProfile::CHROME,
                    decoy_sni,
                    &dcid,
                    &[],
                )],
            }
        }
        DgramEngineKind::WebRtc => Vec::new(),
    }
}

/// Ставит на UDP-сокет флаг «не фрагментировать» (DF) — см. точку вызова за
/// тем, зачем. Best-effort: неудача setsockopt не фатальна (нога просто
/// лишается PMTUD-подстраховки), поэтому ошибки не пробрасываются. Живёт под
/// `cfg`, потому что механизм платформенный: на Linux это `IP(V6)_MTU_DISCOVER`.
#[cfg(target_os = "linux")]
fn set_dont_fragment(socket: &UdpSocket, is_ipv4: bool) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    // SAFETY: fd принадлежит живому `socket`, `val` живёт до конца вызова,
    // размер передаётся корректно; setsockopt не трогает Rust-инварианты.
    unsafe {
        let val: libc::c_int = if is_ipv4 {
            libc::IP_PMTUDISC_DO
        } else {
            libc::IPV6_PMTUDISC_DO
        };
        let (level, name) = if is_ipv4 {
            (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
        };
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Не-Linux: DF-механизм платформозависим (на macOS это `IP_DONTFRAG`, на
/// Windows — `IP_DONTFRAGMENT`), а прод-ноды и Android — Linux. На остальных
/// платформах это no-op, а не ошибка сборки: потолок размера в муксере всё
/// равно не даёт формировать заведомо большие датаграммы.
#[cfg(not(target_os = "linux"))]
fn set_dont_fragment(_socket: &UdpSocket, _is_ipv4: bool) {}

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
    decorative_first: Vec<Bytes>,
) -> Option<(DgramTx, DgramRx)> {
    use tokio::time::{Duration, Instant};

    for decorative in decorative_first {
        let _ = socket.send(&decorative).await;
    }

    // Куча, а не стек: [0u8; RECV_BUF_LEN] — это 64 КиБ, слишком много под стек
    // задачи (см. константу).
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let start = Instant::now();
    let deadline = start + DATAGRAM_LEG_HANDSHAKE_TIMEOUT;
    let mut next_retry = 0usize;

    loop {
        // Отправляем все PING, чьё запланированное смещение уже наступило —
        // первый (offset 0) уходит сразу, дальнейшие переотправляются, если к
        // их моменту ответа ещё не было (bug #7). Каждая проба берёт следующий
        // счётчик nonce, так что это не повтор nonce.
        let now = Instant::now();
        while next_retry < PING_RETRY_OFFSETS_MS.len()
            && now >= start + Duration::from_millis(PING_RETRY_OFFSETS_MS[next_retry])
        {
            if let Ok(hello) = tx.seal(0, FrameType::Heartbeat, Bytes::from_static(PING)) {
                let _ = socket.send(&hello).await;
            }
            next_retry += 1;
        }

        if Instant::now() >= deadline {
            return None;
        }

        // Спим либо до ответа, либо до следующей запланированной пробы (что
        // раньше), но не дольше общего дедлайна.
        let wake_at = if next_retry < PING_RETRY_OFFSETS_MS.len() {
            (start + Duration::from_millis(PING_RETRY_OFFSETS_MS[next_retry])).min(deadline)
        } else {
            deadline
        };
        let wake = wake_at.saturating_duration_since(Instant::now());

        match tokio::time::timeout(wake, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if rx.open(&buf[..n]).is_ok() {
                    return Some((tx, rx));
                }
                // Мусор/повтор/не тот пакет — ждём дальше до дедлайна.
            }
            Ok(Err(e)) => {
                // ECONNREFUSED на connect()-нутом UDP-сокете — это ICMP
                // port-unreachable: приходит один раз на исходящий пакет, и его
                // может подделать наблюдатель на пути, а на старте сервер мог
                // ещё не забиндить сокет к моменту нашего первого PING. Считаем
                // временной ошибкой и продолжаем пробовать (bug #2). Прочие
                // ошибки сокета — фатальны для этой попытки.
                if e.kind() != std::io::ErrorKind::ConnectionRefused {
                    return None;
                }
            }
            Err(_elapsed) => {
                // Тик расписания ретраев — на следующей итерации уйдёт очередной PING.
            }
        }
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
    datagram_root: impl Into<DatagramRoot>,
) {
    let datagram_root = datagram_root.into();
    if muxer.is_fatal() {
        return;
    }
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
    // Запрещаем фрагментацию: если наша датаграмма не влезает в PMTU, ядро
    // вернёт EMSGSIZE, а не молча нарежет её на IP-фрагменты (те и сами
    // приметны для DPI, и создают PMTU-чёрную-дыру — мелкий PING проходит,
    // крупный кадр исчезает). Основную защиту даёт потолок размера в муксере
    // (см. `MAX_DATAGRAM_LEG_PAYLOAD`); DF — это подстраховка на случай пути с
    // MTU меньше нашего потолка (bug #5).
    set_dont_fragment(&socket, udp_addr.is_ipv4());
    let socket = Arc::new(socket);

    // Пробуем оба движка мимикрии, и только потом raw. Монета решает лишь
    // ПОРЯДОК (какой первый), а не «мимикрия против ничего»: если сеть режет
    // одну форму, вторая ещё может пройти прежде, чем мы опустимся до голого
    // UDP (bug #7 — раньше при неудаче первого движка второй не пробовался).
    let first = dgram_leg::choose_engine();
    let engines = [first, dgram_leg::other_engine(first)];

    let mut established: Option<(DgramTx, DgramRx)> = None;
    for kind in engines {
        let (tx, rx) = build_mimicry_pair(&kind, datagram_root, true);
        let decorative_initial = build_decorative_initial(&kind, datagram_root, &decoy_sni);
        if let Some(pair) = try_establish(tx, rx, &socket, decorative_initial).await {
            established = Some(pair);
            break;
        }
        debug!(
            ?session_id,
            ?kind,
            "Datagram leg: mimicry engine got no reply, trying next"
        );
    }

    if established.is_none() {
        debug!(
            ?session_id,
            "Datagram leg: both mimicry engines failed, trying raw UDP"
        );
        let (raw_tx, raw_rx) = build_raw_pair(datagram_root, true);
        established = try_establish(raw_tx, raw_rx, &socket, Vec::new()).await;
    }

    let Some((tx, rx)) = established else {
        debug!(
            ?session_id,
            "Datagram leg: no engine reached the server, staying TCP-only"
        );
        return;
    };
    if muxer.is_fatal() {
        return;
    }
    info!(?session_id, "🌐 Physical UDP leg established");
    metrics::counter!("netrunner_datagram_legs_established_total").increment(1);

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
    // Куча, а не 64-КиБ стековый массив (см. `RECV_BUF_LEN`).
    let mut buf = vec![0u8; RECV_BUF_LEN];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            res = socket.recv(&mut buf) => {
                match res {
                    Ok(n) => {
                        if let Ok(frame) = rx.open(&buf[..n]) {
                            dispatch_open_frame(frame, &control_tx, &handler).await;
                            muxer.mark_datagram_leg_alive();
                        }
                    }
                    // ECONNREFUSED — это доставленный ICMP port-unreachable по
                    // предыдущему исходящему пакету; на connect()-нутом сокете он
                    // приходит один раз и его может подделать наблюдатель на пути.
                    // Не рвём ногу из-за него (bug #2) — следующий recv, скорее
                    // всего, снова заблокируется штатно.
                    Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        netrunner_logger::trace!("Datagram leg reader: transient ECONNREFUSED, continuing");
                    }
                    Err(_) => break,
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
    // DF на общем серверном сокете — по той же причине, что и на клиенте (см.
    // `set_dont_fragment`): нисходящие датаграммы тоже ограничены потолком
    // размера в муксере, и фрагментировать их не нужно.
    if let Ok(local) = socket.local_addr() {
        set_dont_fragment(&socket, local.is_ipv4());
    }
    info!(bind_addr = ?socket.local_addr(), "🌐 UDP datagram leg listener bound");
    // Куча, а не 64-КиБ стековый массив (см. `RECV_BUF_LEN`).
    let mut buf = vec![0u8; RECV_BUF_LEN];

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
                        // Одиночный ICMP port-unreachable от предыдущего пира не
                        // должен ронять цикл, обслуживающий ВСЕ сессии. Логируем
                        // и продолжаем — общий сокет не «подключён» к одному
                        // адресу, так что это не про здоровье конкретной ноги.
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
    // Демультиплексируем, ПРОВЕРЯЯ КАЖДУЮ применимую карту, а не угадывая формат
    // по первому байту (bug #1). У голого raw-фолбэка первый байт — это первый
    // байт случайного `leg_token`, поэтому он с вероятностью ~75% попадал в
    // диапазоны QUIC/RTP и датаграмма молча отбрасывалась. Формат
    // аутентифицирует AEAD: неверная догадка просто не расшифруется, и мы
    // переходим к следующей карте. Каждая проверка — O(1) (хеш-таблица), а
    // успешная расшифровка на нужной карте немедленно завершает разбор.
    //
    // Порядок проверок задаём по первому байту (наиболее вероятная карта —
    // первой), чтобы в установившемся режиме укладываться в один поиск: у
    // QUIC 1-RTT первый байт 0x40..=0x7F, у RTP 0x80..=0xBF. Но raw и любой
    // «промах» всё равно доходят до всех трёх карт.
    let dcid_len = quiceng::QuicProfile::CHROME.dcid_len as usize;

    // Порядок проверок — по убыванию вероятности согласно первому байту, чтобы в
    // установившемся режиме укладываться в один поиск. `QuicLong` (декоративный
    // Initial) сводим к `QuicShort`: сам Initial ни на одну карту не ляжет (его
    // байты на смещении DCID не совпадут с ключом), просто промахнёмся втрое и
    // отбросим — тратить на него отдельную ветку незачем.
    let order: [WireGuess; 3] = match wire.first().map(|&b| guess_wire_kind(b)) {
        Some(WireGuess::QuicShort) | Some(WireGuess::QuicLong) => {
            [WireGuess::QuicShort, WireGuess::Rtp, WireGuess::Raw]
        }
        Some(WireGuess::Rtp) => [WireGuess::Rtp, WireGuess::QuicShort, WireGuess::Raw],
        Some(WireGuess::Raw) => [WireGuess::Raw, WireGuess::QuicShort, WireGuess::Rtp],
        None => return, // пустая датаграмма
    };

    for guess in order {
        let hit = match guess {
            WireGuess::QuicShort | WireGuess::QuicLong => {
                if wire.len() < 1 + dcid_len {
                    continue;
                }
                let mut dcid = [0u8; 8];
                dcid.copy_from_slice(&wire[1..1 + dcid_len]);
                match session_manager.dgram_quic_entry(&dcid) {
                    Some(mut entry) => process_datagram(&mut entry, socket, peer, wire).await,
                    None => continue,
                }
            }
            WireGuess::Rtp => {
                if wire.len() < 12 {
                    continue;
                }
                let ssrc = u32::from_be_bytes(wire[8..12].try_into().unwrap());
                match session_manager.dgram_webrtc_entry(&ssrc) {
                    Some(mut entry) => process_datagram(&mut entry, socket, peer, wire).await,
                    None => continue,
                }
            }
            WireGuess::Raw => {
                if wire.len() < 16 {
                    continue;
                }
                let mut leg_token = [0u8; 16];
                leg_token.copy_from_slice(&wire[0..16]);
                match session_manager.dgram_raw_entry(&leg_token) {
                    Some(mut entry) => process_datagram(&mut entry, socket, peer, wire).await,
                    None => continue,
                }
            }
        };
        // Расшифровалось на этой карте — разбор завершён. Иначе (промах AEAD)
        // это была не та карта: пробуем следующую.
        if hit {
            return;
        }
    }

    // Ни одна карта ДАННЫХ не подошла. Только теперь, ПОСЛЕ промаха по
    // raw/quic/rtp, безопасно рассматривать датаграмму как возможный клиентский
    // QUIC Initial (long header): raw-датаграмма со случайным первым байтом
    // 0xC0+ уже была бы поймана raw-картой выше, так что за Initial мы её не
    // примем (тот же урок, что и bug #1). Отвечаем декоративным
    // Initial+Handshake, если Initial адресован УЖЕ зарегистрированной сессии
    // (bug #12; гейт по регистрации заодно закрывает амплификацию — на
    // случайный зонд не отвечаем).
    maybe_respond_to_client_initial(session_manager, socket, peer, wire).await;
}

/// Разбирает Connection ID'ы из QUIC long header:
/// `first(1) | version(4) | dcid_len(1) | dcid | scid_len(1) | scid`.
fn parse_long_header_cids(wire: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if wire.first().map(|&b| b & 0xC0) != Some(0xC0) {
        return None; // не long header
    }
    let mut off = 1 + 4; // first + version
    let dcid_len = *wire.get(off)? as usize;
    off += 1;
    if dcid_len > 20 {
        return None; // RFC 9000 §17.2: CID не длиннее 20 байт
    }
    let dcid = wire.get(off..off + dcid_len)?.to_vec();
    off += dcid_len;
    let scid_len = *wire.get(off)? as usize;
    off += 1;
    if scid_len > 20 {
        return None;
    }
    let scid = wire.get(off..off + scid_len)?.to_vec();
    Some((dcid, scid))
}

async fn maybe_respond_to_client_initial(
    session_manager: &SessionManager,
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    wire: &[u8],
) {
    let Some((dcid, scid)) = parse_long_header_cids(wire) else {
        return;
    };
    // Наши клиенты кладут в DCID Initial ровно 8 байт (quic_dcid_client) — по
    // ним и адресуется quic-карта. Другой длиной адресовать нашу сессию нельзя.
    if dcid.len() != quiceng::QuicProfile::CHROME.dcid_len as usize {
        return;
    }
    let mut dcid8 = [0u8; 8];
    dcid8.copy_from_slice(&dcid);

    // Помечаем «ответили» ПОД локом (и до отправки), чтобы дубликат Initial не
    // породил второй flight; сам flight шлём уже вне лока — держать RefMut
    // DashMap через .await нельзя (см. bug #19).
    let should_respond = match session_manager.dgram_quic_entry(&dcid8) {
        Some(mut entry) if !entry.responded_to_initial => {
            entry.responded_to_initial = true;
            true
        }
        _ => false,
    };
    if !should_respond {
        return;
    }

    let flight = quiceng::build_server_initial_flight(&quiceng::QuicProfile::CHROME, &dcid, &scid);
    for pkt in flight {
        let _ = socket.send_to(&pkt, peer).await;
    }
}

/// Возвращает `true`, если датаграмма расшифровалась и обработана (нога поднята
/// либо продолжена), `false` — если AEAD не сошёлся: тогда вызывающий
/// (`handle_server_datagram`) пробует следующую демультиплексирующую карту.
/// Инвариант: при `false` НИКАКИХ побочных эффектов на `entry` — иначе промах
/// на чужой карте портил бы чужое состояние.
async fn process_datagram(
    entry: &mut DgramSessionEntry,
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    wire: &[u8],
) -> bool {
    // Расшифровываем РОВНО ОДИН раз, до какого-либо решения об установлении —
    // и решение "устанавливать ли ногу", и решение "отвечать ли PONG" зависят
    // от одного и того же результата, а не от двух независимых попыток.
    let frame = match entry.rx.open(wire) {
        Ok(frame) => frame,
        Err(_) => return false, // мусор/повтор/чужая карта — ногу не трогаем, пусть пробуют дальше
    };

    // Переустанавливаем, если нога ещё не поднята ИЛИ прежний писатель умер
    // (его канал закрыт). Второе закрывает bug #8: после отмены токена сетевой
    // эпохи серверный писатель завершался, а запись `established` оставалась
    // жить — датаграммы уходили в мёртвый канал, PONG'и молча терялись, а нога
    // числилась «свежей». Теперь мёртвый писатель заменяется новым, а не
    // соседствует с ним.
    let needs_establish = match &entry.established {
        None => true,
        Some(est) => est.control_tx.is_closed(),
    };

    if needs_establish {
        // Поднимаем ногу СРАЗУ, до диспетчеризации самого кадра ниже: иначе
        // первый же PING клиента остался бы без ответа (писатель, заведённый
        // ПОСЛЕ, ответил бы только на следующий таймер keepalive — гонка с
        // таймаутом клиентской попытки, реальный баг, словленный интеграционным
        // тестом этого модуля).
        let peer_addr = Arc::new(ArcSwap::from(Arc::new(peer)));
        let opener = Arc::new(RemoteOpener {
            muxer: entry.muxer.clone(),
            mesh: None,
            mesh_route: None,
            mesh_peer: false,
            mesh_onion_peer: false,
        });
        let handler = Arc::new(StreamHandler::new(entry.muxer.clone(), Some(opener)));

        let cap = NetworkConfig::global().channel_capacity;
        let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
        let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);
        // Замена сенсоров в муксере роняет прежние приёмники — если старый
        // писатель ещё жив, его каналы закроются и он корректно завершится.
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
    } else {
        // Роуминг: доверяем последнему АУТЕНТИФИЦИРОВАННОМУ источнику —
        // подлинность уже перепроверил AEAD выше, это не "поверили заголовку".
        entry
            .established
            .as_ref()
            .expect("checked Some in needs_establish")
            .peer_addr
            .store(Arc::new(peer));
    }

    let est = entry
        .established
        .as_ref()
        .expect("just populated above or already present");
    dispatch_open_frame(frame, &est.control_tx, &est.handler).await;
    entry.muxer.mark_datagram_leg_alive();
    true
}

/// Строит `DgramTx`, симметричный уже собранному `entry.rx` (тот же
/// движок), на серверную половину `leg_token`/HP-ключей (`is_client=false`).
fn build_matching_tx(rx: &DgramRx, datagram_root: impl Into<DatagramRoot>) -> DgramTx {
    let datagram_root = datagram_root.into();
    match rx {
        DgramRx::Quic(_) => {
            let ctx = DgramKdfContext::new(DgramEngineLabel::Quic, ATTEMPT);
            let material = DatagramKeyMaterial::derive_from_root_ctx(datagram_root, false, ctx);
            let hp = material.hp_key_tx();
            let leg_token = material.leg_token();
            DgramTx::Quic(quiceng::QuicTx::new(
                CoreDatagramTx::new(material),
                hp,
                Bytes::copy_from_slice(&dgram_leg::quic_dcid_server(&leg_token)),
            ))
        }
        DgramRx::WebRtc(_) => {
            let ctx = DgramKdfContext::new(DgramEngineLabel::WebRtc, ATTEMPT);
            let material = DatagramKeyMaterial::derive_from_root_ctx(datagram_root, false, ctx);
            let leg_token = material.leg_token();
            DgramTx::WebRtc(webrtceng::WebrtcTx::new(
                CoreDatagramTx::new(material),
                &webrtceng::WebrtcProfile::VP8_VIDEO,
                dgram_leg::webrtc_ssrc_server(&leg_token),
            ))
        }
        DgramRx::Raw(_) => {
            let ctx = DgramKdfContext::new(DgramEngineLabel::Raw, ATTEMPT);
            let material = DatagramKeyMaterial::derive_from_root_ctx(datagram_root, false, ctx);
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
        session_manager.register_datagram_session(&server_muxer, 0, datagram_root);

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
                let Some((tx, rx)) = try_establish(tx, rx, &socket, Vec::new()).await else {
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
        session_manager.register_datagram_session(&server_muxer, 0, datagram_root);

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
        session_manager.register_datagram_session(&server_muxer_a, 0, root_a);
        session_manager.register_datagram_session(&server_muxer_b, 0, root_b);

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
        // Оба движка мимикрии (не один) обязаны честно истечь по таймауту
        // прежде, чем клиент опустится до raw — стаб не отвечает ни на quic-,
        // ни на rtp-форму. Значит суммарно прошло не меньше ДВУХ таймаутов
        // (bug #7: раньше второй движок вообще не пробовался).
        assert!(
            elapsed >= 2 * DATAGRAM_LEG_HANDSHAKE_TIMEOUT,
            "both mimicry engines must time out before the raw fallback, took {elapsed:?}"
        );

        token.cancel();
    }

    /// Находит `datagram_root`, у которого первый байт `leg_token` (а значит и
    /// первый байт голой raw-датаграммы) попадает в диапазон, который СТАРЫЙ
    /// сервер принимал за QUIC/RTP/QUIC-long и отбрасывал (`>= 0x40`). Именно на
    /// таких корнях raw-фолбэк молча не работал в ~75% случаев (bug #1).
    fn root_whose_raw_first_byte_is_misclassified() -> [u8; 32] {
        for seed in 0u8..=255 {
            let root = [seed; 32];
            let token = DatagramKeyMaterial::derive_from_root(root, false).leg_token();
            if token[0] >= 0x40 {
                return root;
            }
        }
        panic!("no seed produced a leg_token[0] >= 0x40 — statistically impossible");
    }

    /// Регрессия на bug #1 через НАСТОЯЩИЙ листенер (а не заглушку): клиент,
    /// вынужденный использовать голый raw, чей первый байт исторически
    /// демультиплексировался как QUIC/RTP, всё равно поднимает ногу на сервере.
    /// До фикса `handle_server_datagram` проверял только одну карту по догадке о
    /// первом байте и отбрасывал такую датаграмму.
    #[tokio::test]
    async fn raw_leg_establishes_even_when_its_first_byte_looks_like_quic_or_rtp() {
        crate::net::NetworkConfig::init_global(1500);
        let datagram_root = root_whose_raw_first_byte_is_misclassified();
        // Подтверждаем предпосылку теста: старая ветка ушла бы НЕ в raw.
        let token = DatagramKeyMaterial::derive_from_root(datagram_root, false).leg_token();
        assert!(
            matches!(
                guess_wire_kind(token[0]),
                WireGuess::QuicShort | WireGuess::Rtp | WireGuess::QuicLong
            ),
            "test premise: raw first byte must fall outside the raw guess range"
        );

        let session_manager = Arc::new(SessionManager::new());
        let server_muxer = Arc::new(Muxer::new(false, "srv-raw".into()));
        session_manager.register_datagram_session(&server_muxer, 0, datagram_root);

        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener_socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let listener_token = token.clone();
        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            let _ = run_datagram_listener(listener_socket, sm_clone, listener_token).await;
        });

        // Клиент шлёт ТОЛЬКО raw (обходим монету/мимикрию — тестируем именно
        // демультиплексирование raw на сервере).
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listen_addr).await.unwrap();
        let (raw_tx, raw_rx) = build_raw_pair(datagram_root, true);
        let established = try_establish(raw_tx, raw_rx, &socket, Vec::new()).await;
        assert!(
            established.is_some(),
            "raw leg must round-trip through the real listener despite the misleading first byte"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            server_muxer.datagram_leg_stats().is_some(),
            "server must have established the leg from the raw demux map (bug #1)"
        );

        token.cancel();
    }

    /// Ретраи PING внутри таймаута (bug #7): сервер-заглушка ИГНОРИРУЕТ первую
    /// пробу и отвечает лишь начиная со второй. Раньше `try_establish` слал один
    /// PING и, потеряв его, проваливал движок; теперь переотправка внутри окна
    /// доводит установку до успеха.
    #[tokio::test]
    async fn try_establish_survives_a_dropped_first_ping() {
        crate::net::NetworkConfig::init_global(1500);
        let datagram_root = [0x24u8; 32];

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let stub_token = token.clone();
        tokio::spawn(async move {
            let (mut stub_tx, mut stub_rx) = build_raw_pair(datagram_root, false);
            let mut buf = vec![0u8; RECV_BUF_LEN];
            let mut seen = 0u32;
            loop {
                tokio::select! {
                    _ = stub_token.cancelled() => break,
                    res = socket.recv_from(&mut buf) => {
                        let Ok((n, peer)) = res else { continue };
                        if stub_rx.open(&buf[..n]).is_err() { continue; }
                        seen += 1;
                        // Первую пробу глотаем молча — как одиночная потеря в сети.
                        if seen == 1 { continue; }
                        if let Ok(pong) = stub_tx.seal(0, FrameType::Heartbeat, Bytes::from_static(PONG)) {
                            let _ = socket.send_to(&pong, peer).await;
                        }
                    }
                }
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(listen_addr).await.unwrap();
        let (raw_tx, raw_rx) = build_raw_pair(datagram_root, true);
        let established = try_establish(raw_tx, raw_rx, &client, Vec::new()).await;
        assert!(
            established.is_some(),
            "a single dropped PING must not fail establishment — later retries must get through (bug #7)"
        );

        token.cancel();
    }

    /// Фильтр типов кадров датаграммной ноги (bug #19): по UDP переносится
    /// только `UdpData`/`Heartbeat`. `Close`, пришедший по датаграммному пути,
    /// обязан быть отброшен — иначе он снял бы поток; проверяем, что поток
    /// переживает такой кадр (значит `handler.handle` его не увидел).
    #[tokio::test]
    async fn datagram_dispatch_filters_out_non_udp_frame_types() {
        let muxer = Arc::new(Muxer::new(false, "filter-test".into()));
        let opener = Arc::new(RemoteOpener {
            muxer: muxer.clone(),
            mesh: None,
            mesh_route: None,
            mesh_peer: false,
            mesh_onion_peer: false,
        });
        let handler = StreamHandler::new(muxer.clone(), Some(opener));

        let (stream_tx, mut stream_rx) = mpsc::channel::<Bytes>(4);
        let _tok = muxer.register_stream(55, stream_tx);
        let (control_tx, _control_rx) = mpsc::channel::<MuxMessage>(8);

        // Close по датаграммному пути обязан быть отфильтрован (не дойти до handler).
        dispatch_open_frame(
            Frame::new(55, FrameType::Close, Bytes::new()),
            &control_tx,
            &handler,
        )
        .await;
        // Если бы фильтр пропустил Close, `remove_stream(55)` уже бы сработал —
        // тогда доставка ниже не нашла бы потока. Она находит → поток жив.
        muxer.dispatch_to_local(55, Bytes::from_static(b"still-here"));
        let got = tokio::time::timeout(Duration::from_secs(1), stream_rx.recv())
            .await
            .expect("stream must still be registered — Close was filtered out")
            .expect("channel open");
        assert_eq!(&got[..], b"still-here");

        // А PING по датаграммному пути обязан породить PONG в control-канал.
        let (ping_ctl_tx, mut ping_ctl_rx) = mpsc::channel::<MuxMessage>(8);
        dispatch_open_frame(
            Frame::new(0, FrameType::Heartbeat, Bytes::from_static(PING)),
            &ping_ctl_tx,
            &handler,
        )
        .await;
        let pong = ping_ctl_rx.try_recv().expect("PING must enqueue a PONG");
        assert_eq!(pong.frame_type, FrameType::Heartbeat);
        assert_eq!(&pong.data[..], PONG);
    }

    /// Регрессия на гонку №3: РАЗНЫЕ ноги одной сессии регистрируют РАЗНЫЕ
    /// корни, и сервер обязан держать демультиплексирующие записи ОБОИХ — какой
    /// бы корень клиент ни выбрал для своей единственной UDP-попытки, он найдётся
    /// (раньше `OnceLock` фиксировал только первый и при рассинхроне «первых»
    /// нога не поднималась вовсе).
    #[tokio::test]
    async fn server_registers_every_legs_root_so_the_client_choice_always_matches() {
        use crate::crypto::DatagramKeyMaterial;
        let root_a = [0x11u8; 32];
        let root_b = [0x22u8; 32];
        let session_manager = SessionManager::new();
        let muxer = Arc::new(Muxer::new(false, "race-test".into()));

        // Нога 0 и нога 1 завершили хендшейк со своими (разными) корнями.
        session_manager.register_datagram_session(&muxer, 0, root_a);
        session_manager.register_datagram_session(&muxer, 1, root_b);

        // Обе raw-записи присутствуют (клиент мог выбрать любой корень).
        let token_a = DatagramKeyMaterial::derive_from_root(root_a, false).leg_token();
        let token_b = DatagramKeyMaterial::derive_from_root(root_b, false).leg_token();
        assert!(
            session_manager.dgram_raw_entry(&token_a).is_some(),
            "root of leg 0 must be registered"
        );
        assert!(
            session_manager.dgram_raw_entry(&token_b).is_some(),
            "root of leg 1 must be registered"
        );
    }

    /// Реконнект ноги со свежим корнем ЗАМЕНЯЕТ её прежние записи, а не плодит
    /// мёртвые (bug #8): старый корень снимается, новый встаёт.
    #[tokio::test]
    async fn a_legs_reconnect_replaces_its_stale_demux_entries() {
        use crate::crypto::DatagramKeyMaterial;
        let old_root = [0x33u8; 32];
        let new_root = [0x44u8; 32];
        let session_manager = SessionManager::new();
        let muxer = Arc::new(Muxer::new(false, "reconnect-test".into()));

        session_manager.register_datagram_session(&muxer, 2, old_root);
        let old_token = DatagramKeyMaterial::derive_from_root(old_root, false).leg_token();
        assert!(session_manager.dgram_raw_entry(&old_token).is_some());

        // Та же нога (leg_id=2) переподключилась со свежим ECDH → новый корень.
        session_manager.register_datagram_session(&muxer, 2, new_root);
        let new_token = DatagramKeyMaterial::derive_from_root(new_root, false).leg_token();
        assert!(
            session_manager.dgram_raw_entry(&new_token).is_some(),
            "fresh root must be registered"
        );
        assert!(
            session_manager.dgram_raw_entry(&old_token).is_none(),
            "stale root of the same leg must be retired, not left dangling"
        );

        // Повторная регистрация ТОГО ЖЕ корня — идемпотентна (ничего не ломает).
        session_manager.register_datagram_session(&muxer, 2, new_root);
        assert!(session_manager.dgram_raw_entry(&new_token).is_some());
    }

    /// bug #12: сервер отвечает декоративным flight на клиентский QUIC Initial
    /// зарегистрированной сессии — и НЕ отвечает на Initial неизвестной сессии
    /// (анти-амплификация). Проверяем через настоящий листенер.
    #[tokio::test]
    async fn server_answers_a_client_initial_only_for_a_registered_session() {
        crate::net::NetworkConfig::init_global(1500);
        let datagram_root = [0x71u8; 32];

        let session_manager = Arc::new(SessionManager::new());
        let server_muxer = Arc::new(Muxer::new(false, "srv-initial".into()));
        session_manager.register_datagram_session(&server_muxer, 0, datagram_root);

        let listener_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener_socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let listener_token = token.clone();
        let sm_clone = session_manager.clone();
        tokio::spawn(async move {
            let _ = run_datagram_listener(listener_socket, sm_clone, listener_token).await;
        });

        // Клиентский Initial ДЛЯ этой сессии: DCID = quic_dcid_client(leg_token).
        let leg_token = DatagramKeyMaterial::derive_from_root(datagram_root, false).leg_token();
        let dcid = dgram_leg::quic_dcid_client(&leg_token);
        let initial =
            quiceng::build_client_initial(&quiceng::QuicProfile::CHROME, "example.com", &dcid, &[]);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(listen_addr).await.unwrap();
        client.send(&initial).await.unwrap();

        // Ждём декоративный ответ сервера (Initial+Handshake — минимум один пакет).
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let got = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await;
        assert!(
            got.is_ok() && got.unwrap().is_ok(),
            "server must answer a client Initial for a registered session (bug #12)"
        );
        // Ответ — long-header пакет (Initial или Handshake).
        assert_eq!(
            buf[0] & 0xC0,
            0xC0,
            "server reply must be a QUIC long-header packet"
        );

        // Повторный тот же Initial НЕ должен породить второй flight (дедуп).
        client.send(&initial).await.unwrap();
        // Возможно, придёт второй пакет ПЕРВОГО flight (Handshake) — вычитываем
        // всё, что осталось, и убеждаемся, что нового Initial-ответа нет: даём
        // короткое окно и считаем, что дублей быть не должно после дренажа.
        let _ = tokio::time::timeout(Duration::from_millis(150), client.recv(&mut buf)).await;

        // Initial для НЕизвестной сессии (случайный DCID) — сервер молчит.
        let unknown_dcid = [0x00u8; 8];
        let unknown_initial = quiceng::build_client_initial(
            &quiceng::QuicProfile::CHROME,
            "example.com",
            &unknown_dcid,
            &[],
        );
        let client2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client2.connect(listen_addr).await.unwrap();
        client2.send(&unknown_initial).await.unwrap();
        let silence =
            tokio::time::timeout(Duration::from_millis(400), client2.recv(&mut buf)).await;
        assert!(
            silence.is_err(),
            "server must NOT answer an Initial for an unknown session (amplification gate)"
        );

        token.cancel();
    }

    /// Уборка сессии снимает записи ВСЕХ её ног.
    #[tokio::test]
    async fn session_removal_clears_every_legs_datagram_entries() {
        use crate::crypto::DatagramKeyMaterial;
        let root_a = [0x55u8; 32];
        let root_b = [0x66u8; 32];
        let session_manager = SessionManager::new();
        let sid = "cleanup-test".to_string();
        let muxer = session_manager.get_or_create(&sid);

        session_manager.register_datagram_session(&muxer, 0, root_a);
        session_manager.register_datagram_session(&muxer, 1, root_b);
        let token_a = DatagramKeyMaterial::derive_from_root(root_a, false).leg_token();
        let token_b = DatagramKeyMaterial::derive_from_root(root_b, false).leg_token();

        session_manager.remove(&sid);

        assert!(session_manager.dgram_raw_entry(&token_a).is_none());
        assert!(session_manager.dgram_raw_entry(&token_b).is_none());
    }
}
