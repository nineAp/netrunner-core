//! Диспетчеризация входящих кадров туннеля по их типу и `stream_id`.
//!
//! [`StreamHandler`] — это «маршрутизатор» на приёмной стороне: один кадр входит,
//! и в зависимости от типа происходит одно из:
//! - `Heartbeat` → ответить PONG / измерить RTT / переслать локально;
//! - `Connect`/`UdpConnect` → (только сервер) открыть соединение к цели;
//! - `Data`/`UdpData` → доставить данные в локальный поток (с backpressure);
//! - `Close` → закрыть поток.
//!
//! Открытием реальных соединений к целям занимается [`RemoteOpener`] (есть только
//! на сервере: у клиента `opener == None`, поэтому входящие `Connect` отвергаются).
//! Каждое открытое соединение защищено [`CancellationToken`] — при эвикте/закрытии
//! потока мост и установка соединения мгновенно обрываются.

use bytes::Bytes;
use netrunner_logger::{debug, trace, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::net::{
    connection::{
        bridge::{run_tcp_bridge, run_udp_bridge},
        muxer::Muxer,
    },
    NetworkConfig,
};
use crate::nrxp::{Frame, FrameType};

/// Открыватель реальных соединений к целям (серверная сторона туннеля).
///
/// На каждый входящий `Connect`/`UdpConnect` поднимает TCP/UDP-сокет к цели и
/// запускает соответствующий мост, прокачивающий данные между туннелем и целью.
pub struct RemoteOpener {
    pub muxer: Arc<Muxer>,
}

impl RemoteOpener {
    /// Открывает TCP-соединение к `target` и запускает TCP-мост.
    ///
    /// Всё происходит в отдельной задаче. Установка соединения (тайм-аут 7 с) и
    /// сам мост обёрнуты в `select!` с `token.cancelled()` — эвикт обрывает их
    /// немедленно. При неудаче подключения шлёт `Close` обратно в туннель. По
    /// завершении всегда снимает регистрацию потока.
    pub async fn open_tcp(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let muxer = self.muxer.clone();
        tokio::spawn(async move {
            // Приватность: НЕ логируем `target` (хост, к которому идёт пользователь)
            // — это ровно та информация о его активности, которую прокси не должен
            // хранить нигде. `stream_id` достаточно для локальной корреляции.
            debug!(stream_id, "🌐 [Remote] Connecting");
            let start = Instant::now();

            tokio::select! {
                _ = token.cancelled() => {
                    debug!(stream_id, "🔪 Target connection cancelled by Eviction");
                    return;
                }
                connect_res = tokio::time::timeout(Duration::from_secs(7), TcpStream::connect(&target)) => {
                    match connect_res {
                        Ok(Ok(stream)) => {
                            debug!(stream_id, elapsed_ms = start.elapsed().as_millis() as u64, "✅ [Remote] Connected");
                            let (r, w) = stream.into_split();

                            // Credit-gated reads (Muxer::consume_credit) were tried here and
                            // reverted: tying read pacing to a network round-trip produced
                            // burst-then-stall downloads and jitter on the shared physical leg,
                            // on top of the local mpsc backpressure that already paced reads
                            // correctly. The Credit frame/API stays in Muxer for a possible
                            // future redesign but isn't wired up on this path anymore.

                            // 🔥 Защищаем и сам мост токеном отмены
                            tokio::select! {
                                _ = token.cancelled() => { debug!(stream_id, "🔪 TCP bridge closed by Eviction"); }
                                _ = run_tcp_bridge(stream_id, r, w, muxer.clone(), v_rx) => {}
                            }
                            // 🔥 Сообщаем клиенту, что поток завершён — неважно, из-за
                            // EOF цели, write-timeout ноги, истёкшего STREAM_PAUSE_BUDGET
                            // или нашей же эвикции по бэклогу. Раньше это отправлялось
                            // только при неудачном CONNECT: при штатном завершении моста
                            // клиент никогда не узнавал, что стрим кончился — его
                            // виртуальный TCP-сокет навсегда застревал в CloseWait (ждёт
                            // от нас Close, см. server_eof/socket.close() в клиентском
                            // TcpConnection::poll_and_process), и освобождался только
                            // 120-секундным idle-таймаутом, попутно замедляя весь движок.
                            let _ = muxer
                                .send_control(stream_id, FrameType::Close, Bytes::new())
                                .await;
                        }
                        _ => {
                            warn!(stream_id, "❌ [Remote] Target connection failed");
                            let _ = muxer.send_control(stream_id, FrameType::Close, Bytes::new()).await;
                        }
                    }
                }
            }
            muxer.remove_stream(stream_id);
        });
    }

    /// Биндит UDP-сокет, «подключает» его к `target` и запускает UDP-мост.
    /// Так же защищено токеном отмены; по завершении снимает регистрацию потока.
    pub async fn open_udp(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let muxer = self.muxer.clone();
        tokio::spawn(async move {
            debug!(stream_id, "🚀 [Remote] Binding UDP");
            tokio::select! {
                _ = token.cancelled() => { return; }
                _ = async {
                    let socket = UdpSocket::bind("0.0.0.0:0").await.ok();
                    if let Some(s) = socket {
                        if s.connect(&target).await.is_ok() {
                            run_udp_bridge(stream_id, s, muxer.clone(), v_rx).await;
                        }
                    }
                } => {}
            }
            muxer.remove_stream(stream_id);
        });
    }
}

/// Маршрутизатор входящих кадров. Наличие `opener` определяет роль:
/// `Some` — серверная сторона (умеет открывать соединения к целям),
/// `None` — клиентская (входящие `Connect` отвергаются).
pub(crate) struct StreamHandler {
    muxer: Arc<Muxer>,
    opener: Option<Arc<RemoteOpener>>,
}

impl StreamHandler {
    pub(crate) fn new(muxer: Arc<Muxer>, opener: Option<Arc<RemoteOpener>>) -> Self {
        Self { muxer, opener }
    }

    /// Диспетчеризует один кадр по типу. Для `Data`/`UdpData` доставка идёт через
    /// `await` (backpressure ради сохранения порядка), для управляющих —
    /// в отдельных задачах, чтобы не блокировать reader ноги.
    pub(crate) async fn handle(&self, frame: Frame) {
        let stream_id = frame.header.stream_id;

        match frame.header.frame_type {
            FrameType::Heartbeat => {
                let payload = frame.payload.as_ref();
                if payload == b"PING" {
                    trace!(stream_id, "🤝 [Tunnel] PING received, replying PONG");
                    let muxer = self.muxer.clone();
                    tokio::spawn(async move {
                        let _ = muxer
                            .send_control(stream_id, FrameType::Heartbeat, Bytes::from("PONG"))
                            .await;
                    });
                } else if payload == b"PONG" {
                    trace!(stream_id, "🤝 [Tunnel] PONG received");
                    self.muxer.dispatch_to_local(stream_id, frame.payload);
                } else {
                    if self.opener.is_some() {
                        trace!(
                            stream_id,
                            "💓 [Server] Standard Heartbeat received, sending reply"
                        );
                        let muxer = self.muxer.clone();
                        tokio::spawn(async move {
                            let _ = muxer
                                .send_control(stream_id, FrameType::Heartbeat, Bytes::new())
                                .await;
                        });
                    } else {
                        trace!(stream_id, "💓 [Client] Standard Heartbeat reply received");
                    }
                }
            }

            FrameType::Connect => {
                self.handle_conn_request(stream_id, frame.payload, false)
                    .await
            }
            FrameType::UdpConnect => {
                self.handle_conn_request(stream_id, frame.payload, true)
                    .await
            }

            FrameType::Data | FrameType::UdpData => {
                // Non-blocking: in-order delivery is guaranteed by the stream's
                // single persistent backlog-drainer task, not by awaiting here.
                self.muxer.dispatch_to_local(stream_id, frame.payload);
            }

            FrameType::Close => {
                debug!(stream_id, "🏁 [Tunnel] Peer closed stream");
                self.muxer.remove_stream(stream_id);
            }

            FrameType::Credit => {
                // Сквозной flow control (см. Muxer::consume_credit/grant_credit):
                // приёмник шлёт "можешь прислать ещё N байт". Синхронно и дёшево —
                // просто прибавляет к атомарному счётчику и будит ждущего отправителя.
                if let Ok(bytes) = frame.payload.as_ref().try_into().map(u32::from_be_bytes) {
                    trace!(stream_id, bytes, "💳 [Tunnel] Credit received");
                    self.muxer.grant_credit(stream_id, bytes);
                } else {
                    warn!(stream_id, "Malformed Credit frame payload, ignoring");
                }
            }

            FrameType::Diag => {
                // Диагностика клиента, доставленная по туннелю. Осмысленна только
                // на сервере: пересылаем в сток вместе с id сессии (берём из
                // muxer'а — на сервере это сессия этой ноги). На клиенте сток не
                // поднят, поэтому отчёт просто отбрасывается. Никогда не идёт в
                // локальные сокеты и не маршрутизируется как данные.
                let session_id = self.muxer.session_id().to_string();
                let json_line = String::from_utf8_lossy(&frame.payload).into_owned();
                trace!(
                    session_id = %session_id,
                    bytes = json_line.len(),
                    "🩺 [Tunnel] Client diagnostics report received"
                );
                crate::net::diagnostics::report_client_diag(
                    crate::net::diagnostics::ClientDiagReport {
                        session_id,
                        json_line,
                    },
                );
            }
        }
    }

    /// Обрабатывает `Connect`/`UdpConnect`: регистрирует поток (получая токен
    /// отмены) и просит [`RemoteOpener`] открыть соединение. На клиенте (нет
    /// opener) — отказ с `Close`. `payload` несёт адрес цели строкой `"ip:port"`.
    async fn handle_conn_request(&self, stream_id: u32, payload: Bytes, is_udp: bool) {
        let target = String::from_utf8_lossy(&payload).to_string();

        if let Some(opener) = &self.opener {
            let cap = NetworkConfig::global().channel_capacity;
            let (v_tx, v_rx) = mpsc::channel::<Bytes>(cap);

            // 🔥 Собираем токен для мгновенного обрыва связи при Eviction.
            // Больший бэклог, чем клиентский дефолт: реальная цель в интернете
            // медленнее и капризнее локального TUN — аплоаду нужен запас (см.
            // SERVER_STREAM_BACKLOG_MAX_BYTES).
            let cancel_token = self.muxer.register_stream_with_backlog_cap(
                stream_id,
                v_tx,
                crate::net::SERVER_STREAM_BACKLOG_MAX_BYTES,
            );

            if is_udp {
                opener.open_udp(stream_id, target, v_rx, cancel_token).await;
            } else {
                opener.open_tcp(stream_id, target, v_rx, cancel_token).await;
            }
        } else {
            warn!(
                stream_id,
                "⚠️ [Tunnel] Rejected incoming connection to {} (Client mode)", target
            );
            let muxer = self.muxer.clone();
            tokio::spawn(async move {
                let _ = muxer
                    .send_control(stream_id, FrameType::Close, Bytes::new())
                    .await;
            });
        }
    }
}
