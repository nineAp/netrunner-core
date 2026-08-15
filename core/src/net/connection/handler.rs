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
                // stream_id=0 зарезервирован под heartbeat/diag (см. doc-
                // комментарий модуля и `connection.rs`, откуда сервер шлёт
                // "auth_rejected: <причина>" именно на этот id при
                // безоговорочном отказе токена) — ни один реальный
                // Connect-поток туда никогда не попадает, так что здесь можно
                // безопасно читать payload как текстовый сигнал, не путая его
                // с закрытием прикладного потока.
                //
                // РАНЬШЕ этот кадр обрабатывался наравне со всеми остальными
                // Close — payload не читался вообще, поэтому сервер честно
                // слал "auth_rejected", а клиент это никогда не видел:
                // `establish_leg` (connection.rs) в итоге всегда получал
                // общую ошибку "Движок остановлен" вместо ERR_AUTH_FAILED, и
                // `Muxer::mark_fatal` (единственное, что останавливает
                // бесконечный реконнект с тем же мёртвым токеном) не
                // вызывался НИКОГДА. На практике это годами держало клиента
                // с просроченным токеном в цикле "переподключение через 2с"
                // навечно — 4 ноги (MAX_TUNNEL_LEGS) × раз в LEG_RECONNECT_DELAY
                // дают устойчивые ~2 запроса/сек на internal/validate без
                // единого шанса самостоятельно остановиться.
                if stream_id == 0 {
                    if let Ok(reason) = std::str::from_utf8(frame.payload.as_ref()) {
                        if reason.starts_with("auth_rejected") {
                            warn!(
                                reason,
                                "🚫 [Tunnel] Server rejected auth token, marking session fatal"
                            );
                            self.muxer.mark_fatal();
                        }
                    }
                }
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

            FrameType::Cover => {
                // Набивка ради формы трафика (см. cover-flight в
                // `ServerHandler::run`): данных в таком кадре нет, у него нет
                // ни потока, ни адресата. Молча отбрасываем.
                //
                // Отдельная ветка нужна не только ради полноты `match`:
                // reader ноги отдаёт сюда КАЖДЫЙ разобранный кадр (см.
                // `TunnelEngine::run`), фильтра перед `handle` нет, так что
                // cover-кадры сюда доходят штатно на каждом хендшейке.
                trace!(stream_id, "🎭 [Tunnel] Cover frame discarded");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn client_handler() -> (StreamHandler, Arc<Muxer>) {
        let muxer = Arc::new(Muxer::new(true, "test-session".into()));
        (StreamHandler::new(muxer.clone(), None), muxer)
    }

    /// Регрессия на сам баг: сервер шлёт "auth_rejected: ..." Close-кадром на
    /// stream_id=0 при безоговорочном отказе токена (см. `connection.rs`), но
    /// раньше payload здесь вообще не читался — `mark_fatal()` не вызывался
    /// НИКОГДА, и клиент с мёртвым токеном реконнектился раз в
    /// LEG_RECONNECT_DELAY вечно (наблюдалось на проде: 4 ноги (MAX_TUNNEL_LEGS)
    /// держали ~2 запроса/сек на /internal/validate часами).
    #[tokio::test]
    async fn close_frame_with_auth_rejected_reason_marks_session_fatal() {
        let (handler, muxer) = client_handler();
        assert!(!muxer.is_fatal());

        let frame = Frame::new(
            0,
            FrameType::Close,
            Bytes::from_static(b"auth_rejected: account banned"),
        );
        handler.handle(frame).await;

        assert!(
            muxer.is_fatal(),
            "Close(stream_id=0, \"auth_rejected: ...\") обязан пометить сессию как фатальную"
        );
    }

    /// Обычное закрытие прикладного потока (stream_id != 0) не имеет отношения
    /// к авторизации — не должно гасить всю сессию.
    #[tokio::test]
    async fn close_frame_on_application_stream_does_not_mark_fatal() {
        let (handler, muxer) = client_handler();

        let frame = Frame::new(
            42,
            FrameType::Close,
            Bytes::from_static(b"auth_rejected: this text on the wrong stream_id doesn't count"),
        );
        handler.handle(frame).await;

        assert!(!muxer.is_fatal());
    }

    /// Пустой/обычный Close на служебном stream_id=0 (например, эвикт при
    /// закрытии сокета) — тоже не должен ложно триггерить фатальное состояние.
    #[tokio::test]
    async fn close_frame_on_control_stream_without_auth_rejected_text_does_not_mark_fatal() {
        let (handler, muxer) = client_handler();

        let frame = Frame::new(0, FrameType::Close, Bytes::new());
        handler.handle(frame).await;

        assert!(!muxer.is_fatal());
    }
}
