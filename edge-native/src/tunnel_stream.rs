//! `TunnelStream` — представляет один Connect-поток внутри NRXP-туннеля до
//! VPN-ноды как обычный `AsyncRead + AsyncWrite`, чтобы поверх него можно
//! было поднять настоящий TLS-клиент (`tokio_rustls`) и HTTP/1
//! (`hyper::client::conn`) — им обоим нужен именно такой интерфейс, ни один
//! не знает и не должен знать про NRXP-кадрирование. Используется только
//! открытым HTTP-реверс-прокси (`proxy_http.rs`); WS-мост (`bridge.rs`)
//! работает с той же нодой напрямую через `EdgeTunnel`, без этой обёртки —
//! ему не нужен `AsyncRead`/`AsyncWrite`, только явный цикл кадров.
//!
//! Чтение и запись сокета разнесены по разным задачам (`into_split` +
//! отдельный writer-таск) НЕ ради производительности, а из-за живого бага:
//! нода шлёт health-check PING на произвольном probe stream_id и ждёт PONG,
//! иначе через HEALTH_CHECK_TIMEOUT (20с) эвиктит ногу (см.
//! `Muxer::perform_health_check` в core/src/net/connection/muxer.rs). Раньше
//! `poll_read` складывал PONG в буфер, который сливался только когда hyper
//! САМ вызывал `poll_write` — а простаивающему в пуле keep-alive-соединению
//! `proxy_http.rs::landing_pool`/`backend_pool` писать НЕЧЕГО, так что hyper
//! запись не дёргал, PONG не уходил, и нода рвала полностью исправные
//! пуловые соединения сама (живая проверка: пуловое соединение умирало
//! ровно ~20с спустя после последнего использования — событие "backend
//! connection closed" в логе точно совпадало с HEALTH_CHECK_TIMEOUT).
//! Теперь `poll_read`, увидев PING, кидает PONG в канал к writer-таску
//! НЕМЕДЛЕННО и синхронно (`try_send`, не требует `.await`/`Poll`) — вообще
//! не завися от того, вызывает ли hyper `poll_write` в этот момент.

use bytes::{Bytes, BytesMut};
use netrunner_core::edge::{EdgeFrameKind, EdgeHandshake, EdgeTunnel, HandshakeOutcome};
use netrunner_logger::warn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::EdgeConfig;

/// Единственный логический stream_id на всю обёртку — `TunnelStream`
/// открывает СВОЮ собственную TCP-ногу до ноды на каждый вызов `connect`
/// (см. doc там), поэтому конфликтов id с другими потоками той же ноги нет —
/// heartbeat идёт на 0, поэтому 1, тот же выбор, что и в `bridge.rs`.
const TUNNEL_STREAM_ID: u32 = 1;
const SOCKET_READ_CHUNK: usize = 16 * 1024;

/// Ёмкость канала до writer-таска — исходящих кадров одновременно в полёте
/// немного (обычно один `Data`-кадр на `poll_write` + изредка один PONG),
/// с большим запасом на случай короткого всплеска.
const WRITE_CHANNEL_CAPACITY: usize = 32;

pub struct TunnelStream {
    read_half: OwnedReadHalf,
    tunnel: EdgeTunnel,
    /// Для `poll_write` (нужен poll-совместимый reserve+send, см.
    /// `tokio_util::sync::PollSender`) — единственный владелец права
    /// "зарезервировать слот", поэтому не клонируется.
    write_tx: PollSender<Bytes>,
    /// Для PONG из `poll_read` — обычный клон `Sender` того же канала:
    /// `try_send` не требует `Poll`/резервирования и не конфликтует с
    /// `write_tx` (mpsc допускает много `Sender` на один канал).
    control_tx: mpsc::Sender<Bytes>,
    /// Декодированные, но ещё не отданные вызывающему коду байты Data-кадров
    /// нашего stream_id — один вызов `tunnel.feed()` может вернуть сразу
    /// несколько кадров, а `poll_read` отдаёт их по частям, по мере того,
    /// сколько попросил вызывающий буфер.
    read_buf: BytesMut,
    /// Переиспользуемый буфер одного `read_half.read()` — заведён в
    /// структуре, а не создаётся заново на каждый `poll_read`, чтобы не
    /// платить zero-init 16 КБ на каждый вызов.
    read_raw: Box<[u8; SOCKET_READ_CHUNK]>,
    eof: bool,
}

impl TunnelStream {
    /// Дозвон + NRXP-хендшейк + auth-heartbeat + `Connect`-кадр до
    /// `target_addr` — то же самое, что `bridge::run_bridge` делает перед
    /// своим циклом моста, только без входящего WebSocket: результат этой
    /// функции сам является потоком байт для дальнейшей обёртки в TLS.
    pub async fn connect(cfg: &EdgeConfig, target_addr: &str) -> Result<Self, String> {
        let mut socket = TcpStream::connect(&cfg.vpn_node_addr)
            .await
            .map_err(|e| format!("connect({}) failed: {e}", cfg.vpn_node_addr))?;
        let _ = socket.set_nodelay(true);

        let session_id = format!(
            "edge-{:016x}-{:08x}",
            rand::random::<u64>(),
            rand::random::<u32>()
        );

        let hello =
            EdgeHandshake::with_identity(cfg.decoy_sni.clone(), &session_id, cfg.identity.clone());
        socket
            .write_all(&hello.client_hello_bytes())
            .await
            .map_err(|e| format!("write ClientHello: {e}"))?;

        let mut tunnel = complete_handshake(&mut socket, hello).await?;

        let auth_frame = tunnel.encode_auth_heartbeat(&session_id, 0, &cfg.auth_token)?;
        socket
            .write_all(&auth_frame)
            .await
            .map_err(|e| format!("write auth heartbeat: {e}"))?;

        let connect_frame = tunnel.encode_frame(
            TUNNEL_STREAM_ID,
            EdgeFrameKind::Connect,
            Bytes::from(target_addr.to_string()),
        )?;
        socket
            .write_all(&connect_frame)
            .await
            .map_err(|e| format!("write Connect frame: {e}"))?;

        // Дальше чтение и запись идут раздельно — см. doc на модуль за тем,
        // почему: writer-таск владеет своей половиной единолично и пишет
        // всё, что придёт по каналу (обычные Data-кадры из poll_write И
        // health-check PONG из poll_read), независимо от того, что в этот
        // момент делает вызывающий код (hyper) с нашим `AsyncWrite`.
        let (read_half, write_half) = socket.into_split();
        let (tx, mut rx) = mpsc::channel::<Bytes>(WRITE_CHANNEL_CAPACITY);
        let control_tx = tx.clone();

        tokio::spawn(async move {
            let mut write_half = write_half;
            while let Some(chunk) = rx.recv().await {
                if let Err(e) = write_half.write_all(&chunk).await {
                    warn!("[netrunner-edge] tunnel writer failed: {e}");
                    return;
                }
            }
            // Все Sender/PollSender сброшены (TunnelStream уничтожен) —
            // канал закрылся сам, это штатное завершение, не ошибка.
            let _ = write_half.shutdown().await;
        });

        Ok(Self {
            read_half,
            tunnel,
            write_tx: PollSender::new(tx),
            control_tx,
            read_buf: BytesMut::new(),
            read_raw: Box::new([0u8; SOCKET_READ_CHUNK]),
            eof: false,
        })
    }
}

/// Крутит `EdgeHandshake` до готового `EdgeTunnel` — идентична одноимённой
/// функции в `bridge.rs`; не вынесена в общий модуль намеренно (две копии
/// самодостаточного 20-строчного цикла дешевле, чем ещё один shared-модуль
/// ради одной функции — см. CLAUDE.md-принцип "не плодить абстракции").
async fn complete_handshake(
    socket: &mut TcpStream,
    mut hs: EdgeHandshake,
) -> Result<EdgeTunnel, String> {
    let mut buf = BytesMut::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = socket
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read during handshake: {e}"))?;
        if n == 0 {
            return Err("vpn node closed connection during handshake".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);

        match hs.feed(&mut buf)? {
            HandshakeOutcome::NeedMore(next) => hs = next,
            HandshakeOutcome::Done(tunnel) => return Ok(tunnel),
        }
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let n = std::cmp::min(buf.remaining(), this.read_buf.len());
                let chunk = this.read_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                // Пустое чтение без ошибки — стандартный сигнал EOF для
                // AsyncRead (buf остаётся нетронутым).
                return Poll::Ready(Ok(()));
            }

            let mut raw_buf = ReadBuf::new(this.read_raw.as_mut_slice());
            match Pin::new(&mut this.read_half).poll_read(cx, &mut raw_buf) {
                Poll::Ready(Ok(())) => {
                    let n = raw_buf.filled().len();
                    if n == 0 {
                        this.eof = true;
                        continue;
                    }
                    let frames = match this.tunnel.feed(&this.read_raw[..n]) {
                        Ok(f) => f,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)))
                        }
                    };
                    for frame in frames {
                        if frame.kind == EdgeFrameKind::Heartbeat {
                            // Нода периодически шлёт health-check PING на
                            // произвольном probe stream_id (не 0, не
                            // TUNNEL_STREAM_ID) и ждёт PONG на том же
                            // stream_id — см. doc на модуль за тем, почему
                            // это `try_send` в канал, а не буфер на слив
                            // потом.
                            if &frame.payload[..] == b"PING" {
                                if let Ok(pong) = this.tunnel.encode_frame(
                                    frame.stream_id,
                                    EdgeFrameKind::Heartbeat,
                                    Bytes::from_static(b"PONG"),
                                ) {
                                    let _ = this.control_tx.try_send(pong);
                                }
                            }
                        } else if frame.stream_id == 0 && frame.kind == EdgeFrameKind::Close {
                            // Явный отказ ноды (--require-auth и т.п.) —
                            // трактуем как обрыв, вызывающий код (TLS/HTTP
                            // поверх) увидит это как оборванное соединение,
                            // с понятной причиной уже залогированной ранее
                            // в auth-heartbeat.
                            this.eof = true;
                        } else if frame.stream_id == TUNNEL_STREAM_ID {
                            match frame.kind {
                                EdgeFrameKind::Data => {
                                    this.read_buf.extend_from_slice(&frame.payload)
                                }
                                EdgeFrameKind::Close => this.eof = true,
                                _ => {}
                            }
                        }
                    }
                    // Возвращаемся к началу цикла: либо есть, что отдать из
                    // read_buf, либо eof, либо читаем сокет ещё раз.
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "tunnel writer task gone",
                )))
            }
            Poll::Pending => return Poll::Pending,
        }
        let frame = match this.tunnel.encode_frame(
            TUNNEL_STREAM_ID,
            EdgeFrameKind::Data,
            Bytes::copy_from_slice(buf),
        ) {
            Ok(f) => f,
            Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
        };
        match this.write_tx.send_item(frame) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel writer task gone",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Реальная запись идёт асинхронно в writer-таске (см. doc на
        // модуль) — раздельного сигнала "уже точно ушло в сокет" отсюда нет,
        // а сам writer-таск пишет их last-in-first-out по мере поступления
        // в канал, так что "передано в канал" — практический эквивалент
        // "flushed" для этого транспорта (тот же принцип, что раньше был у
        // TcpStream::poll_flush — для сырого TCP это всегда no-op).
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Лучшее усилие: сообщаем ноде о закрытии Close-кадром, если канал
        // до writer-таска ещё жив и не занят резервированием из poll_write
        // прямо сейчас. Реальный TCP FIN уйдёт от writer-таска сам, как
        // только этот `TunnelStream` (и все его Sender/PollSender) будут
        // уничтожены — ждать этого здесь синхронно не нужно.
        if let Ok(frame) =
            this.tunnel
                .encode_frame(TUNNEL_STREAM_ID, EdgeFrameKind::Close, Bytes::new())
        {
            if let Some(sender) = this.write_tx.get_ref() {
                let _ = sender.try_send(frame);
            }
        }
        Poll::Ready(Ok(()))
    }
}
