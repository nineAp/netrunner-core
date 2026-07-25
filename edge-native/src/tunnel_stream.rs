//! `TunnelStream` — представляет один Connect-поток внутри NRXP-туннеля до
//! VPN-ноды как обычный `AsyncRead + AsyncWrite`, чтобы поверх него можно
//! было поднять настоящий TLS-клиент (`tokio_rustls`) и HTTP/1
//! (`hyper::client::conn`) — им обоим нужен именно такой интерфейс, ни один
//! не знает и не должен знать про NRXP-кадрирование. Используется только
//! открытым HTTP-реверс-прокси (`proxy_http.rs`); WS-мост (`bridge.rs`)
//! работает с той же нодой напрямую через `EdgeTunnel`, без этой обёртки —
//! ему не нужен `AsyncRead`/`AsyncWrite`, только явный цикл кадров.

use bytes::{Buf, Bytes, BytesMut};
use netrunner_core::edge::{EdgeFrameKind, EdgeHandshake, EdgeTunnel, HandshakeOutcome};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::EdgeConfig;

/// Единственный логический stream_id на всю обёртку — `TunnelStream`
/// открывает СВОЮ собственную TCP-ногу до ноды на каждый вызов `connect`
/// (см. doc там), поэтому конфликтов id с другими потоками той же ноги нет —
/// heartbeat идёт на 0, поэтому 1, тот же выбор, что и в `bridge.rs`.
const TUNNEL_STREAM_ID: u32 = 1;
const SOCKET_READ_CHUNK: usize = 16 * 1024;

pub struct TunnelStream {
    socket: TcpStream,
    tunnel: EdgeTunnel,
    /// Декодированные, но ещё не отданные вызывающему коду байты Data-кадров
    /// нашего stream_id — один вызов `tunnel.feed()` может вернуть сразу
    /// несколько кадров, а `poll_read` отдаёт их по частям, по мере того,
    /// сколько попросил вызывающий буфер.
    read_buf: BytesMut,
    /// Переиспользуемый буфер одного `socket.read()` — заведён в структуре,
    /// а не создаётся заново на каждый `poll_read`, чтобы не платить
    /// zero-init 16 КБ на каждый вызов.
    read_raw: Box<[u8; SOCKET_READ_CHUNK]>,
    /// Закодированный, но ещё не полностью дописанный в сокет исходящий
    /// кадр — `poll_write` может столкнуться с частичной записью на уровне
    /// TCP (сам кадр крупнее одного успешного `socket.write()`), а по
    /// контракту `AsyncWrite` повторный вызов может прийти с ДРУГИМ
    /// буфером — реальный источник данных для дозаписи после `Pending`
    /// должен жить здесь, а не в аргументе `buf`.
    pending_write: BytesMut,
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

        let hello = EdgeHandshake::new(cfg.decoy_sni.clone(), &session_id);
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

        Ok(Self {
            socket,
            tunnel,
            read_buf: BytesMut::new(),
            read_raw: Box::new([0u8; SOCKET_READ_CHUNK]),
            pending_write: BytesMut::new(),
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
            match Pin::new(&mut this.socket).poll_read(cx, &mut raw_buf) {
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
                        if frame.stream_id == 0 && frame.kind == EdgeFrameKind::Close {
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
        if this.pending_write.is_empty() {
            let frame = match this.tunnel.encode_frame(
                TUNNEL_STREAM_ID,
                EdgeFrameKind::Data,
                Bytes::copy_from_slice(buf),
            ) {
                Ok(f) => f,
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
            };
            this.pending_write.extend_from_slice(&frame);
        }
        while !this.pending_write.is_empty() {
            match Pin::new(&mut this.socket).poll_write(cx, &this.pending_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tunnel socket write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => this.pending_write.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending_write.is_empty() {
            if let Ok(frame) =
                this.tunnel
                    .encode_frame(TUNNEL_STREAM_ID, EdgeFrameKind::Close, Bytes::new())
            {
                this.pending_write.extend_from_slice(&frame);
            }
        }
        while !this.pending_write.is_empty() {
            match Pin::new(&mut this.socket).poll_write(cx, &this.pending_write) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(n)) => this.pending_write.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }
}
