//! # netrunner-client-edge — NRXP-клиент для Cloudflare Workers (wasm32)
//!
//! Точка входа wasm-сборки, запускаемой Cloudflare Workers runtime'ом (не
//! `main()` — воркеры не самостоятельные исполняемые файлы, JS-раннер вызывает
//! экспортированный `fetch`-обработчик; см. `#[event(fetch)]` ниже, это
//! wasm-эквивалент `main.rs` для этой платформы).
//!
//! ## Роль в топологии
//!
//! ```text
//!   удалённый сервер            Cloudflare Worker (этот крейт)         VPN-нода                бэкенд
//!   (обычный TCP/WS-клиент) ──▶  WebSocket ⇄ NRXP-туннель (edge.rs)  ──▶  netrunner-server  ──▶  BACKEND_ADDR
//! ```
//!
//! Воркер здесь играет роль клиента протокола NRXP: он поднимает исходящий TCP
//! (через `worker::Socket` — Cloudflare Sockets API) до `VPN_NODE_ADDR`,
//! проводит тот же самый маскирующийся под TLS хендшейк, что и обычный
//! Linux/мобильный клиент (`ClientHandler::perform_handshake` в
//! `core/src/net/connection/connection.rs`), и дальше просто ретранслирует
//! байты в обе стороны между этим туннелем и входящим WebSocket-соединением от
//! удалённого сервера. Реальная логика протокола (хендшейк, кадры, шифрование)
//! не продублирована — она переиспользована из `netrunner_core::edge`,
//! отдельного платформо-независимого модуля ядра, который не тянет
//! `tokio::net` (недоступен на `wasm32-unknown-unknown`, поэтому обычный
//! `net::connection` для этой цели не компилируется).
//!
//! Мультиплексирования нескольких потоков внутри одного WS-соединения здесь
//! нет: один WebSocket = один логический стрим `EDGE_STREAM_ID` внутри одной
//! TCP-ноги до ноды. Этого достаточно для роли "точка входа перед нодой";
//! полноценный `Muxer` с несколькими ногами и failover остаётся у "толстых"
//! клиентов (TUN-VPN на Linux/Android/iOS).
//!
//! ## Конфигурация (Worker vars/secrets, `wrangler.toml`)
//!
//! - `VPN_NODE_ADDR` (var) — `host:port` вашей VPN-ноды (`netrunner-server`),
//!   например `1.2.3.4:443`.
//! - `BACKEND_ADDR` (var) — `host:port` цели, которую нода должна открыть по
//!   `Connect`-кадру (см. `ARCH.md`); это и есть тот самый "бэкенд", к
//!   которому в итоге приходит трафик.
//! - `DECOY_SNI` (var, опционально) — домен-декой для поддельного
//!   `ClientHello` (по умолчанию `www.debian.org`).
//! - `AUTH_TOKEN` (secret, опционально) — Bearer-токен, если нода поднята с
//!   `--require-auth`.

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use netrunner_core::edge::{EdgeFrameKind, EdgeHandshake, EdgeTunnel, HandshakeOutcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::*;

/// Единственный логический stream_id, который эта edge-нога использует для
/// сквозного TCP-потока к `BACKEND_ADDR`. Кадры Heartbeat идут на stream_id 0
/// (см. `EdgeTunnel::encode_auth_heartbeat`), поэтому 1 — первый свободный.
const EDGE_STREAM_ID: u32 = 1;

/// Размер буфера чтения одного `Socket::read`/TCP-чтения с ноги до ноды.
const SOCKET_READ_CHUNK: usize = 16 * 1024;

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let is_upgrade = req
        .headers()
        .get("Upgrade")?
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !is_upgrade {
        // Незамаскированный прямой запрос (не WS-апгрейд) — не наш случай
        // использования; отвечаем нейтрально, ничего не выдавая о протоколе.
        return Response::ok("netrunner edge relay");
    }

    let vpn_node = env.var("VPN_NODE_ADDR")?.to_string();
    let backend_addr = env.var("BACKEND_ADDR")?.to_string();
    let decoy_sni = env
        .var("DECOY_SNI")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "www.debian.org".to_string());
    let auth_token = env
        .secret("AUTH_TOKEN")
        .map(|v| v.to_string())
        .unwrap_or_default();

    let pair = WebSocketPair::new()?;
    let server = pair.server;
    server.accept()?;

    // wait_until держит воркер живым, пока идёт мост, но не блокирует ответ
    // клиенту с апгрейдом — тот уходит сразу вместе с pair.client ниже.
    let bridge_ws = server.clone();
    ctx.wait_until(async move {
        if let Err(e) = run_bridge(&bridge_ws, vpn_node, decoy_sni, backend_addr, auth_token).await
        {
            console_error!("[netrunner-edge] bridge failed: {e}");
        }
        let _ = bridge_ws.close(Some(1000), Some("bridge closed"));
    });

    Response::from_websocket(pair.client)
}

/// Ведёт один edge-мост: TCP-нога до `vpn_node` (с NRXP-хендшейком) на одной
/// стороне, входящий WebSocket на другой. Возвращается, когда любая из сторон
/// закрывается или протокол дал ошибку.
async fn run_bridge(
    ws: &WebSocket,
    vpn_node: String,
    decoy_sni: String,
    backend_addr: String,
    auth_token: String,
) -> std::result::Result<(), String> {
    let (host, port) = split_host_port(&vpn_node)?;

    let mut socket = Socket::builder()
        .secure_transport(SecureTransport::Off) // сами маскируемся под TLS вручную — реальный TLS тут не нужен
        .connect(host, port)
        .map_err(|e| format!("connect({vpn_node}) failed: {e}"))?;
    socket
        .opened()
        .await
        .map_err(|e| format!("socket to {vpn_node} did not open: {e}"))?;

    // session_id уходит в auth-heartbeat как есть — не обязан быть криптографически
    // случайным (это просто идентификатор сессии для логов/маршрутизации ноды),
    // поэтому JS Date.now()+случайный счётчик потоков вполне достаточно на edge.
    let session_id = format!(
        "edge-{:x}-{:x}",
        (js_sys::Date::now() as u64),
        (js_sys::Math::random() * u32::MAX as f64) as u32
    );

    let hello = EdgeHandshake::new(decoy_sni, &session_id);
    socket
        .write_all(&hello.client_hello_bytes())
        .await
        .map_err(|e| format!("write ClientHello: {e}"))?;

    let mut tunnel = complete_handshake(&mut socket, hello).await?;

    let auth_frame = tunnel.encode_auth_heartbeat(&session_id, 0, &auth_token)?;
    socket
        .write_all(&auth_frame)
        .await
        .map_err(|e| format!("write auth heartbeat: {e}"))?;

    let connect_frame = tunnel.encode_frame(
        EDGE_STREAM_ID,
        EdgeFrameKind::Connect,
        Bytes::from(backend_addr),
    )?;
    socket
        .write_all(&connect_frame)
        .await
        .map_err(|e| format!("write Connect frame: {e}"))?;

    let mut ws_events = ws.events().map_err(|e| e.to_string())?;
    let mut sock_buf = [0u8; SOCKET_READ_CHUNK];

    loop {
        tokio::select! {
            event = ws_events.next() => {
                match event {
                    Some(Ok(WebsocketEvent::Message(msg))) => {
                        if let Some(bytes) = msg.bytes() {
                            let frame = tunnel.encode_frame(
                                EDGE_STREAM_ID,
                                EdgeFrameKind::Data,
                                Bytes::from(bytes),
                            )?;
                            socket
                                .write_all(&frame)
                                .await
                                .map_err(|e| format!("write Data frame: {e}"))?;
                        }
                        // Текстовые WS-сообщения игнорируются — протокол везёт только
                        // бинарные потоковые данные удалённого сервера.
                    }
                    Some(Ok(WebsocketEvent::Close(_))) | None => {
                        let close_frame =
                            tunnel.encode_frame(EDGE_STREAM_ID, EdgeFrameKind::Close, Bytes::new())?;
                        let _ = socket.write_all(&close_frame).await;
                        return Ok(());
                    }
                    Some(Err(e)) => return Err(format!("websocket event stream error: {e}")),
                }
            }
            n = socket.read(&mut sock_buf) => {
                let n = n.map_err(|e| format!("read from vpn node: {e}"))?;
                if n == 0 {
                    return Err("vpn node closed the tunnel leg".to_string());
                }
                for frame in tunnel.feed(&sock_buf[..n])? {
                    if frame.stream_id == 0 && frame.kind == EdgeFrameKind::Close {
                        // Явный отказ ноды (см. connection.rs: провал validator.validate()
                        // при --require-auth), не голый TCP EOF — stream_id=0 никогда не
                        // используется реальным Connect-потоком (см. EDGE_STREAM_ID),
                        // это служебный канал наравне с heartbeat/diag.
                        let reason = String::from_utf8_lossy(&frame.payload[..]).into_owned();
                        return Err(format!("vpn node rejected connection: {reason}"));
                    }
                    if frame.stream_id != EDGE_STREAM_ID {
                        continue; // heartbeat/диагностика ноды — эту ногу не обслуживает более одного потока
                    }
                    match frame.kind {
                        EdgeFrameKind::Data => {
                            if let Err(e) = ws.send_with_bytes(&frame.payload[..]) {
                                return Err(format!("forward to websocket: {e}"));
                            }
                        }
                        EdgeFrameKind::Close => return Ok(()),
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Крутит `EdgeHandshake` до готового `EdgeTunnel`, дочитывая сокет по мере
/// необходимости (зеркало цикла `ClientHandler::perform_handshake` в ядре, но
/// управляемое явной обратной связью `feed`, а не `tokio::net::TcpStream`).
async fn complete_handshake(
    socket: &mut Socket,
    mut hs: EdgeHandshake,
) -> std::result::Result<EdgeTunnel, String> {
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

fn split_host_port(addr: &str) -> std::result::Result<(String, u16), String> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("VPN_NODE_ADDR must be host:port, got {addr:?}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("VPN_NODE_ADDR has an invalid port: {addr:?}"))?;
    Ok((host.to_string(), port))
}
