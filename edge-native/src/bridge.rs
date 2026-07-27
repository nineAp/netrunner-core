//! Ведёт один edge-мост: TCP-нога до VPN-ноды (с NRXP-хендшейком) на одной
//! стороне, входящий WebSocket (принятый axum) на другой. Прямой native-порт
//! `run_bridge`/`complete_handshake` из `client-edge/src/lib.rs` (см. doc
//! там за полным описанием роли в топологии) — тот же протокол, та же
//! логика, отличается только транспорт: `tokio::net::TcpStream` вместо
//! `worker::Socket` (Cloudflare Sockets API) и `axum::extract::ws::WebSocket`
//! вместо `worker::WebSocketPair`. Собственно протокольный код (хендшейк,
//! кадры, шифрование) целиком в `netrunner_core::edge` — тут только доставка
//! байт между двумя сторонами.

use crate::EdgeConfig;
use axum::extract::ws::{Message, WebSocket};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use netrunner_core::edge::{EdgeFrameKind, EdgeHandshake, EdgeTunnel, HandshakeOutcome};
use netrunner_logger::{error, info};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Единственный логический stream_id, который эта edge-нога использует для
/// сквозного TCP-потока до `BACKEND_ADDR` (см. `EDGE_STREAM_ID` в
/// `client-edge/src/lib.rs` — то же самое значение и то же обоснование:
/// heartbeat-кадры идут на stream_id 0, поэтому 1 — первый свободный).
const EDGE_STREAM_ID: u32 = 1;

/// Размер буфера одного чтения TCP-соединения с ноги до ноды.
const SOCKET_READ_CHUNK: usize = 16 * 1024;

/// Точка входа моста — вызывается из `on_upgrade` после успешного WS-апгрейда.
/// Ошибки только логируются: WS-соединение уже принято клиентом, вернуть
/// HTTP-ошибку на этом этапе невозможно, остаётся просто закрыть сокет.
pub async fn run(ws: WebSocket, cfg: Arc<EdgeConfig>) {
    if let Err(e) = run_bridge(ws, &cfg).await {
        error!("[netrunner-edge] bridge failed: {e}");
    }
}

async fn run_bridge(mut ws: WebSocket, cfg: &EdgeConfig) -> Result<(), String> {
    let mut socket = TcpStream::connect(&cfg.vpn_node_addr)
        .await
        .map_err(|e| format!("connect({}) failed: {e}", cfg.vpn_node_addr))?;
    // Тот же приём, что и у полноценного клиента (см. `net::connection`) —
    // маленькие NRXP-кадры не должны копиться в буфере Nagle, задерживая
    // интерактивный трафик (RTT-чувствительные запросы через тоннель).
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
    info!(
        "[netrunner-edge] handshake with {} ok ({session_id})",
        cfg.vpn_node_addr
    );

    let auth_frame = tunnel.encode_auth_heartbeat(&session_id, 0, &cfg.auth_token)?;
    socket
        .write_all(&auth_frame)
        .await
        .map_err(|e| format!("write auth heartbeat: {e}"))?;

    let connect_frame = tunnel.encode_frame(
        EDGE_STREAM_ID,
        EdgeFrameKind::Connect,
        Bytes::from(cfg.backend_addr.clone()),
    )?;
    socket
        .write_all(&connect_frame)
        .await
        .map_err(|e| format!("write Connect frame: {e}"))?;

    let mut sock_buf = [0u8; SOCKET_READ_CHUNK];

    loop {
        tokio::select! {
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        let frame = tunnel.encode_frame(EDGE_STREAM_ID, EdgeFrameKind::Data, bytes)?;
                        socket
                            .write_all(&frame)
                            .await
                            .map_err(|e| format!("write Data frame: {e}"))?;
                    }
                    // Текстовые/ping/pong WS-сообщения игнорируются — протокол
                    // везёт только бинарные потоковые данные удалённого
                    // клиента (то же самое, что и в client-edge/src/lib.rs).
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(format!("websocket read error: {e}")),
                    None => {
                        let close_frame =
                            tunnel.encode_frame(EDGE_STREAM_ID, EdgeFrameKind::Close, Bytes::new())?;
                        let _ = socket.write_all(&close_frame).await;
                        return Ok(());
                    }
                }
            }
            n = socket.read(&mut sock_buf) => {
                let n = n.map_err(|e| format!("read from vpn node: {e}"))?;
                if n == 0 {
                    return Err("vpn node closed the tunnel leg".to_string());
                }
                for frame in tunnel.feed(&sock_buf[..n])? {
                    if frame.kind == EdgeFrameKind::Heartbeat {
                        // Нода периодически шлёт health-check PING на СВОЁМ
                        // произвольном probe stream_id (не 0, не EDGE_STREAM_ID
                        // — см. `Muxer::perform_health_check` в
                        // core/src/net/connection/muxer.rs) и ждёт PONG на том
                        // же stream_id в пределах HEALTH_CHECK_TIMEOUT (20с).
                        // Без ответа нода считает ногу мёртвой и эвиктит её —
                        // ЖИВОЙ БАГ: соединение обрывалось само по себе даже
                        // когда всё было исправно, просто потому что этот цикл
                        // никогда не отвечал на пинг (см. `StreamHandler::handle`
                        // в handler.rs за тем, как отвечает "толстый" клиент —
                        // ровно то же самое здесь, вручную, раз этот бридж не
                        // использует общий `StreamHandler`).
                        if &frame.payload[..] == b"PING" {
                            let pong = tunnel.encode_frame(
                                frame.stream_id,
                                EdgeFrameKind::Heartbeat,
                                Bytes::from_static(b"PONG"),
                            )?;
                            socket
                                .write_all(&pong)
                                .await
                                .map_err(|e| format!("write heartbeat pong: {e}"))?;
                        }
                        continue;
                    }
                    if frame.stream_id == 0 && frame.kind == EdgeFrameKind::Close {
                        // Явный отказ ноды (--require-auth и т.п.), не голый
                        // TCP EOF — stream_id=0 никогда не используется
                        // реальным Connect-потоком (см. EDGE_STREAM_ID).
                        let reason = String::from_utf8_lossy(&frame.payload[..]).into_owned();
                        return Err(format!("vpn node rejected connection: {reason}"));
                    }
                    if frame.stream_id != EDGE_STREAM_ID {
                        continue; // диагностика ноды — не наш поток
                    }
                    match frame.kind {
                        EdgeFrameKind::Data => {
                            if let Err(e) = ws.send(Message::Binary(frame.payload)).await {
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
/// необходимости — зеркало одноимённой функции в `client-edge/src/lib.rs`,
/// отличается только источником байт (`TcpStream` вместо `worker::Socket`).
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
