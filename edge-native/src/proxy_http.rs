//! Открытый HTTP(S)-реверс-прокси через уже собранный NRXP-туннель до ноды.
//!
//! Раньше через `netrunner-edge` могли пройти только клиенты, умеющие
//! говорить WebSocket (см. `bridge.rs`) — обычный переход по ссылке в
//! браузере получал только decoy-страницу. Здесь та же самая NRXP-нога до
//! ноды используется для настоящего HTTP-запроса: браузер видит реальный
//! ответ `BACKEND_ADDR`, а цепочка (эта VDS -> нода -> бэкенд) остаётся
//! замаскированной под обычный TLS ровно так же, как и для WS-клиентов —
//! осознанно "открытый прокси без контроля" (нет проверки, кто именно сюда
//! пришёл), см. `main.rs` за подробным разбором обоих слоёв маскировки.
//!
//! Настоящий TLS здесь — ВНУТРЕННИЙ слой: `TunnelStream` (см.
//! `tunnel_stream.rs`) — это просто ещё один поток байт (Connect-нога до
//! `BACKEND_ADDR`), NRXP ничего не знает про TLS поверх себя. `tokio_rustls`
//! поднимает настоящий TLS-клиент прямо на этом потоке до реального хоста
//! бэкенда — тем же способом, каким обычный reverse-proxy подключился бы к
//! апстриму напрямую по TCP, только вместо `TcpStream::connect` здесь
//! `TunnelStream::connect`.

use crate::tunnel_stream::TunnelStream;
use crate::EdgeConfig;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header;
use hyper_util::rt::TokioIo;
use netrunner_logger::{error, warn};
use rustls_pki_types::ServerName;
use std::sync::{Arc, LazyLock};
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

/// Верхняя граница тела запроса/ответа, которое прокси готов буферизовать
/// целиком в памяти — `hyper::client::conn::http1` в этой версии проще всего
/// использовать с уже собранным телом (`Full<Bytes>`), а не потоково; для
/// "открыть ссылку в браузере, попасть на сайт" (HTML/JSON/статика обычного
/// размера) этого достаточно. Большие файлы/апдейты через этот путь не
/// предполагаются — см. ограничения в README.md.
const MAX_PROXIED_BODY_BYTES: usize = 16 * 1024 * 1024;

/// По RFC 7230 §6.1 эти заголовки осмысленны только для ОДНОГО хопа
/// TCP-соединения и не должны слепо копироваться на другую сторону
/// reverse-proxy. `Content-Length`/`Transfer-Encoding` — отдельная и более
/// серьёзная причина: framing тела ответа/запроса вычисляет сам hyper по
/// фактическому типу `Body`, который мы передаём (`Full<Bytes>` на пути к
/// бэкенду, `axum::body::Body::from(bytes)` на пути к браузеру) — скопированное
/// значение этих заголовков с чужой стороны конфликтует с тем, что hyper сам
/// решает выставить, и рвёт HTTP-фрейминг соединения (ответ клиенту
/// перестаёт приходить вовсе, именно так и было обнаружено при живой проверке).
fn is_hop_by_hop(name: &hyper::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// Список доверенных корневых сертификатов — строится один раз на процесс
/// (не на каждый запрос): `webpki-roots` — статический набор, разбирать его
/// заново при каждом HTTP-запросе было бы чистой тратой CPU.
static TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
});

/// Точка входа из `main.rs::handle` — ошибки не всплывают наружу как
/// HTTP-5xx (подозрительно, не то, что показал бы обычный сайт при сбое),
/// а превращаются в ту же decoy-страницу, что и раньше отдавалась на любой
/// не-WS запрос: недоступность бэкенда/ноды снаружи должна выглядеть как
/// "тут просто дефолтная страница веб-сервера", а не как явная ошибка прокси.
pub async fn proxy(cfg: Arc<EdgeConfig>, req: axum::extract::Request) -> Response {
    match try_proxy(&cfg, req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("[netrunner-edge] http proxy failed: {e}");
            crate::decoy_response()
        }
    }
}

async fn try_proxy(cfg: &EdgeConfig, req: axum::extract::Request) -> Result<Response, String> {
    let (backend_host, _) = cfg
        .backend_addr
        .rsplit_once(':')
        .ok_or_else(|| format!("BACKEND_ADDR must be host:port, got {:?}", cfg.backend_addr))?;

    let tunnel_stream = TunnelStream::connect(cfg, &cfg.backend_addr).await?;

    let connector = TlsConnector::from(TLS_CONFIG.clone());
    let server_name = ServerName::try_from(backend_host.to_string())
        .map_err(|e| format!("invalid backend hostname {backend_host:?}: {e}"))?;
    let tls_stream = connector
        .connect(server_name, tunnel_stream)
        .await
        .map_err(|e| format!("TLS handshake with backend failed: {e}"))?;

    let (mut send_request, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .map_err(|e| format!("HTTP/1 handshake with backend failed: {e}"))?;

    // Живёт ровно на один запрос-ответ — TunnelStream не пулится между
    // запросами (см. doc в tunnel_stream.rs), так что и эта задача завершится
    // сама, как только send_request выше закроет свою сторону.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            warn!("[netrunner-edge] backend connection closed: {e}");
        }
    });

    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut out_req = hyper::Request::builder()
        .method(parts.method)
        .uri(path_and_query);
    for (name, value) in parts.headers.iter() {
        // Host переписываем на реальный бэкенд ниже — иначе бэкенд увидит
        // домен ЭТОЙ VDS и не поймёт, какой виртуальный хост отдавать (то
        // же самое сделал бы любой обычный reverse-proxy). Hop-by-hop —
        // см. doc `is_hop_by_hop`.
        if name != header::HOST && !is_hop_by_hop(name) {
            out_req = out_req.header(name, value);
        }
    }
    out_req = out_req.header(header::HOST, backend_host);

    let body_bytes = axum::body::to_bytes(body, MAX_PROXIED_BODY_BYTES)
        .await
        .map_err(|e| format!("reading request body: {e}"))?;
    let out_req = out_req
        .body(Full::new(body_bytes))
        .map_err(|e| format!("building proxied request: {e}"))?;

    let resp = send_request
        .send_request(out_req)
        .await
        .map_err(|e| format!("sending proxied request: {e}"))?;

    let (parts, body) = resp.into_parts();
    let body_bytes: Bytes = body
        .collect()
        .await
        .map_err(|e| format!("reading backend response body: {e}"))?
        .to_bytes();

    let mut builder = Response::builder().status(parts.status);
    if let Some(headers) = builder.headers_mut() {
        // `.iter()`, не `.into_iter()`: он отдаёт по одной полноценной
        // `(&HeaderName, &HeaderValue)` паре на КАЖДОЕ значение (в т.ч.
        // повторные, как `Set-Cookie`), без "None = то же имя, что у
        // предыдущей записи" — фильтрация по имени тогда безопасна и не
        // рвёт группировку многозначных заголовков.
        headers.extend(
            parts
                .headers
                .iter()
                .filter(|(name, _)| !is_hop_by_hop(name))
                .map(|(name, value)| (name.clone(), value.clone())),
        );
    }
    builder
        .body(Body::from(body_bytes))
        .map_err(|e| format!("building response: {e}"))
        .map(IntoResponse::into_response)
}
