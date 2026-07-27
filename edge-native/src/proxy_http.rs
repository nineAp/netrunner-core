//! Открытый HTTP(S)-реверс-прокси через уже собранный NRXP-туннель до ноды.
//!
//! Раньше через `netrunner-edge` могли пройти только клиенты, умеющие
//! говорить WebSocket (см. `bridge.rs`) — обычный переход по ссылке в
//! браузере получал только decoy-страницу. Здесь та же самая NRXP-нога до
//! ноды используется для настоящего HTTP-запроса: браузер видит реальный
//! ответ, а цепочка (эта VDS -> нода -> апстрим) остаётся замаскированной под
//! обычный TLS ровно так же, как и для WS-клиентов — осознанно "открытый
//! прокси без контроля" (нет проверки, кто именно сюда пришёл), см. `main.rs`
//! за подробным разбором обоих слоёв маскировки.
//!
//! Апстрим — не один хост, а два: `LANDING_ADDR` (сама разметка сайта) и
//! `BACKEND_ADDR` (его API) — см. `route_for` за тем, как путь запроса решает,
//! куда его вести, и `EdgeConfig::landing_addr`/`backend_addr` за тем, почему
//! разделять их вообще пришлось (зеркалируемый лендинг и его API живут на
//! разных хостах, один `BACKEND_ADDR` на всё запросы к API 404-ил).
//!
//! Настоящий TLS здесь — ВНУТРЕННИЙ слой: `TunnelStream` (см.
//! `tunnel_stream.rs`) — это просто ещё один поток байт (Connect-нога до
//! выбранного апстрима), NRXP ничего не знает про TLS поверх себя.
//! `tokio_rustls` поднимает настоящий TLS-клиент прямо на этом потоке до
//! реального хоста — тем же способом, каким обычный reverse-proxy
//! подключился бы к апстриму напрямую по TCP, только вместо
//! `TcpStream::connect` здесь `TunnelStream::connect`.

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
use std::time::Duration;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

/// Один keep-alive HTTP/1.1-отправитель поверх уже установленного
/// NRXP-туннеля + внутреннего TLS до бэкенда — то, чем реально владеет пул в
/// `EdgeConfig::conn_pool` (см. её doc-комментарий за тем, зачем пул вообще
/// нужен).
pub(crate) type PooledSender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

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

/// Разбирает путь запроса и решает, куда его вести. Два независимых сигнала,
/// оба ведут на `BACKEND_ADDR`:
/// - подстрока `/api/` — вызов API (`/en/account/api/v1/auth/telegram/session`);
/// - подстрока `/account` — весь раздел "аккаунт" целиком, а не только его
///   API: в оригинале сам сайт уводит браузер на другой хост
///   (`account.netrunner-vpn.com/profile`) для ЭТИХ страниц, т.е. фронт
///   раздела "аккаунт" (не только его API) физически живёт на бэкенде, а не
///   на лендинге — `/en/account/profile` СНАЧАЛА казался обычной страницей
///   лендинга (не содержит `/api/`), но лендинг о таком пути не знает и
///   отдаёт 404, потому что этот путь никогда там и не жил.
///
/// До появления этой развилки всё шло на один-единственный `BACKEND_ADDR`, и
/// такие вызовы либо 404-лись (не тот апстрим не знает такого пути), либо
/// били по правильному хосту, но случайно, в зависимости от того, что
/// реально стояло в `BACKEND_ADDR` на конкретной VDS.
fn route_for<'a>(
    cfg: &'a EdgeConfig,
    path: &str,
) -> (&'a str, &'a tokio::sync::Mutex<Vec<PooledSender>>) {
    if path.contains("/api/") || path.contains("/account") {
        (&cfg.backend_addr, &cfg.backend_pool)
    } else {
        (&cfg.landing_addr, &cfg.landing_pool)
    }
}

async fn try_proxy(cfg: &EdgeConfig, req: axum::extract::Request) -> Result<Response, String> {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let (target_addr, pool) = route_for(cfg, &path_and_query);
    let (target_host, _) = target_addr
        .rsplit_once(':')
        .ok_or_else(|| format!("upstream addr must be host:port, got {target_addr:?}"))?;

    let body_bytes = axum::body::to_bytes(body, MAX_PROXIED_BODY_BYTES)
        .await
        .map_err(|e| format!("reading request body: {e}"))?;

    // Собирается заново на каждую попытку (а не один раз) — `hyper::Request`
    // не `Clone`, а попытки может быть две (пул + фоллбэк на свежее
    // соединение ниже); сама сборка дешёвая (`body_bytes` — `Bytes`, клон по
    // счётчику ссылок, не копия).
    let build_request = || -> Result<hyper::Request<Full<Bytes>>, String> {
        let mut builder = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(&path_and_query);
        for (name, value) in parts.headers.iter() {
            // Host переписываем на реальный бэкенд ниже — иначе бэкенд увидит
            // домен ЭТОЙ VDS и не поймёт, какой виртуальный хост отдавать (то
            // же самое сделал бы любой обычный reverse-proxy). Hop-by-hop —
            // см. doc `is_hop_by_hop`.
            if name != header::HOST && !is_hop_by_hop(name) {
                builder = builder.header(name, value);
            }
        }
        builder = builder.header(header::HOST, target_host);
        builder
            .body(Full::new(body_bytes.clone()))
            .map_err(|e| format!("building proxied request: {e}"))
    };

    // Сначала пробуем уже поднятое keep-alive соединение из пула, привязанного
    // к ЭТОМУ конкретному апстриму (`route_for` выше) — см. doc на
    // `EdgeConfig::landing_pool`/`backend_pool` за тем, почему это не просто
    // оптимизация. Протухшее соединение (нода/бэкенд закрыли простаивавший
    // канал) — не ошибка, просто открываем новое ниже, как и раньше.
    let mut sender = pop_pooled(pool).await;
    let mut resp = None;
    if let Some(sr) = sender.as_mut() {
        match sr.send_request(build_request()?).await {
            Ok(r) => resp = Some(r),
            Err(_) => sender = None,
        }
    }

    let resp = match resp {
        Some(r) => r,
        None => {
            let mut sr = connect_backend(cfg, target_addr, target_host).await?;
            let r = sr
                .send_request(build_request()?)
                .await
                .map_err(|e| format!("sending proxied request: {e}"))?;
            sender = Some(sr);
            r
        }
    };

    let (parts, body) = resp.into_parts();
    let body_bytes: Bytes = body
        .collect()
        .await
        .map_err(|e| format!("reading backend response body: {e}"))?
        .to_bytes();

    // Тело полностью вычитано — соединение снова простаивает и готово к
    // следующему запросу, кладём обратно в пул вместо того, чтобы дать ему
    // молча упасть вместе с этой функцией.
    if let Some(sr) = sender {
        push_pooled(pool, sr).await;
    }

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

/// Верхняя граница `EdgeConfig::conn_pool` — держим её небольшой: пул не
/// призван обслуживать неограниченный параллелизм, только сгладить типичную
/// пачку суб-ресурсов одной страницы, не открывая для каждого из них свежий
/// NRXP-хендшейк одновременно (см. doc на `EdgeConfig::conn_pool`).
const MAX_POOLED_CONNS: usize = 8;

/// Сколько НОВЫХ NRXP-хендшейков до ноды можно поднимать одновременно. Пул
/// сам по себе не спасает первый холодный всплеск запросов (первая загрузка
/// страницы бьёт по пустому пулу — все параллельные суб-ресурсы разом видят
/// "пусто" и разом же пытаются открыть свежее соединение, то есть тот же
/// самый затор, из-за которого пул вообще появился, просто один раз при
/// каждом холодном старте вместо каждого запроса). Живая проверка показала,
/// что нода спокойно поднимает 5 одновременных исходящих TCP до бэкенда, но
/// уже на 15 часть из них не успевает уложиться и превращается в "tls
/// handshake eof" — лимит ниже (с запасом) превращает всплеск в несколько
/// последовательных мелких партий вместо одной большой.
const MAX_CONCURRENT_BACKEND_CONNECTS: usize = 4;

static CONNECT_LIMIT: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_BACKEND_CONNECTS));

/// Верхняя граница на весь цикл "TCP до ноды + NRXP-хендшейк + TLS до
/// бэкенда + HTTP/1-хендшейк" — без неё зависшая (не оборвавшаяся с ошибкой,
/// а именно ЗАВИСШАЯ на каком-то `.await`) попытка держала бы один из
/// `MAX_CONCURRENT_BACKEND_CONNECTS` пропусков семафора бесконечно, и уже
/// СЛЕДУЮЩИЕ запросы вставали бы в очередь за него — на живой проверке
/// именно так и произошло: несколько зависших попыток из-за одной пачки
/// конкурентных запросов держали семафор потом ещё много минут, и с виду
/// не связанные с ними одиночные запросы тоже начали тормозить на ~20-25с.
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Устанавливает НОВОЕ NRXP+TLS+HTTP/1-соединение до `target_addr`
/// (`LANDING_ADDR` или `BACKEND_ADDR` — см. `route_for`) — то же самое, что
/// раньше делал `try_proxy` инлайном на каждый запрос. Теперь вызывается
/// только когда пул пуст или отдал протухшее соединение. `CONNECT_LIMIT`
/// общий на оба апстрима намеренно — он защищает НОДУ (см. её doc) от
/// слишком многих одновременных свежих хендшейков, а нода тут одна на оба
/// направления, лендинг и бэкенд просто два разных `Connect`-кадра через неё.
async fn connect_backend(
    cfg: &EdgeConfig,
    target_addr: &str,
    target_host: &str,
) -> Result<PooledSender, String> {
    let _permit = CONNECT_LIMIT
        .acquire()
        .await
        .expect("CONNECT_LIMIT semaphore is never closed");

    tokio::time::timeout(
        BACKEND_CONNECT_TIMEOUT,
        connect_backend_inner(cfg, target_addr, target_host),
    )
    .await
    .map_err(|_| format!("connecting via {} timed out after {BACKEND_CONNECT_TIMEOUT:?}", cfg.vpn_node_addr))?
}

async fn connect_backend_inner(
    cfg: &EdgeConfig,
    target_addr: &str,
    target_host: &str,
) -> Result<PooledSender, String> {
    let tunnel_stream = TunnelStream::connect(cfg, target_addr).await?;

    let connector = TlsConnector::from(TLS_CONFIG.clone());
    let server_name = ServerName::try_from(target_host.to_string())
        .map_err(|e| format!("invalid upstream hostname {target_host:?}: {e}"))?;
    let tls_stream = connector
        .connect(server_name, tunnel_stream)
        .await
        .map_err(|e| format!("TLS handshake with backend failed: {e}"))?;

    let (send_request, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .map_err(|e| format!("HTTP/1 handshake with backend failed: {e}"))?;

    // Живёт, пока соединение не закроется (нода/бэкенд оборвали канал или
    // сама `SendRequest` вышла из пула по возрасту) — не обязательно на один
    // запрос, раз теперь есть переиспользование через пул.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            warn!("[netrunner-edge] backend connection closed: {e}");
        }
    });

    Ok(send_request)
}

/// Достаёт одно готовое к работе соединение из пула, если есть. `ready()`
/// проверяется ВНЕ лока над пулом (сам лок держим только на время `pop()`) —
/// иначе конкурентные запросы сериализовались бы друг за другом на этой
/// проверке, что свело бы на нет весь смысл пулинга (ровно та проблема с
/// живой VDS, из-за которой пул вообще появился). Параметризовано пулом
/// (`landing_pool` или `backend_pool`, см. `route_for`), а не завязано на
/// `EdgeConfig` напрямую — один и тот же код обслуживает оба апстрима.
async fn pop_pooled(pool: &tokio::sync::Mutex<Vec<PooledSender>>) -> Option<PooledSender> {
    let mut sr = pool.lock().await.pop()?;
    if sr.ready().await.is_ok() {
        Some(sr)
    } else {
        None
    }
}

/// Возвращает соединение в пул после того, как ответ на текущий запрос
/// полностью вычитан (см. вызов в `try_proxy`) — переполнение пула просто
/// роняет соединение (закрывается само через `Drop`), не ошибка.
async fn push_pooled(pool: &tokio::sync::Mutex<Vec<PooledSender>>, sr: PooledSender) {
    let mut pool = pool.lock().await;
    if pool.len() < MAX_POOLED_CONNS {
        pool.push(sr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> EdgeConfig {
        EdgeConfig {
            vpn_node_addr: "1.2.3.4:443".to_string(),
            landing_addr: "netrunner-vpn.com:443".to_string(),
            backend_addr: "account.netrunner-vpn.com:443".to_string(),
            decoy_sni: "cloudflare.com".to_string(),
            auth_token: String::new(),
            landing_pool: tokio::sync::Mutex::new(Vec::new()),
            backend_pool: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Живые примеры из двух последовательных багов: обычная страница
    /// лендинга уходит на лендинг, а весь раздел "аккаунт" — целиком на
    /// бэкенд, не только его API-вызовы (см. doc на `route_for` за тем,
    /// почему `/en/account/profile` — не страница лендинга, хоть и не
    /// содержит `/api/`).
    #[test]
    fn routes_landing_pages_and_api_calls_to_different_upstreams() {
        let cfg = test_cfg();

        let (addr, _) = route_for(&cfg, "/");
        assert_eq!(addr, "netrunner-vpn.com:443");

        let (addr, _) = route_for(&cfg, "/en/pricing");
        assert_eq!(addr, "netrunner-vpn.com:443");

        let (addr, _) = route_for(&cfg, "/en/account/profile");
        assert_eq!(addr, "account.netrunner-vpn.com:443");

        let (addr, _) = route_for(&cfg, "/en/account/api/v1/auth/telegram/session");
        assert_eq!(addr, "account.netrunner-vpn.com:443");

        let (addr, _) = route_for(&cfg, "/api/v1/health");
        assert_eq!(addr, "account.netrunner-vpn.com:443");
    }
}
