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
use crate::browser_proxy::{self, Target as BrowserTarget};
use crate::EdgeConfig;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::header;
use hyper_util::rt::TokioIo;
use netrunner_logger::{error, warn};
use rustls_pki_types::ServerName;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use tokio::io::{AsyncRead, AsyncWrite};

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
/// Search is deliberately pinned to one upstream. This endpoint cannot be
/// used as an arbitrary URL fetcher or an open forward proxy.
const SEARCH_UPSTREAM_ADDR: &str = "html.duckduckgo.com:443";
/// Locales supported by the landing site's Next.js middleware. Requests can
/// arrive here as `/en/search` after that middleware has prefixed the URL.
const SEARCH_LOCALES: &[&str] = &[
    "en", "ru", "zh-CN", "fa", "ar", "tr", "uk", "be", "vi", "uz", "th",
];

#[cfg(test)]
fn looks_like_asset(path: &str) -> bool {
    let Some(ext) = path.rsplit('/').next().and_then(|f| f.rsplit_once('.')) else {
        return false;
    };
    matches!(
        ext.1.to_ascii_lowercase().as_str(),
        "js" | "mjs"
            | "css"
            | "map"
            | "woff"
            | "woff2"
            | "ttf"
            | "eot"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "svg"
            | "ico"
    )
}

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

/// Точка входа из `main.rs::handle`. Если upstream недоступен, возвращает
/// некэшируемый 502. Заглушка nginx маскировала сбой и иногда сама попадала
/// в кэш зеркала вместо реального ответа сайта.
pub async fn proxy(cfg: Arc<EdgeConfig>, req: axum::extract::Request) -> Response {
    match try_proxy(&cfg, req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("[netrunner-edge] http proxy failed: {e}");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::from("upstream unavailable"))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
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
    if search_upstream_path(path).is_some() {
        return (SEARCH_UPSTREAM_ADDR, &cfg.search_pool);
    }
    if path.contains("/api/") || path.contains("/account") {
        (&cfg.backend_addr, &cfg.backend_pool)
    } else {
        (&cfg.landing_addr, &cfg.landing_pool)
    }
}

/// Maps the search endpoint and DuckDuckGo's follow-up paths to the fixed
/// search upstream. A locale prefix is optional because the site's Next.js
/// middleware may turn `/search` into `/en/search` before the request reaches
/// this relay. The locale is removed before forwarding so DuckDuckGo receives
/// its expected paths (`/html/`, `/html/...`, or `/l/...`).
fn search_upstream_path(path_and_query: &str) -> Option<std::borrow::Cow<'_, str>> {
    let (pathname, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(pathname, query)| {
            (pathname, Some(query))
        });

    let normalized_path = pathname
        .strip_prefix('/')
        .and_then(|rest| rest.split_once('/'))
        .filter(|(locale, _)| SEARCH_LOCALES.contains(locale))
        .map(|(_, suffix)| format!("/{suffix}"));
    let upstream_path = normalized_path.as_deref().unwrap_or(pathname);

    if upstream_path == "/search" || upstream_path == "/search/" {
        return Some(match query {
            Some(query) => std::borrow::Cow::Owned(format!("/html/?{query}")),
            None => std::borrow::Cow::Borrowed("/html/"),
        });
    }

    let is_search_follow_up = upstream_path == "/html"
        || upstream_path.starts_with("/html/")
        || upstream_path.starts_with("/l/");
    if !is_search_follow_up {
        return None;
    }

    Some(match (normalized_path, query) {
        (Some(path), Some(query)) => std::borrow::Cow::Owned(format!("{path}?{query}")),
        (Some(path), None) => std::borrow::Cow::Owned(path),
        (None, _) => std::borrow::Cow::Borrowed(path_and_query),
    })
}

/// Бэкенд ничего не знает про префикс "/account" — он смонтирован на
/// "/api/v1" и раздаёт SPA/`/assets` без него (см. `netrunner-backend/src/api.rs`),
/// тот же приём, что и в `netrunner-mirror/src/index.js`
/// (`pathname.slice("/account".length)`). Браузер же шлёт запросы именно с
/// этим префиксом — его добавляет `resolveAccountBase()` в
/// `netrunner-landing/app/[lang]/auth/auth-client.tsx`, когда страница
/// открыта не с канонического домена (ровно наш случай: любой заход через
/// эту VDS). Без отрезания префикса первая страница ЛК (`/account/profile`)
/// ещё попадает в SPA-fallback бэкенда и рендерится, но все её чанки
/// (`/account/assets/*.js`, путь берётся из рантайм `<base href="/account/">`,
/// см. `frontend/index.html`/`frontend/src/base.ts`) для бэкенда — тоже
/// незнакомый путь, что снова ловит тот же SPA-fallback и отдаёт им
/// `index.html` вместо JS: браузер видит "Failed to load module script...
/// MIME type text/html" ровно на этих чанках.
fn strip_account_prefix(path_and_query: &str) -> std::borrow::Cow<'_, str> {
    match path_and_query.strip_prefix("/account") {
        Some("") => std::borrow::Cow::Borrowed("/"),
        Some(rest) if rest.starts_with('/') => std::borrow::Cow::Borrowed(rest),
        // "/account?foo=bar" (no trailing slash before the query string) —
        // rest is "?foo=bar", which isn't a valid path on its own.
        Some(rest) if rest.starts_with('?') => std::borrow::Cow::Owned(format!("/{rest}")),
        _ => std::borrow::Cow::Borrowed(path_and_query),
    }
}

/// `Some(target)` — редиректнуть на `target` перед проксированием, см. doc
/// в `try_proxy` за полным обоснованием (лендинг строит переход в аккаунт с
/// языковым префиксом ПЕРЕД "/account", из-за чего собственный бутстрап
/// аккаунта неверно вычисляет `<base href>`). Срабатывает только когда
/// "/account" реально встречается НЕ в позиции 0 — путь, уже начинающийся с
/// "/account", и путь без "/account" вообще не трогаем. Вызовы API
/// намеренно исключены (`strip_account_prefix` их не режет и они уже
/// работают как есть, лишний редирект тут не нужен и рискует сломать
/// fetch/XHR с ручной обработкой `Location`).
fn account_redirect_target(path_and_query: &str) -> Option<&str> {
    let idx = path_and_query.find("/account")?;
    if idx == 0 || path_and_query.contains("/api/") {
        return None;
    }
    Some(&path_and_query[idx..])
}

async fn try_proxy(cfg: &EdgeConfig, req: axum::extract::Request) -> Result<Response, String> {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let request_host = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let is_browser_gateway = host_without_port(request_host)
        .eq_ignore_ascii_case(&cfg.browser_proxy_domain);

    if !is_browser_gateway {
        if let Some(search_path) = search_upstream_path(&path_and_query) {
            if let Some((search_route, search_query)) = search_path.split_once('?') {
                if search_route.starts_with("/l/") {
                    if let Some(target) = browser_proxy::search_redirect(search_query) {
                        let location = browser_proxy::gateway_url(
                            &target,
                            &cfg.browser_proxy_domain,
                        );
                        return Response::builder()
                            .status(StatusCode::FOUND)
                            .header(header::LOCATION, location)
                            .header(header::CACHE_CONTROL, "no-store")
                            .body(Body::empty())
                            .map_err(|error| format!("building search redirect: {error}"));
                    }
                }
            }
        }
    }

    let browser_target = if is_browser_gateway {
        let parsed = if path_and_query.starts_with("/browse/") {
            browser_proxy::parse_target(&path_and_query).await
        } else if let Some(referer) = parts.headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
            browser_proxy::parse_referer_target(
                referer,
                &path_and_query,
                &cfg.browser_proxy_domain,
            )
            .await
        } else {
            Err("browse URL is missing".to_string())
        };
        match parsed {
            Ok(target) => Some(target),
            Err(error) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(Body::from(error))
                    .unwrap_or_else(|_| StatusCode::BAD_REQUEST.into_response()));
            }
        }
    } else {
        None
    };
    if browser_target.is_none()
        && route_for(cfg, &path_and_query).0 == SEARCH_UPSTREAM_ADDR
        && parts.method != hyper::Method::GET
        && parts.method != hyper::Method::HEAD
    {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::METHOD_NOT_ALLOWED.into_response()));
    }

    // Оригинал при переходе в раздел "аккаунт" делает полный переход на
    // ОТДЕЛЬНЫЙ домен (account.netrunner-vpn.com/profile — БЕЗ языкового
    // префикса, "account" там сам домен, не сегмент пути). У нас один и тот
    // же origin, а ссылку на переход строит лендинг с языковым префиксом
    // ПЕРЕД "/account" (`/en/account/profile`, см. resolveAccountBase() в
    // netrunner-landing). Собственный бутстрап-скрипт index.html аккаунта
    // (см. doc на `strip_account_prefix`) выбирает `<base href>` ТОЛЬКО по
    // тому, начинается ли `location.pathname` РОВНО с "/account" (позиция
    // 0) — из-за "/en/" перед этим он всегда выбирает "/" вместо
    // "/account/", и все относительные чанки (`./assets/*.js`) начинают
    // резолвиться от корня: либо мимо `BACKEND_ADDR` в `LANDING_ADDR` (404,
    // если в пути вообще нет "/account"), либо на `BACKEND_ADDR`, но НЕ
    // срезанными (`strip_account_prefix` режет только путь, начинающийся с
    // "/account", а тут спереди ещё "/en") — оба случая живая проверка
    // подтвердила: браузер видит "MIME type text/html" вместо JS.
    //
    // Поправить сам JS аккаунта нельзя (другой репозиторий/сборка), поэтому
    // нормализуем то, что видит браузер: редиректим, роняя всё ДО
    // "/account", когда это НЕ вызов API (тот и так работает с префиксом
    // как есть — бэкенд его сам матчит по суффиксу, см. doc на
    // `strip_account_prefix`, лишний редирект ему не нужен и рискует
    // сломать fetch/XHR с ручной обработкой `Location`). После редиректа
    // `location.pathname` у браузера уже начинается с "/account", и
    // собственный скрипт аккаунта сам выбирает правильный `<base href>` —
    // дальше все относительные чанки одной страницы резолвятся уже
    // корректно, точечно чинить каждый `/assets/*.js` по отдельности не
    // нужно.
    if let Some(target) = account_redirect_target(&path_and_query) {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, target)
            .body(Body::empty())
            .map_err(|e| format!("building account-redirect response: {e}"));
    }

    let static_route = if browser_target.is_none() {
        Some(route_for(cfg, &path_and_query))
    } else {
        None
    };
    let dynamic_pool = if let Some(target) = &browser_target {
        Some(browser_pool(cfg, &target.pool_key).await)
    } else {
        None
    };
    let (target_addr, target_host, target_authority, pool, use_tls) =
        if let Some(target) = &browser_target {
            (
                target.connect_addr.clone(),
                target.url.host_str().unwrap_or_default().to_string(),
                target.host_header.clone(),
                dynamic_pool.as_deref().expect("dynamic browser pool"),
                target.tls,
            )
        } else {
            let (target_addr, pool) = static_route.expect("static route");
            let (target_host, _) = target_addr
                .rsplit_once(':')
                .ok_or_else(|| format!("upstream addr must be host:port, got {target_addr:?}"))?;
            (
                target_addr.to_string(),
                target_host.to_string(),
                target_host.to_string(),
                pool,
                true,
            )
        };

    // Только у BACKEND_ADDR путь может нести префикс "/account", который
    // сам бэкенд не понимает (см. doc на `strip_account_prefix`) — у
    // LANDING_ADDR путь пересылается как есть, ничего резать не нужно.
    let forwarded_path = if let Some(target) = &browser_target {
        target_path_and_query(&target.url)
    } else {
        if target_addr == SEARCH_UPSTREAM_ADDR && path_and_query.starts_with("/search") {
            match path_and_query.split_once('?') {
                Some((_, query)) => std::borrow::Cow::Owned(format!("/html/?{query}")),
                None => std::borrow::Cow::Borrowed("/html/"),
            }
        } else if target_addr == cfg.backend_addr {
            strip_account_prefix(&path_and_query)
        } else {
            std::borrow::Cow::Borrowed(path_and_query.as_str())
        }
    };

    let body_bytes = axum::body::to_bytes(body, MAX_PROXIED_BODY_BYTES)
        .await
        .map_err(|e| format!("reading request body: {e}"))?;

    // Настоящий Host, который видел браузер (blue-pixel-studio.online и
    // т.п.) — нужен ниже как `X-Forwarded-Host`, ДО того как мы его
    // перепишем на `target_host` для самого запроса. См. doc на
    // `build_request` за тем, зачем бэкенду вообще знать оригинал.
    let original_host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Собирается заново на каждую попытку (`hyper::Request` не `Clone`); сама
    // сборка дешёвая: `body_bytes` клонируется по счётчику ссылок.
    let build_request = || -> Result<hyper::Request<Full<Bytes>>, String> {
        let mut builder = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(forwarded_path.as_ref());
        for (name, value) in parts.headers.iter() {
            // Host переписываем на реальный бэкенд ниже — иначе бэкенд увидит
            // домен ЭТОЙ VDS и не поймёт, какой виртуальный хост отдавать (то
            // же самое сделал бы любой обычный reverse-proxy). Hop-by-hop —
            // см. doc `is_hop_by_hop`.
            let browser_credential = browser_target.is_some()
                && (name == header::COOKIE
                    || name == header::AUTHORIZATION
                    || name == header::ACCEPT_ENCODING
                    || name == header::ORIGIN
                    || name == header::REFERER);
            let search_credential = target_addr == SEARCH_UPSTREAM_ADDR
                && (name == header::COOKIE
                    || name == header::AUTHORIZATION
                    || name == header::ACCEPT_ENCODING);
            if name != header::HOST
                && !is_hop_by_hop(name)
                && !search_credential
                && !browser_credential
            {
                builder = builder.header(name, value);
            }
        }
        builder = builder.header(header::HOST, target_authority.as_str());
        if let Some(target) = &browser_target {
            builder = builder
                .header(header::ACCEPT_ENCODING, "identity")
                .header(header::ORIGIN, target.url.origin().ascii_serialization())
                .header(header::REFERER, target.url.as_str());
        } else if target_addr == SEARCH_UPSTREAM_ADDR {
            // The search-result HTML must remain uncompressed until links are
            // rewritten to the browse gateway.
            builder = builder.header(header::ACCEPT_ENCODING, "identity");
        }
        // Живой баг: бэкенд определяет по Host, безопасно ли ставить
        // `Set-Cookie: ...; Domain=.netrunner-vpn.com` (см.
        // cookie_domain_attr в netrunner-backend/src/modules/auth/controller.rs)
        // — но раз мы САМИ переписали Host на `target_host` строкой выше
        // (обязательно, иначе бэкенд не поймёт, какой вирт.хост отдавать),
        // бэкенд видит "account.netrunner-vpn.com" и честно ставит
        // Domain=.netrunner-vpn.com — а браузер при этом реально стоит на
        // blue-pixel-studio.online и молча дропает такую cookie целиком
        // (RFC 6265 domain-match). Итог живьём: Telegram-логин "успешен"
        // (токен приходит в теле ответа), но /users/me и /auth/refresh
        // сразу после — 401 навсегда, ЛК зацикливается обратно на /en/auth.
        // X-Forwarded-Host — единственный правдивый сигнал о том, что
        // реально видел браузер; без него у бэкенда просто нет способа
        // отличить "настоящий account.netrunner-vpn.com" от "зеркало,
        // прикидывающееся им ради маршрутизации".
        if browser_target.is_none() {
            if let Some(ref host) = original_host {
            builder = builder.header("x-forwarded-host", host.as_str());
            }
        }
        builder
            .body(Full::new(body_bytes.clone()))
            .map_err(|e| format!("building proxied request: {e}"))
    };

    // Reuse keep-alive connections where possible. A connection can look
    // ready immediately before the upstream closes it, or reset while its
    // response body is being read. Retry safe browser reads on a fresh tunnel
    // so transient stale-pool failures do not turn the mirror into a decoy.
    let retryable = parts.method == hyper::Method::GET || parts.method == hyper::Method::HEAD;
    let mut pooled_error = None;
    if let Some(mut pooled) = pop_pooled(pool).await {
        match send_and_collect(&mut pooled, build_request()?).await {
            Ok(response) => {
                push_pooled(pool, pooled).await;
                let (mut parts, mut body_bytes) = response;
                rewrite_response(
                    &mut parts,
                    &mut body_bytes,
                    browser_target.as_ref(),
                    cfg,
                    target_addr == SEARCH_UPSTREAM_ADDR,
                )?;
                return build_response(parts, body_bytes);
            }
            Err(error) if error.is_request_send() || retryable => {
                pooled_error = Some(error.to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }

    let first_fresh = fresh_attempt(
        cfg,
        &target_addr,
        &target_host,
        use_tls,
        &build_request,
    )
    .await;
    let (response_parts, response_bytes, fresh_sender) = match first_fresh {
        Ok(result) => result,
        Err(first_error) if retryable => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            fresh_attempt(
                cfg,
                &target_addr,
                &target_host,
                use_tls,
                &build_request,
            )
                .await
                .map_err(|retry_error| {
                    format!(
                        "upstream retry failed: {retry_error}; first attempt failed: {first_error}"
                    )
                })?
        }
        Err(error) => return Err(error),
    };
    push_pooled(pool, fresh_sender).await;

    if let Some(pooled_error) = pooled_error {
        warn!("[netrunner-edge] discarded stale upstream connection: {pooled_error}");
    }

    let mut response_parts = response_parts;
    let mut response_bytes = response_bytes;
    rewrite_response(
        &mut response_parts,
        &mut response_bytes,
        browser_target.as_ref(),
        cfg,
        target_addr == SEARCH_UPSTREAM_ADDR,
    )?;
    build_response(response_parts, response_bytes)
}

fn host_without_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority.split_once(']').map_or(authority, |(host, _)| host)
    } else {
        authority.split(':').next().unwrap_or(authority)
    }
}

fn target_path_and_query(url: &url::Url) -> std::borrow::Cow<'static, str> {
    let path = url.path();
    match url.query() {
        Some(query) => std::borrow::Cow::Owned(format!("{path}?{query}")),
        None => std::borrow::Cow::Owned(path.to_string()),
    }
}

async fn browser_pool(
    cfg: &EdgeConfig,
    key: &str,
) -> std::sync::Arc<tokio::sync::Mutex<Vec<PooledSender>>> {
    let mut pools = cfg.browser_pools.lock().await;
    if let Some(pool) = pools.get(key) {
        return pool.clone();
    }
    // The public-site gateway can see arbitrary destination hosts. Keep the
    // origin cache bounded so unique one-off hostnames cannot grow it forever.
    if pools.len() >= 64 {
        return std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    }
    pools
        .entry(key.to_string())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())))
        .clone()
}

fn rewrite_response(
    parts: &mut hyper::http::response::Parts,
    body: &mut Bytes,
    target: Option<&BrowserTarget>,
    cfg: &EdgeConfig,
    is_search: bool,
) -> Result<(), String> {
    if let Some(target) = target {
        if let Some(location) = parts.headers.get(header::LOCATION).and_then(|v| v.to_str().ok()) {
            if let Ok(url) = target.url.join(location) {
                if matches!(url.scheme(), "http" | "https") {
                    let proxied = browser_proxy::gateway_url(&url, &cfg.browser_proxy_domain);
                    parts.headers.insert(
                        header::LOCATION,
                        hyper::header::HeaderValue::from_str(&proxied)
                            .map_err(|error| format!("rewriting redirect: {error}"))?,
                    );
                }
            }
        }
        parts.headers.remove(header::SET_COOKIE);
        parts.headers.remove("content-security-policy");
        parts.headers.remove("content-security-policy-report-only");
        rewrite_document_body(parts, body, &target.url, cfg)?;
    } else if is_search {
        let base = url::Url::parse("https://html.duckduckgo.com/html/")
            .expect("static search URL is valid");
        rewrite_document_body(parts, body, &base, cfg)?;
    }
    Ok(())
}

fn rewrite_document_body(
    parts: &hyper::http::response::Parts,
    body: &mut Bytes,
    base_url: &url::Url,
    cfg: &EdgeConfig,
) -> Result<(), String> {
    let Some(content_type) = parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return Ok(());
    };
    let content_type = content_type.to_ascii_lowercase();
    if content_type.contains("text/css") {
        if let Some(rewritten) = browser_proxy::rewrite_css(body, base_url, &cfg.browser_proxy_domain) {
            *body = Bytes::from(rewritten);
        }
        return Ok(());
    }
    if !content_type.contains("text/html") && !content_type.contains("application/xhtml+xml") {
        return Ok(());
    }
    if std::str::from_utf8(body).is_err() {
        return Ok(());
    }
    let relay_domain = cfg
        .browser_proxy_domain
        .strip_prefix("browse.")
        .unwrap_or(&cfg.browser_proxy_domain);
    *body = Bytes::from(browser_proxy::rewrite_html(
        body,
        base_url,
        &cfg.browser_proxy_domain,
        relay_domain,
    )?);
    Ok(())
}

fn build_response(
    parts: hyper::http::response::Parts,
    body_bytes: Bytes,
) -> Result<Response, String> {
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

struct AttemptFailure {
    phase: &'static str,
    detail: String,
}

impl AttemptFailure {
    fn is_request_send(&self) -> bool {
        self.phase == "sending proxied request"
    }
}

impl std::fmt::Display for AttemptFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.phase, self.detail)
    }
}

async fn send_and_collect(
    sender: &mut PooledSender,
    request: hyper::Request<Full<Bytes>>,
) -> Result<(hyper::http::response::Parts, Bytes), AttemptFailure> {
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| AttemptFailure {
            phase: "sending proxied request",
            detail: error.to_string(),
        })?;
    let (parts, body) = response.into_parts();
    let mut body = body;
    let mut body_bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| AttemptFailure {
            phase: "reading backend response body",
            detail: error.to_string(),
        })?;
        if let Ok(data) = frame.into_data() {
            if data.len() > MAX_PROXIED_BODY_BYTES.saturating_sub(body_bytes.len()) {
                return Err(AttemptFailure {
                    phase: "reading backend response body",
                    detail: format!("response exceeds {MAX_PROXIED_BODY_BYTES} byte buffer limit"),
                });
            }
            body_bytes.extend_from_slice(&data);
        }
    }
    Ok((parts, body_bytes.freeze()))
}

async fn fresh_attempt<F>(
    cfg: &EdgeConfig,
    target_addr: &str,
    target_host: &str,
    use_tls: bool,
    build_request: &F,
) -> Result<(hyper::http::response::Parts, Bytes, PooledSender), String>
where
    F: Fn() -> Result<hyper::Request<Full<Bytes>>, String>,
{
    let mut sender = connect_backend(cfg, target_addr, target_host, use_tls).await?;
    let (parts, body) = send_and_collect(&mut sender, build_request()?)
        .await
        .map_err(|error| error.to_string())?;
    Ok((parts, body, sender))
}

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
    use_tls: bool,
) -> Result<PooledSender, String> {
    let _permit = CONNECT_LIMIT
        .acquire()
        .await
        .expect("CONNECT_LIMIT semaphore is never closed");

    tokio::time::timeout(
        BACKEND_CONNECT_TIMEOUT,
        connect_backend_inner(cfg, target_addr, target_host, use_tls),
    )
    .await
    .map_err(|_| {
        format!(
            "connecting via {} timed out after {BACKEND_CONNECT_TIMEOUT:?}",
            cfg.vpn_node_addr
        )
    })?
}

async fn connect_backend_inner(
    cfg: &EdgeConfig,
    target_addr: &str,
    target_host: &str,
    use_tls: bool,
) -> Result<PooledSender, String> {
    let tunnel_stream = TunnelStream::connect(cfg, target_addr).await?;

    if use_tls {
        let connector = TlsConnector::from(TLS_CONFIG.clone());
        let server_name = ServerName::try_from(target_host.to_string())
            .map_err(|e| format!("invalid upstream hostname {target_host:?}: {e}"))?;
        let tls_stream = connector
            .connect(server_name, tunnel_stream)
            .await
            .map_err(|e| format!("TLS handshake with backend failed: {e}"))?;
        finish_http_handshake(tls_stream).await
    } else {
        finish_http_handshake(tunnel_stream).await
    }
}

async fn finish_http_handshake<S>(stream: S) -> Result<PooledSender, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream))
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
            browser_proxy_domain: "browse.mirror.example".to_string(),
            decoy_sni: "cloudflare.com".to_string(),
            auth_token: String::new(),
            // Маршрутизация HTTP не зависит от учётных данных ноды — они нужны
            // только на хендшейке туннеля.
            identity: None,
            landing_pool: tokio::sync::Mutex::new(Vec::new()),
            backend_pool: tokio::sync::Mutex::new(Vec::new()),
            search_pool: tokio::sync::Mutex::new(Vec::new()),
            browser_pools: tokio::sync::Mutex::new(std::collections::HashMap::new()),
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

    /// Живой баг: ЛК открыт через эту VDS (не с канонического домена), браузер
    /// получает `<base href="/account/">` (см. `frontend/index.html`) и после
    /// него шлёт все чанки с этим префиксом — бэкенд его не понимает и без
    /// отрезания отвечал на `/account/assets/*.js` тем же `index.html`
    /// (SPA-fallback), что и на саму страницу — "Failed to load module
    /// script... MIME type text/html" в консоли браузера.
    #[test]
    fn strips_account_prefix_only_for_backend_bound_paths() {
        assert_eq!(strip_account_prefix("/account"), "/");
        assert_eq!(strip_account_prefix("/account/profile"), "/profile");
        assert_eq!(
            strip_account_prefix("/account/assets/jsx-runtime-BIe8Z300.js"),
            "/assets/jsx-runtime-BIe8Z300.js"
        );
        assert_eq!(
            strip_account_prefix("/account/api/v1/users/me"),
            "/api/v1/users/me"
        );
        // Не трогаем пути, где "/account" — не префикс, а совпадение где-то
        // внутри (тот самый `/en/account/profile` из route_for — сюда
        // `strip_account_prefix` не применяется вовсе, см. `try_proxy`).
        assert_eq!(
            strip_account_prefix("/en/account/profile"),
            "/en/account/profile"
        );
        // Путь, который лишь НАЧИНАЕТСЯ так же, но это другой сегмент —
        // "/accounting", не "/account".
        assert_eq!(strip_account_prefix("/accounting"), "/accounting");
    }

    /// Живой баг: браузер видит "Failed to load module script... MIME type
    /// text/html" на чанках ЛК даже ПОСЛЕ фикса `strip_account_prefix` —
    /// потому что бутстрап аккаунта сам вычисляет `<base href>` по
    /// `location.pathname.indexOf("/account") === 0`, а лендинг ведёт на
    /// `/en/account/profile` (языковой префикс ПЕРЕД "/account", проверка
    /// не проходит). Редирект нормализует путь до того, как этот скрипт
    /// вообще выполнится.
    #[test]
    fn redirects_account_pages_but_not_api_calls_or_already_normalized_paths() {
        assert_eq!(
            account_redirect_target("/en/account/profile"),
            Some("/account/profile")
        );
        assert_eq!(
            account_redirect_target("/ru/account/settings?tab=billing"),
            Some("/account/settings?tab=billing")
        );
        // Уже нормализован — незачем редиректить самого себя в бесконечный цикл.
        assert_eq!(account_redirect_target("/account/profile"), None);
        // Не про аккаунт вообще.
        assert_eq!(account_redirect_target("/en/pricing"), None);
        // Вызов API — уже работает с префиксом как есть, редирект не нужен
        // (см. doc на `account_redirect_target`).
        assert_eq!(
            account_redirect_target("/en/account/api/v1/auth/telegram/session"),
            None
        );
    }

    /// Живой инцидент: CDN перед нами (Cloudflare) кэширует `*.js`/`*.css`
    /// по расширению независимо от `Cache-Control` источника — decoy-200 на
    /// временную (не постоянную) неудачу застревал в её кэше навсегда,
    /// пока кто-то не почистит руками. См. doc на `proxy`.
    #[test]
    fn recognizes_static_asset_extensions() {
        assert!(looks_like_asset("/account/assets/index-BVs-cDup.js"));
        assert!(looks_like_asset("/account/assets/index-CaA__h5d.css"));
        assert!(looks_like_asset("/account/assets/lib-BbZj81bx.js.map"));
        assert!(looks_like_asset("/fonts/inter.woff2"));
        assert!(!looks_like_asset("/en/account/profile"));
        assert!(!looks_like_asset("/en/account/api/v1/users/me"));
        assert!(!looks_like_asset("/"));
    }
}
