//! # netrunner-edge-native — NRXP-клиент как обычный сервис на VDS
//!
//! Та же роль, что и у [`client-edge`](../client-edge) (Cloudflare Worker),
//! но как самостоятельный tokio-бинарь для произвольной VDS, а не привязанный
//! к рантайму Cloudflare Workers. Два независимых входа в один и тот же
//! NRXP-туннель до ноды:
//!
//! ```text
//!   WS-клиент  ──WSS──▶  axum: WS ⇄ NRXP-мост (bridge.rs)          ──┐
//!                                                                     ├──NRXP/TCP──▶  netrunner-server  ──▶  BACKEND_ADDR
//!   браузер    ──HTTPS──▶ axum: открытый HTTP-реверс-прокси          │              (VPN-нода)
//!               (proxy_http.rs, TLS до бэкенда ВНУТРИ NRXP-ноги) ──┘
//! ```
//!
//! Обычная ссылка в браузере (GET без `Upgrade`) теперь тоже долетает до
//! настоящего сайта/бэкенда за нодой, не только WS-клиенты — см.
//! `proxy_http.rs`: осознанно "открытый прокси без контроля", кто угодно,
//! кто откроет ссылку на эту VDS, попадает на реальный сайт, никакой
//! проверки личности на этом входе нет.
//!
//! Зачем отдельный бинарь, а не просто "клиент-edge, но не wasm": протокольная
//! логика (хендшейк, кадры, шифрование) уже платформо-независима —
//! `netrunner_core::edge` не тянет `tokio::net` и одинаково собирается что под
//! `wasm32-unknown-unknown` (Workers), что нативно. Разница только в
//! транспорте: там `worker::Socket`/`worker::WebSocketPair` (Cloudflare
//! Sockets API), здесь — обычный `tokio::net::TcpStream` и `axum`. Смешивать
//! wasm-only зависимость `worker` с нативным `tokio`-рантаймом в одном крейте
//! не имеет смысла (`worker-build`/`wrangler` не умеют собрать нативный
//! бинарь из того же крейта) — поэтому это отдельный член workspace, не
//! `#[cfg]`-ветка внутри `client-edge`.
//!
//! ## Два слоя маскировки (важно понимать по отдельности)
//!
//! 1. **Входящая нога (пользователь/браузер ⇄ эта VDS)** — обычный HTTPS/WSS
//!    поверх настоящего TLS. Реального TLS-терминатора в этом бинаре нет
//!    осознанно — см. `README.md` за тем, почему это должен делать Caddy
//!    (или любой другой reverse-proxy) перед этим процессом: настоящий
//!    ACME-сертификат убедительнее самоподписанного, а сам этот процесс
//!    тогда вообще не должен знать о приватных ключах TLS.
//! 2. **Исходящая нога (эта VDS ⇄ настоящая VPN-нода)** — NRXP,
//!    маскирующийся под TLS ClientHello к `DECOY_SNI` (см.
//!    `netrunner_core::edge`/`tlseng`). Это прячет СОДЕРЖИМОЕ хендшейка от
//!    DPI/содержимого-инспектирующих посредников, но НЕ прячет сам факт
//!    "эта VDS соединяется с IP X" от хостера этой VDS, который видит
//!    netflow/файрвол-логи без какой-либо расшифровки. Если конкретно
//!    хостер — часть модели угроз, `DECOY_SNI` тут не панацея (см. README).
//!
//! Для HTTP-прокси есть ещё и ТРЕТИЙ, вложенный слой — настоящий TLS-клиент
//! до реального `BACKEND_ADDR`, поднятый ПРЯМО НАД NRXP-нёй (см.
//! `tunnel_stream.rs`/`proxy_http.rs`) — не путать с decoy-маскировкой слоя 2
//! выше, это два независимых TLS-рукопожатия с разными целями.
//!
//! Конфигурация — только переменные окружения (см. `EdgeConfig::from_env`),
//! секрет (`AUTH_TOKEN`) в их числе — ничего не зашито в бинарь.

mod bridge;
mod proxy_http;
mod tunnel_stream;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use clap::Parser;
use netrunner_logger::{error, info, Logger};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Дефолтная страница nginx — то, что видит буквально любой, кто открывает
/// IP/домен с только что поднятым веб-сервером без настроенного контента.
/// Максимально частая, ничем не примечательная картина в интернете — ровно
/// то, что нужно decoy-ответу на не-WS-запрос (сканер DPI, случайный визит
/// браузером, healthcheck без Upgrade-заголовка). Дословно тот же текст, что
/// и в `client-edge/src/lib.rs::DECOY_PAGE_HTML` — единый паттерн маскировки
/// на обеих платформах.
const DECOY_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
"#;

/// Конфигурация моста — читается один раз при старте процесса (в отличие от
/// Cloudflare Workers, где `env.var(...)` читается на каждый запрос заново,
/// здесь это соответствует обычному "прочитать конфиг один раз при старте
/// сервиса"). Названия переменных намеренно совпадают 1:1 с `wrangler.toml`
/// у `client-edge`, чтобы конфигурация была узнаваемой для того, кто уже
/// разворачивал воркер-вариант.
pub struct EdgeConfig {
    /// `host:port` вашей VPN-ноды (`netrunner-server`) — ClientHello-таргет.
    pub(crate) vpn_node_addr: String,
    /// `host:port`, который нода откроет по `Connect`-кадру (ваш бэкенд) —
    /// используется и WS-мостом, и HTTP-прокси (там же ещё и как SNI/Host
    /// для внутреннего TLS до реального бэкенда, см. `proxy_http.rs`).
    pub(crate) backend_addr: String,
    /// Домен-декой для поддельного `ClientHello` — должен резолвиться и
    /// отвечать 200, чтобы отпечаток держался правдоподобно (см.
    /// `core::net::DEFAULT_DECOY_HOST` и ARCH.md в основном репозитории).
    pub(crate) decoy_sni: String,
    /// Bearer-токен для auth-heartbeat — нужен только если нода поднята с
    /// `--require-auth`. Пустая строка, если не задан (нода без
    /// `--require-auth` его не проверяет).
    pub(crate) auth_token: String,
}

impl EdgeConfig {
    /// Секрет и адреса — только из окружения, ничего не зашито в бинарь и не
    /// принимается аргументом командной строки (аргументы командной строки
    /// процесса видны любому, у кого есть доступ к `/proc` на этой VDS, что
    /// не так для переменных окружения демона, если он не запущен под
    /// пользователем с полным доступом к `/proc/<pid>/environ` — та же
    /// причина, по которой `AUTH_TOKEN` у `netrunner-server` тоже приходит
    /// исключительно через `PROXY_INTERNAL_SECRET` в `env`, не через `--flag`).
    fn from_env() -> Self {
        let vpn_node_addr = std::env::var("VPN_NODE_ADDR")
            .expect("VPN_NODE_ADDR обязателен — host:port вашей VPN-ноды");
        let backend_addr = std::env::var("BACKEND_ADDR")
            .expect("BACKEND_ADDR обязателен — host:port бэкенда за нодой");
        let decoy_sni = std::env::var("DECOY_SNI").unwrap_or_else(|_| "www.debian.org".to_string());
        let auth_token = std::env::var("AUTH_TOKEN").unwrap_or_default();
        Self {
            vpn_node_addr,
            backend_addr,
            decoy_sni,
            auth_token,
        }
    }
}

/// Аргументы командной строки — только про то, где слушать. Секреты и
/// протокольные адреса — исключительно `EdgeConfig::from_env` (см. её doc).
#[derive(Parser, Debug)]
#[command(author, version, about = "Netrunner Edge (native, non-Workers)")]
struct Args {
    /// Адрес привязки. Слушает на этом хосте:порте открытым HTTP —
    /// см. README.md за тем, почему TLS-терминацию должен делать Caddy/nginx
    /// перед этим процессом, а не сам процесс.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    #[arg(short, long, default_value_t = 8082)]
    port: u16,
}

/// Decoy-страница — общая для трёх мест: не-WS/не-HTTP-прокси-путь ниже уже
/// не бывает (см. `handle`), но `proxy_http::proxy` тоже отдаёт её как
/// graceful fallback, если сам бэкенд/нода недоступны (см. её doc comment).
pub(crate) fn decoy_response() -> Response {
    Html(DECOY_PAGE_HTML).into_response()
}

/// Единственный маршрут: WS-апгрейд уходит в мост (`bridge.rs`), любой
/// другой HTTP-запрос — в открытый реверс-прокси (`proxy_http.rs`), который
/// сам решит, что ответить (реальный сайт или decoy при сбое). `WebSocketUpgrade`
/// извлекается вручную через `from_request_parts`, а не как параметр-
/// экстрактор — иначе запрос без нужных заголовков падал бы 400-й ошибкой
/// axum ДО того, как этот обработчик вообще получит управление, вместо
/// тихого ухода в HTTP-прокси-ветку (то же поведение, что и explicit-проверка
/// `Upgrade`-заголовка в wasm-варианте, `client-edge/src/lib.rs::fetch`).
async fn handle(State(cfg): State<Arc<EdgeConfig>>, req: Request) -> Response {
    let is_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !is_upgrade {
        return proxy_http::proxy(cfg, req).await;
    }

    let (mut parts, _body) = req.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &cfg).await {
        Ok(ws) => ws.on_upgrade(move |socket| bridge::run(socket, cfg)),
        // Заголовок Upgrade: websocket есть, но остальное (Sec-WebSocket-Key
        // и т.п.) не сходится — тот же decoy, не axum-дефолтная ошибка.
        Err(_) => decoy_response(),
    }
}

async fn shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Не удалось установить обработчик Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Не удалось установить обработчик SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("🛑 Получен SIGINT (Ctrl+C). Останавливаемся..."),
        _ = terminate => info!("🛑 Получен SIGTERM. Останавливаемся..."),
    }
    token.cancel();
}

#[tokio::main]
async fn main() {
    // rustls 0.23+ больше не выбирает крипто-бэкенд неявно (даже когда в
    // дереве зависимостей включена только ОДНА фича, "ring") — без этого
    // явного вызова ПЕРВЫЙ же `rustls::ClientConfig::builder()` в
    // `proxy_http.rs` паникует в отдельной tokio-задаче на каждый запрос
    // (см. `rustls::crypto::CryptoProvider`). Ставить нужно РОВНО один раз
    // за жизнь процесса, до первого TLS-хендшейка — то есть здесь, в start.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Не удалось установить крипто-провайдер rustls");

    // Та же причина, что и у netrunner-server: НЕ пишем JSON-лог на диск —
    // JSON уходит в stdout, виден через `docker logs`/journalctl.
    Logger::init(None, true);
    Logger::global().set_level("info");

    let args = Args::parse();
    let cfg = Arc::new(EdgeConfig::from_env());

    info!(
        "🛰️  netrunner-edge слушает {}:{} → нода {} → бэкенд {}",
        args.host, args.port, cfg.vpn_node_addr, cfg.backend_addr
    );

    let app = Router::new()
        .route("/", any(handle))
        .fallback(any(handle))
        .with_state(cfg);

    let listener = match TcpListener::bind((args.host.as_str(), args.port)).await {
        Ok(l) => l,
        Err(e) => {
            error!("Не удалось забиндиться на {}:{}: {e}", args.host, args.port);
            std::process::exit(1);
        }
    };

    let token = CancellationToken::new();
    let shutdown_token = token.clone();

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal(shutdown_token).await;
        })
        .await
    {
        error!("Сервер завершился с ошибкой: {e}");
        std::process::exit(1);
    }

    info!("✅ netrunner-edge остановлен.");
}
