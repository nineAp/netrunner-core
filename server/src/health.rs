//! Минимальный HTTP `/health` для supervisor'а (systemd/docker healthcheck) —
//! отдельный порт, не тот, где слушается замаскированный туннельный протокол
//! (смешивать их нельзя: health-эндпоинт — обычный читаемый HTTP, это выдало
//! бы DPI ровно то, что декой должен скрывать). По умолчанию биндится только
//! на 127.0.0.1 — наружу торчать не должен, это внутренняя проверка для
//! supervisor'а/docker healthcheck на этой же машине.
//!
//! Не использует HTTP-фреймворк (лишняя зависимость ради одного эндпоинта) —
//! отвечает одним и тем же 200+JSON на любое подключение, не разбирая запрос.

use netrunner_logger::{error, info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Отдаёт реальное состояние — не просто "процесс жив", а сколько сейчас
/// физических соединений реально обслуживается (см. `Network::run`,
/// `active_connections`).
pub async fn run(
    host: String,
    port: u16,
    active_connections: Arc<AtomicU64>,
    token: CancellationToken,
) {
    let addr = format!("{host}:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %addr, "Не удалось поднять health-listener");
            return;
        }
    };
    info!("🩺 Health-эндпоинт слушает на {}", addr);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("Health-listener остановлен по сигналу отмены.");
                break;
            }
            res = listener.accept() => {
                let Ok((mut stream, _)) = res else { continue };
                let active = active_connections.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    let body = format!(
                        r#"{{"status":"ok","active_connections":{active}}}"#
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if let Err(e) = stream.write_all(response.as_bytes()).await {
                        warn!(error = %e, "Health-listener: ошибка записи ответа");
                    }
                });
            }
        }
    }
}
