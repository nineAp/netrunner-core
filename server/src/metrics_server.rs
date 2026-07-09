//! `/metrics` для центрального Prometheus (см.
//! `netrunner-data/docker-compose.observability.yml`) — в отличие от
//! `/health` (127.0.0.1-only, см. `health.rs`), этот порт публикуется наружу
//! и ОБЯЗАТЕЛЬНО должен быть зафайрволен на IP observability-VPS: любой,
//! кто до него дотянется, увидит число активных соединений/трафик этой
//! ноды (не секрет пользователей, но разведка для DPI/блокировщика).
//!
//! Тот же hand-rolled HTTP-паттерн, что и в `health.rs` (не тянуть HTTP-
//! фреймворк ради одного эндпоинта на бинарнике, для которого важен размер
//! и минимальные зависимости) — просто рендерит текущий снапшот метрик из
//! уже установленного `PrometheusHandle` на каждый коннект.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use netrunner_logger::{error, info, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Регистрирует глобальный recorder `metrics`-крейта — вызывать ровно один
/// раз при старте, до первого `metrics::counter!`/`gauge!`/`histogram!`.
pub fn install_recorder() -> PrometheusHandle {
    PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder")
}

pub async fn run(host: String, port: u16, handle: PrometheusHandle, token: CancellationToken) {
    let addr = format!("{host}:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %addr, "Не удалось поднять metrics-листенер");
            return;
        }
    };
    info!("📊 Metrics-эндпоинт слушает на {}", addr);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("Metrics-listener остановлен по сигналу отмены.");
                break;
            }
            res = listener.accept() => {
                let Ok((mut stream, _)) = res else { continue };
                let body = handle.render();
                tokio::spawn(async move {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if let Err(e) = stream.write_all(response.as_bytes()).await {
                        warn!(error = %e, "Metrics-listener: ошибка записи ответа");
                    }
                });
            }
        }
    }
}
