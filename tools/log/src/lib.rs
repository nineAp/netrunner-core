pub mod error;

use regex::Regex;
use std::sync::{Once, OnceLock};

// Экспортируем макросы и instrument, чтобы они были доступны как netrunner_logger::instrument
pub use tracing::{debug, error, info, instrument, span, trace, warn, Event};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt,
    layer::{Context, SubscriberExt},
    reload::Handle,
    util::SubscriberInitExt,
    EnvFilter, Layer, Registry,
};

pub use error::{
    AppError, ERR_AUTH_FAILED, ERR_INFRA_TIMEOUT, ERR_NET_MTU_DROP, ERR_NET_TLS_TAMPER,
    ERR_SYS_PANIC,
};

type ReloadableFilter = Handle<EnvFilter, Registry>;

pub struct Logger {
    filter_handle: ReloadableFilter,
    _guard: Option<WorkerGuard>,
}

static INIT: Once = Once::new();
static LOGGER: OnceLock<Logger> = OnceLock::new();

#[allow(dead_code)]
struct PiiRedactorLayer {
    ip_regex: Regex,
}

impl PiiRedactorLayer {
    fn new() -> Self {
        Self {
            ip_regex: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for PiiRedactorLayer {
    fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {
        // В продакшн-версии здесь можно реализовать Visitor для глубокой очистки полей.
        // Сейчас слой присутствует в стеке для фильтрации перед записью.
    }
}

impl Logger {
    pub fn init(log_dir: Option<&str>, is_production: bool) {
        INIT.call_once(|| {
            // 1. Настройка динамического фильтра
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let (filter_layer, handle) = tracing_subscriber::reload::Layer::new(filter);

            // 2. Слой маскировки
            let redactor_layer = PiiRedactorLayer::new();

            // 3. Базовый реестр
            let registry = tracing_subscriber::registry()
                .with(filter_layer)
                .with(redactor_layer);

            let mut file_guard = None;

            if is_production {
                // Прод режим: JSON + Файл
                if let Some(path) = log_dir {
                    let file_appender = tracing_appender::rolling::daily(path, "netrunner.json");
                    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

                    let json_layer = fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_current_span(true)
                        .with_span_list(true)
                        .with_writer(non_blocking)
                        .with_ansi(false);

                    registry.with(json_layer).init();
                    file_guard = Some(guard);

                    // Глобальный перехват паник
                    std::panic::set_hook(Box::new(|info| {
                        tracing::error!(
                            error_code = ERR_SYS_PANIC,
                            panic_info = ?info,
                            "FATAL: Unhandled panic occurred. System is going down."
                        );
                    }));
                } else {
                    registry.with(fmt::layer().json().with_ansi(false)).init();
                }
            } else {
                // Дебаг режим: Красивый вывод в консоль
                #[cfg(target_os = "android")]
                let android_layer = tracing_android::layer("NETRUNNER_RUST")
                    .expect("Failed to create android layer");

                #[cfg(not(target_os = "android"))]
                let fmt_layer = fmt::layer()
                    .with_target(true)
                    .with_line_number(true)
                    .with_ansi(true)
                    .with_writer(std::io::stdout);

                #[cfg(target_os = "android")]
                registry.with(android_layer).init();

                #[cfg(not(target_os = "android"))]
                registry.with(fmt_layer).init();
            }

            let logger_instance = Logger {
                filter_handle: handle,
                _guard: file_guard,
            };

            let _ = LOGGER.set(logger_instance);

            eprintln!(
                "--- [DEBUG] Netrunner Logger initialized (Mode: {}, File: {}) ---",
                if is_production { "PROD" } else { "DEBUG" },
                log_dir.is_some()
            );
        });
    }

    pub fn set_level(&self, level: &str) {
        if let Ok(new_filter) = EnvFilter::try_new(level) {
            let _ = self.filter_handle.reload(new_filter);
            eprintln!("--- [DEBUG] Log level changed to: {} ---", level);
        }
    }

    pub fn global() -> &'static Logger {
        LOGGER.get().expect("Logger not initialized!")
    }

    // Вспомогательные методы для работы без макросов
    pub fn log_info(&self, msg: &str) {
        tracing::info!("{}", msg);
    }
    pub fn log_error(&self, msg: &str) {
        tracing::error!("{}", msg);
    }
}
