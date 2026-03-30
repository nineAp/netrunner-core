use std::sync::{Once, OnceLock};
pub use tracing::{debug, error, info, instrument, span, trace, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, reload::Handle, util::SubscriberInitExt, EnvFilter, Registry,
};
type ReloadableFilter = Handle<EnvFilter, Registry>;

pub struct Logger {
    filter_handle: ReloadableFilter,
    _guard: Option<WorkerGuard>,
}

static INIT: Once = Once::new();
static LOGGER: OnceLock<Logger> = OnceLock::new();

impl Logger {
    pub fn init(log_dir: Option<&str>) {
        INIT.call_once(|| {
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let (filter_layer, handle) = tracing_subscriber::reload::Layer::new(filter);

            let mut file_guard = None;
            let mut file_layer = None;

            // Настраиваем запись в файл, если передан путь
            if let Some(path) = log_dir {
                // Ротация: новый файл каждый день, префикс "netrunner.log"
                let file_appender = tracing_appender::rolling::daily(path, "netrunner.log");
                let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

                file_layer = Some(
                    fmt::layer()
                        .with_writer(non_blocking)
                        .with_ansi(false) // В файле цвета не нужны
                        .with_target(true)
                        .with_line_number(true),
                );
                file_guard = Some(guard);
            }

            let registry = tracing_subscriber::registry().with(filter_layer);

            // Слой для Android
            #[cfg(target_os = "android")]
            let registry = {
                let android_layer = tracing_android::layer("NETRUNNER_RUST")
                    .expect("Failed to create android layer");
                registry.with(android_layer)
            };

            // Слой для консоли (Desktop/Server)
            #[cfg(not(target_os = "android"))]
            let registry = {
                let fmt_layer = fmt::layer()
                    .with_target(true)
                    .with_line_number(true)
                    .with_ansi(true)
                    .with_writer(std::io::stdout);
                registry.with(fmt_layer)
            };

            // Добавляем файловый слой, если он был создан
            if let Some(f_layer) = file_layer {
                registry.with(f_layer).init();
            } else {
                registry.init();
            }

            let _ = LOGGER.set(Logger {
                filter_handle: handle,
                _guard: file_guard,
            });

            eprintln!(
                "--- [DEBUG] Logger initialized (File logging: {}) ---",
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

    pub fn info(&self, msg: &str) {
        tracing::info!("{}", msg);
    }
    pub fn debug(&self, msg: &str) {
        tracing::debug!("{}", msg);
    }
    pub fn error(&self, msg: &str) {
        tracing::error!("{}", msg);
    }
    pub fn warn(&self, msg: &str) {
        tracing::warn!("{}", msg);
    }
}
