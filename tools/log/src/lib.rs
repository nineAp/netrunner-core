use std::sync::{Once, OnceLock};
pub use tracing::{debug, error, info, instrument, span, trace, warn};
use tracing_subscriber::{
    fmt, layer::SubscriberExt, reload::Handle, util::SubscriberInitExt, EnvFilter, Registry,
};
type ReloadableFilter = Handle<EnvFilter, Registry>;

pub struct Logger {
    filter_handle: ReloadableFilter,
}

static INIT: Once = Once::new();
static LOGGER: OnceLock<Logger> = OnceLock::new();

impl Logger {
    pub fn init() {
        INIT.call_once(|| {
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);

            let registry = tracing_subscriber::registry().with(filter);

            #[cfg(target_os = "android")]
            let registry = {
                let android_layer = tracing_android::layer("NETRUNNER_RUST")
                    .expect("Failed to create android layer");
                registry.with(android_layer)
            };

            #[cfg(not(target_os = "android"))]
            let registry = {
                let fmt_layer = fmt::layer()
                    .with_target(true)
                    .with_line_number(true)
                    .with_ansi(true)
                    .with_writer(std::io::stdout);
                registry.with(fmt_layer)
            };

            registry.init();

            let _ = LOGGER.set(Logger {
                filter_handle: handle,
            });
            eprintln!("--- [DEBUG] Logger initialized ---");
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
