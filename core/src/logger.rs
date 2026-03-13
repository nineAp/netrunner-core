use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

pub fn logger_init() {
    eprintln!("--- [DEBUG] logger_init start ---");
    let _ = LogTracer::init();

    // 4. Фильтр (создаем его один раз для всех)
    let filter_layer =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));

    // Инициализируем базовый реестр
    let registry = tracing_subscriber::registry().with(filter_layer);

    // 2 & 5. Собираем реестр с учетом платформы
    #[cfg(target_os = "android")]
    {
        // Слой для Android Logcat
        let android_layer =
            tracing_android::layer("NETRUNNER_RUST").expect("Failed to create android layer");

        let subscriber = registry.with(android_layer);
        if let Err(e) = subscriber.try_init() {
            eprintln!("Subscriber already set: {:?}", e);
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        // 3. Слой для консоли (только для Linux/десктопа)
        let fmt_layer = fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false);

        let subscriber = registry.with(fmt_layer);
        if let Err(e) = subscriber.try_init() {
            eprintln!("Subscriber already set: {:?}", e);
        }
    }
}
