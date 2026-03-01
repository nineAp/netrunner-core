use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn logger_init() {
    let fmt_layer = fmt::layer()
        .with_target(true) // Показывать, из какого модуля пришел лог
        .with_thread_ids(false)
        .with_line_number(true); // Показывать строку кода (очень полезно для дебага)

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info")) // По умолчанию уровень info
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}
