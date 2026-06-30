//! Утилита генерации FFI-биндингов (UniFFI).
//!
//! Тонкая обёртка вокруг `uniffi_bindgen`: по `.udl`-описанию клиента
//! (`client/src/netrunner_client.udl`) генерирует Kotlin/Swift-обёртки для вызова
//! нативных функций из мобильного приложения. Запускается из `Makefile`
//! (цель `build-android`) как отдельный бинарь.

fn main() {
    uniffi::uniffi_bindgen_main();
}
