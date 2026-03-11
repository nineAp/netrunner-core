mod core;
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("NetrunnerRust"),
    );
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
