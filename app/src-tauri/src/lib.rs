mod core;
use core::start_vpn_android::start_vpn_android;
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("NetrunnerRust"),
    );
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start_vpn_android])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
