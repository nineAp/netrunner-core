#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// 2. Только после него идут импорты
use tauri;

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
