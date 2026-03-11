use tauri::{
  plugin::{Builder, TauriPlugin},
  Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::Vpn;
#[cfg(mobile)]
use mobile::Vpn;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the vpn APIs.
pub trait VpnExt<R: Runtime> {
  fn vpn(&self) -> &Vpn<R>;
}

impl<R: Runtime, T: Manager<R>> crate::VpnExt<R> for T {
  fn vpn(&self) -> &Vpn<R> {
    self.state::<Vpn<R>>().inner()
  }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
  Builder::new("vpn")
    .invoke_handler(tauri::generate_handler![commands::ping])
    .setup(|app, api| {
      #[cfg(mobile)]
      let vpn = mobile::init(app, api)?;
      #[cfg(desktop)]
      let vpn = desktop::init(app, api)?;
      app.manage(vpn);
      Ok(())
    })
    .build()
}
