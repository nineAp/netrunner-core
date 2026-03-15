uniffi::setup_scaffolding!();
mod connections;
pub mod tun;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tracing::info;
mod session;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}
#[derive(uniffi::Object)]
pub struct Session {
    pub(crate) shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Session {
    pub fn stop(&self) {
        let mut guard = self.shutdown_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        info!("Session dropped, resetting platform routing...");
        if let Ok(mut tx) = self.shutdown_tx.lock() {
            if let Some(tx) = tx.take() {
                let _ = tx.send(());
            }
        }
        let _ = crate::tun::routing::reset_platform_routing();
    }
}
