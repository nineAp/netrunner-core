use super::{Session, SessionManager};
use std::sync::Arc;
use uniffi;

#[uniffi::export]
impl SessionManager {
    pub fn start_mobile(
        &self,
        remote_address: String,
        tun_fd: i32,
        cache_dir: String,
    ) -> Arc<Session> {
        self.spawn_session(remote_address, Some(tun_fd), cache_dir)
    }

    pub fn start_desktop(&self, remote_address: String, cache_dir: String) -> Arc<Session> {
        self.spawn_session(remote_address, None, cache_dir)
    }
}
