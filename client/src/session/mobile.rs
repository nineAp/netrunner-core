use crate::session::{Session, SessionManager};
use std::sync::Arc;
use uniffi;

#[uniffi::export]
impl SessionManager {
    pub fn start_mobile(&self, remote_address: String, tun_fd: i32) -> Arc<Session> {
        self.spawn_session(remote_address, Some(tun_fd))
    }
}
