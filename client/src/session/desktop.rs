use super::{Session, SessionManager};
use std::sync::Arc;

impl SessionManager {
    pub fn start_desktop(&self, remote_address: String) -> Arc<Session> {
        self.spawn_session(remote_address)
    }
}
