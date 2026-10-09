//! Обёртка над [`AuthValidator`]: каталог и допуск mesh-пиров берутся из
//! [`Directory`], а учётные записи и биллинг (если есть панель) — из неё.
//!
//! Узел без панели (`inner = None`) не принимает пользовательских токенов, но
//! полноценно участвует в mesh: это и есть «автономный режим», которого раньше
//! не было (`MESH.md` §11 п. 5).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use netrunner_logger::{AppError, ERR_AUTH_FAILED};

use super::{unix_now, Directory};
use crate::net::{AuthValidator, MeshPeer, NodeHealthReport, UsageDelta, UsageReport, UserQuota};

pub struct DirectoryValidator {
    directory: Arc<Directory>,
    inner: Option<Arc<dyn AuthValidator>>,
}

impl DirectoryValidator {
    pub fn new(directory: Arc<Directory>, inner: Option<Arc<dyn AuthValidator>>) -> Self {
        Self { directory, inner }
    }

    pub fn directory(&self) -> &Arc<Directory> {
        &self.directory
    }
}

fn unavailable() -> AppError {
    AppError::new(
        ERR_AUTH_FAILED,
        "Доступ запрещен",
        "Standalone swarm node: user accounts are not available",
    )
}

#[async_trait]
impl AuthValidator for DirectoryValidator {
    async fn validate(&self, token: &str) -> Result<UserQuota, AppError> {
        match &self.inner {
            Some(v) => v.validate(token).await,
            None => Err(unavailable()),
        }
    }

    async fn report_usage(&self, user_id: &str, delta_bytes: u64) -> Result<UsageReport, AppError> {
        match &self.inner {
            Some(v) => v.report_usage(user_id, delta_bytes).await,
            None => Err(unavailable()),
        }
    }

    async fn report_usage_batch(
        &self,
        batch_id: &str,
        deltas: &[UsageDelta],
    ) -> Result<HashMap<String, UsageReport>, AppError> {
        match &self.inner {
            Some(v) => v.report_usage_batch(batch_id, deltas).await,
            None => Ok(HashMap::new()),
        }
    }

    async fn report_node_health(&self, report: NodeHealthReport) -> Result<(), AppError> {
        match &self.inner {
            Some(v) => v.report_node_health(report).await,
            None => Ok(()),
        }
    }

    async fn list_mesh_peers(&self) -> Result<Vec<MeshPeer>, AppError> {
        Ok(self.directory.peers(unix_now()))
    }

    async fn validate_mesh_peer(&self, peer_id: &str, peer_secret: &str) -> Result<(), AppError> {
        if self.directory.validate_mesh_peer(peer_id, peer_secret) {
            Ok(())
        } else {
            Err(AppError::new(
                ERR_AUTH_FAILED,
                "Mesh peer rejected",
                "Peer does not hold the swarm key for its node id",
            ))
        }
    }
}
