use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use http::Request;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::warn;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct BearerAuth {
    mode: AuthMode,
}

#[derive(Clone, Debug)]
enum AuthMode {
    Anonymous,
    Static(String),
    Remote(RemoteAuth),
}

#[derive(Clone, Debug)]
struct RemoteAuth {
    client: Client,
    url: String,
    usage_url: String,
    internal_secret: String,
    cache: Arc<RwLock<HashMap<[u8; 32], CacheEntry>>>,
    allow_ttl: Duration,
    deny_ttl: Duration,
}

#[derive(Clone, Copy, Debug)]
struct CacheEntry {
    allowed: bool,
    subject_id: Option<Uuid>,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthGrant {
    subject_id: Option<Uuid>,
}

#[derive(Serialize)]
struct ValidateRequest<'a> {
    token: &'a str,
}

#[derive(Deserialize)]
struct ValidateResponse {
    user_id: Uuid,
    limit_bytes: Option<i64>,
    used_bytes: i64,
}

#[derive(Serialize)]
struct UsageRequest {
    user_id: Uuid,
    delta_bytes: i64,
}

#[derive(Deserialize)]
struct UsageResponse {
    over_limit: bool,
}

impl BearerAuth {
    pub fn new(token: Option<String>) -> Self {
        Self {
            mode: token.map_or(AuthMode::Anonymous, AuthMode::Static),
        }
    }

    pub fn remote(url: String, usage_url: String, internal_secret: String) -> Result<Self> {
        if url.trim().is_empty() || usage_url.trim().is_empty() || internal_secret.trim().is_empty()
        {
            bail!("remote auth URL, usage URL and internal secret must all be non-empty");
        }

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .context("failed to build MASQUE auth HTTP client")?;

        Ok(Self {
            mode: AuthMode::Remote(RemoteAuth {
                client,
                url,
                usage_url,
                internal_secret,
                cache: Arc::new(RwLock::new(HashMap::new())),
                allow_ttl: Duration::from_secs(30),
                deny_ttl: Duration::from_secs(3),
            }),
        })
    }

    pub async fn authorize(&self, request: &Request<()>) -> Option<AuthGrant> {
        let Some(actual) = bearer_token(request) else {
            return matches!(self.mode, AuthMode::Anonymous)
                .then_some(AuthGrant { subject_id: None });
        };

        match &self.mode {
            AuthMode::Anonymous => Some(AuthGrant { subject_id: None }),
            AuthMode::Static(expected) => constant_time_eq(actual.as_bytes(), expected.as_bytes())
                .then_some(AuthGrant { subject_id: None }),
            AuthMode::Remote(remote) => remote.authorize(actual).await,
        }
    }

    /// Возвращает `true`, если backend сообщает о достигнутом лимите.
    pub async fn report_usage(&self, grant: AuthGrant, delta_bytes: u64) -> bool {
        if delta_bytes == 0 {
            return false;
        }
        let (AuthMode::Remote(remote), Some(subject_id)) = (&self.mode, grant.subject_id) else {
            return false;
        };
        remote.report_usage(subject_id, delta_bytes).await
    }
}

impl RemoteAuth {
    async fn authorize(&self, token: &str) -> Option<AuthGrant> {
        let fingerprint: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let now = Instant::now();
        if let Some(entry) = self.cache.read().await.get(&fingerprint).copied() {
            if entry.expires_at > now {
                return entry.allowed.then_some(AuthGrant {
                    subject_id: entry.subject_id,
                });
            }
        }

        let grant = match self
            .client
            .post(&self.url)
            .header("X-Internal-Secret", &self.internal_secret)
            .json(&ValidateRequest { token })
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                match response.json::<ValidateResponse>().await {
                    Ok(response)
                        if !response
                            .limit_bytes
                            .is_some_and(|limit| response.used_bytes >= limit) =>
                    {
                        Some(AuthGrant {
                            subject_id: Some(response.user_id),
                        })
                    }
                    Ok(_) => None,
                    Err(error) => {
                        warn!(%error, "MASQUE auth response has invalid JSON");
                        None
                    }
                }
            }
            Ok(_) => None,
            Err(error) => {
                warn!(
                    token_fingerprint = %hex::encode(&fingerprint[..6]),
                    %error,
                    "MASQUE remote authorization failed closed"
                );
                None
            }
        };

        let ttl = if grant.is_some() {
            self.allow_ttl
        } else {
            self.deny_ttl
        };
        let mut cache = self.cache.write().await;
        cache.insert(
            fingerprint,
            CacheEntry {
                allowed: grant.is_some(),
                subject_id: grant.and_then(|grant| grant.subject_id),
                expires_at: now + ttl,
            },
        );
        if cache.len() > 4096 {
            cache.retain(|_, entry| entry.expires_at > now);
        }
        grant
    }

    async fn report_usage(&self, subject_id: Uuid, delta_bytes: u64) -> bool {
        let delta_bytes = delta_bytes.min(i64::MAX as u64) as i64;
        match self
            .client
            .post(&self.usage_url)
            .header("X-Internal-Secret", &self.internal_secret)
            .json(&UsageRequest {
                user_id: subject_id,
                delta_bytes,
            })
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response
                .json::<UsageResponse>()
                .await
                .map(|response| response.over_limit)
                .unwrap_or(false),
            Ok(response) => {
                warn!(status = %response.status(), "MASQUE usage report rejected");
                false
            }
            Err(error) => {
                warn!(%error, "MASQUE usage report failed");
                false
            }
        }
    }
}

fn bearer_token(request: &Request<()>) -> Option<&str> {
    request
        .headers()
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_bearer_token() {
        let request = Request::builder()
            .header("authorization", "Bearer secret")
            .body(())
            .unwrap();
        assert!(authorize(&BearerAuth::new(Some("secret".into())), &request));
    }

    #[test]
    fn rejects_missing_or_different_token() {
        let missing = Request::new(());
        let different = Request::builder()
            .header("authorization", "Bearer nope")
            .body(())
            .unwrap();
        let auth = BearerAuth::new(Some("secret".into()));
        assert!(!authorize(&auth, &missing));
        assert!(!authorize(&auth, &different));
    }

    #[test]
    fn anonymous_mode_accepts_requests_without_header() {
        assert!(authorize(&BearerAuth::new(None), &Request::new(())));
    }

    fn authorize(auth: &BearerAuth, request: &Request<()>) -> bool {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(auth.authorize(request))
            .is_some()
    }
}
