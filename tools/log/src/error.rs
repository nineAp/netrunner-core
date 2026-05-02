// tools/log/src/error.rs
use std::collections::HashMap;
use std::fmt;

// Реестр кодов ошибок (Error Codes Registry)
pub const ERR_INFRA_TIMEOUT: &str = "INFRA_TIMEOUT";
pub const ERR_AUTH_FAILED: &str = "AUTH_FAILED";
pub const ERR_NET_MTU_DROP: &str = "NET_TUNNEL_MTU_DROP";
pub const ERR_NET_TLS_TAMPER: &str = "NET_TLS_TAMPER";
pub const ERR_SYS_PANIC: &str = "SYS_UNHANDLED_PANIC";

#[derive(Debug)]
pub struct AppError {
    pub code: &'static str,
    pub user_msg: String,
    pub internal_msg: String,
    pub metadata: HashMap<String, String>,
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AppError {
    pub fn new(
        code: &'static str,
        user_msg: impl Into<String>,
        internal_msg: impl Into<String>,
    ) -> Self {
        Self {
            code,
            user_msg: user_msg.into(),
            internal_msg: internal_msg.into(),
            metadata: HashMap::new(),
            cause: None,
        }
    }

    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_cause(mut self, err: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Box::new(err));
        self
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.internal_msg)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as _)
    }
}
