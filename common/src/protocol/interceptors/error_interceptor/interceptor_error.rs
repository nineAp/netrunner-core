use bytes::Bytes;

#[derive(Debug, Clone, Copy)]
pub enum ErrorAction {
    Wait,
    Redirect,
    Drop,
}

pub enum ErrorType {
    Tls(&'static str),
    Handshake(&'static str),
    ApplicationData(&'static str),
}

pub struct InterceptorError {
    pub error_type: ErrorType,
    pub action: ErrorAction,
    pub data: Bytes,
}

impl InterceptorError {
    pub fn new(error_type: ErrorType, action: ErrorAction, data: Bytes) -> Self {
        Self {
            error_type,
            action,
            data,
        }
    }
    fn log_error(&self) {
        let (category, message) = match &self.error_type {
            ErrorType::Tls(m) => ("TLS", m),
            ErrorType::Handshake(m) => ("Handshake", m),
            ErrorType::ApplicationData(m) => ("AppData", m),
        };
        println!(
            "[{}] Error: {} (Byte: {:#02x})",
            category, message, self.data
        );
    }

    pub fn execute_strategy(&self) -> ErrorAction {
        self.log_error();
        self.action
    }
}
