use bytes::Bytes;
use tracing::{error, trace, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    Wait,
    Redirect,
    Drop,
}

#[derive(Debug)]
pub enum ErrorStage {
    Tls(&'static str),
    Handshake(&'static str),
    ApplicationData(&'static str),
}

#[derive(Debug)]
pub struct TlsError {
    pub stage: ErrorStage,
    pub action: ErrorAction,
    pub data: Bytes,
}

impl TlsError {
    pub fn new(stage: ErrorStage, action: ErrorAction, data: Bytes) -> Self {
        Self {
            stage,
            action,
            data,
        }
    }

    fn log_error(&self) {
        // Определяем уровень логирования в зависимости от действия
        // Если мы просто ждем данные (Wait) — это не ошибка, а рабочий процесс (debug/trace)
        // Если дропаем соединение (Drop) — это серьезно (error)

        let stage_name = match &self.stage {
            ErrorStage::Tls(_) => "TLS",
            ErrorStage::Handshake(_) => "Handshake",
            ErrorStage::ApplicationData(_) => "AppData",
        };

        let message = match &self.stage {
            ErrorStage::Tls(m) | ErrorStage::Handshake(m) | ErrorStage::ApplicationData(m) => m,
        };

        // Подготавливаем превью данных (первые 8 байт в хексе)
        let data_preview = if !self.data.is_empty() {
            let limit = self.data.len().min(8);
            format!(
                "Hex: {:02x?}{}",
                &self.data[..limit],
                if self.data.len() > 8 { "..." } else { "" }
            )
        } else {
            "No data".to_string()
        };

        match self.action {
            ErrorAction::Wait => {
                // Wait — это нормальное состояние асинхронного чтения
                trace!(
                    stage = stage_name,
                    action = ?self.action,
                    data = %data_preview,
                    "{}", message
                );
            }
            ErrorAction::Redirect => {
                warn!(
                    stage = stage_name,
                    action = ?self.action,
                    data = %data_preview,
                    "⚠️ {}", message
                );
            }
            ErrorAction::Drop => {
                error!(
                    stage = stage_name,
                    action = ?self.action,
                    data = %data_preview,
                    "🚨 {}", message
                );
            }
        }
    }

    pub fn execute_strategy(&self) -> ErrorAction {
        self.log_error();
        self.action
    }
}
