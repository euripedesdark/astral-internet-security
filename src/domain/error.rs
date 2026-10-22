use axum::http::StatusCode;
use serde_json::{json, Value};

#[derive(Debug)]
pub enum FirewallError {
    RuleNotFound(String),
    InvalidRule(String),
    BackendError(String),
    StorageError(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuleNotFound(id) => write!(f, "Rule not found: {}", id),
            Self::InvalidRule(msg) => write!(f, "Invalid rule: {}", msg),
            Self::BackendError(msg) => write!(f, "Firewall backend error: {}", msg),
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for FirewallError {}

impl FirewallError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::RuleNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidRule(_) => StatusCode::BAD_REQUEST,
            Self::BackendError(_) | Self::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn to_json_response(&self) -> (StatusCode, axum::Json<Value>) {
        (self.status_code(), axum::Json(json!({"error": self.to_string()})))
    }
}
