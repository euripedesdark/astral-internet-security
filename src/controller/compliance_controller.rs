use crate::domain::SyslogRemoteConfig;
use crate::service::ComplianceEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct CreateSnapshotRequest {
    pub author: String,
    pub description: String,
}

#[derive(Clone)]
pub struct ComplianceController {
    engine: Arc<dyn ComplianceEngine>,
}

impl ComplianceController {
    pub fn new(engine: Arc<dyn ComplianceEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_get_audit_logs(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_audit_logs(100)))
    }

    pub fn handle_get_syslog(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_syslog_config()))
    }

    pub fn handle_set_syslog(&self, config: SyslogRemoteConfig) -> Response {
        match self.engine.set_syslog_config(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_ntp(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_ntp_status()))
    }

    pub fn handle_get_snapshots(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_config_snapshots()))
    }

    pub fn handle_create_snapshot(&self, req: CreateSnapshotRequest) -> Response {
        match self.engine.create_snapshot(&req.author, &req.description) {
            Ok(snap) => (StatusCode::CREATED, Json(snap)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_rollback_snapshot(&self, id: &str) -> Response {
        match self.engine.rollback_to_snapshot(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"rollback": true, "snapshotId": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_backup(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_backup_status()))
    }

    pub fn handle_trigger_backup(&self) -> Response {
        match self.engine.trigger_encrypted_backup() {
            Ok(b) => (StatusCode::OK, Json(b)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }
}
