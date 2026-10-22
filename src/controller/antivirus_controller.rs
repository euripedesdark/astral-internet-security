use crate::domain::{AntivirusBypass, DecompressionLimits};
use crate::service::AntivirusEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct AntivirusController {
    engine: Arc<dyn AntivirusEngine>,
}

impl AntivirusController {
    pub fn new(engine: Arc<dyn AntivirusEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_get_status(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_status()))
    }

    pub fn handle_trigger_update(&self) -> Response {
        match self.engine.trigger_freshclam_update() {
            Ok(status) => (StatusCode::OK, Json(status)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_quarantine(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_quarantine_items()))
    }

    pub fn handle_delete_quarantine(&self, id: &str) -> Response {
        match self.engine.delete_quarantine_item(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_limits(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_decompression_limits()))
    }

    pub fn handle_set_limits(&self, limits: DecompressionLimits) -> Response {
        match self.engine.set_decompression_limits(limits) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_bypass(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_antivirus_bypass()))
    }

    pub fn handle_set_bypass(&self, bypass: AntivirusBypass) -> Response {
        match self.engine.set_antivirus_bypass(bypass) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }
}
