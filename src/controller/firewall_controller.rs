use crate::domain::{FirewallRule, NatRule};
use crate::service::FirewallEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct PanicRequest {
    pub enabled: bool,
}

#[derive(Clone)]
pub struct FirewallController {
    engine: Arc<dyn FirewallEngine>,
}

impl FirewallController {
    pub fn new(engine: Arc<dyn FirewallEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_health(&self) -> Json<serde_json::Value> {
        Json(json!({ "status": "UP", "service": "astral-internet-security" }))
    }

    pub fn handle_state(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_state()))
    }

    pub fn handle_get_rules(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_rules()))
    }

    pub fn handle_add_rule(&self, rule: FirewallRule) -> Response {
        match self.engine.add_rule(rule) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_delete_rule(&self, id: &str) -> Response {
        match self.engine.delete_rule(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_nat(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_nat_rules()))
    }

    pub fn handle_add_nat(&self, rule: NatRule) -> Response {
        match self.engine.add_nat_rule(rule) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_delete_nat(&self, id: &str) -> Response {
        match self.engine.delete_nat_rule(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_panic(&self, req: PanicRequest) -> Response {
        match self.engine.set_panic_mode(req.enabled) {
            Ok(active) => (StatusCode::OK, Json(json!({"panicMode": active}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_stats(&self) -> Json<serde_json::Value> {
        let stats = self.engine.get_interface_stats();
        Json(json!({
            "timestamp": Utc::now().to_rfc3339(),
            "interfaces": stats
        }))
    }
}
