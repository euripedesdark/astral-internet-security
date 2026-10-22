use crate::domain::{AlgConfig, NatRule};
use crate::service::NatEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct NatController {
    engine: Arc<dyn NatEngine>,
}

impl NatController {
    pub fn new(engine: Arc<dyn NatEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_get_rules(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_rules()))
    }

    pub fn handle_add_rule(&self, rule: NatRule) -> Response {
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

    pub fn handle_get_alg(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_alg_config()))
    }

    pub fn handle_set_alg(&self, config: AlgConfig) -> Response {
        match self.engine.set_alg_config(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }
}
