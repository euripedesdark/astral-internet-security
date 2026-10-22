use crate::domain::{DohConfig, EdgeJwtValidator, ZtnaAppPublish};
use crate::service::ZeroTrustEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct ZeroTrustController {
    engine: Arc<dyn ZeroTrustEngine>,
}

impl ZeroTrustController {
    pub fn new(engine: Arc<dyn ZeroTrustEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_get_tunnel(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_tunnel_status()))
    }

    pub fn handle_get_apps(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_ztna_apps()))
    }

    pub fn handle_add_app(&self, app: ZtnaAppPublish) -> Response {
        match self.engine.publish_ztna_app(app) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_delete_app(&self, id: &str) -> Response {
        match self.engine.delete_ztna_app(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_jwt(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_jwt_validator()))
    }

    pub fn handle_set_jwt(&self, config: EdgeJwtValidator) -> Response {
        match self.engine.set_jwt_validator(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_doh(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_doh_config()))
    }

    pub fn handle_set_doh(&self, config: DohConfig) -> Response {
        match self.engine.set_doh_config(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }
}
