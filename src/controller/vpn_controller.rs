use crate::domain::{ClientSpecificOverride, OpenVpnConfig};
use crate::service::VpnEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct IssueCertRequest {
    pub common_name: String,
    pub cert_type: String,
}

#[derive(Clone)]
pub struct VpnController {
    engine: Arc<dyn VpnEngine>,
}

impl VpnController {
    pub fn new(engine: Arc<dyn VpnEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_get_config(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_vpn_config()))
    }

    pub fn handle_set_config(&self, config: OpenVpnConfig) -> Response {
        match self.engine.set_vpn_config(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_certs(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_certificates()))
    }

    pub fn handle_issue_cert(&self, req: IssueCertRequest) -> Response {
        match self.engine.issue_certificate(&req.common_name, &req.cert_type) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_revoke_cert(&self, id: &str) -> Response {
        match self.engine.revoke_certificate(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"revoked": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_overrides(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_client_overrides()))
    }

    pub fn handle_set_override(&self, ccd: ClientSpecificOverride) -> Response {
        match self.engine.set_client_override(ccd) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_export_ovpn(&self, client_name: &str) -> Response {
        match self.engine.export_ovpn_profile(client_name) {
            Ok(profile) => (StatusCode::OK, Json(profile)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }
}
