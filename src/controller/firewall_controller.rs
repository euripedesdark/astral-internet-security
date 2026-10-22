use crate::domain::{
    AliasObject, AntiSpoofingConfig, FirewallRule, GeoIpPolicy, NetworkZone, RateLimitConfig,
};
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

    pub fn handle_get_zones(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_zones()))
    }

    pub fn handle_add_zone(&self, zone: NetworkZone) -> Response {
        match self.engine.add_zone(zone) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_aliases(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_aliases()))
    }

    pub fn handle_add_alias(&self, alias: AliasObject) -> Response {
        match self.engine.add_alias(alias) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_delete_alias(&self, id: &str) -> Response {
        match self.engine.delete_alias(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_anti_spoofing(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_anti_spoofing()))
    }

    pub fn handle_set_anti_spoofing(&self, config: AntiSpoofingConfig) -> Response {
        match self.engine.set_anti_spoofing(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_rate_limiting(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_rate_limiting()))
    }

    pub fn handle_set_rate_limiting(&self, config: RateLimitConfig) -> Response {
        match self.engine.set_rate_limiting(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_geoip(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_geoip_policies()))
    }

    pub fn handle_add_geoip(&self, policy: GeoIpPolicy) -> Response {
        match self.engine.add_geoip_policy(policy) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_delete_geoip(&self, id: &str) -> Response {
        match self.engine.delete_geoip_policy(id) {
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
