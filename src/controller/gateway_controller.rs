use crate::domain::{
    DnsSinkholeConfig, EgressFilterConfig, MultiWanConfig, MultiWanSetupRequest, PbrRule,
    QosConfig, WanLink, WifiHotspotConfig,
};
use crate::service::GatewayEngine;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct GatewayController {
    engine: Arc<dyn GatewayEngine>,
}

impl GatewayController {
    pub fn new(engine: Arc<dyn GatewayEngine>) -> Self {
        Self { engine }
    }

    pub fn handle_get_wan_links(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_wan_links()))
    }

    pub fn handle_update_wan_link(&self, link: WanLink) -> Response {
        match self.engine.update_wan_link(link) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_multi_wan(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_multi_wan_config()))
    }

    pub fn handle_set_multi_wan(&self, config: MultiWanConfig) -> Response {
        match self.engine.set_multi_wan_config(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_pbr(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_pbr_rules()))
    }

    pub fn handle_add_pbr(&self, rule: PbrRule) -> Response {
        match self.engine.add_pbr_rule(rule) {
            Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_delete_pbr(&self, id: &str) -> Response {
        match self.engine.delete_pbr_rule(id) {
            Ok(_) => (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_sinkhole(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_dns_sinkhole()))
    }

    pub fn handle_set_sinkhole(&self, config: DnsSinkholeConfig) -> Response {
        match self.engine.set_dns_sinkhole(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_qos(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_qos_config()))
    }

    pub fn handle_set_qos(&self, config: QosConfig) -> Response {
        match self.engine.set_qos_config(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_egress(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_egress_filter()))
    }

    pub fn handle_set_egress(&self, config: EgressFilterConfig) -> Response {
        match self.engine.set_egress_filter(config) {
            Ok(res) => (StatusCode::OK, Json(res)).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    // NOVOS ENDPOINTS: Interfaces, Multi-WAN Setup e Wi-Fi Hotspot

    pub fn handle_get_interfaces(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_system_interfaces()))
    }

    pub fn handle_setup_multi_wan(&self, req: MultiWanSetupRequest) -> Response {
        match self.engine.apply_multi_wan_setup(req) {
            Ok(links) => (StatusCode::OK, Json(json!({"success": true, "links": links}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_get_wifi_status(&self) -> Json<serde_json::Value> {
        Json(json!(self.engine.get_wifi_status()))
    }

    pub fn handle_start_wifi_hotspot(&self, config: WifiHotspotConfig) -> Response {
        match self.engine.start_wifi_hotspot(config) {
            Ok(status) => (StatusCode::OK, Json(json!({"success": true, "wifi": status}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }

    pub fn handle_stop_wifi_hotspot(&self) -> Response {
        match self.engine.stop_wifi_hotspot() {
            Ok(status) => (StatusCode::OK, Json(json!({"success": true, "wifi": status}))).into_response(),
            Err(e) => e.to_json_response().into_response(),
        }
    }
}
