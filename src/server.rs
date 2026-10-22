use crate::config::FirewallConfig;
use crate::controller::{FirewallController, PanicRequest};
use crate::domain::{FirewallRule, NatRule};
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

pub struct FirewallServer {
    config: Arc<FirewallConfig>,
    controller: Arc<FirewallController>,
}

impl FirewallServer {
    pub fn new(config: Arc<FirewallConfig>, controller: Arc<FirewallController>) -> Self {
        Self { config, controller }
    }

    pub fn build_router(&self) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        Router::new()
            .route(
                "/health",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_health()
                }),
            )
            .route(
                "/actuator/health",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_health()
                }),
            )
            // Firewall State
            .route(
                "/api/firewall/state",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_state()
                }),
            )
            .route(
                "/api/v1/firewall/state",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_state()
                }),
            )
            // Rules
            .route(
                "/api/firewall/rules",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_get_rules()
                })
                .post(|State(ctrl): State<Arc<FirewallController>>, Json(rule): Json<FirewallRule>| async move {
                    ctrl.handle_add_rule(rule)
                }),
            )
            .route(
                "/api/v1/firewall/rules",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_get_rules()
                })
                .post(|State(ctrl): State<Arc<FirewallController>>, Json(rule): Json<FirewallRule>| async move {
                    ctrl.handle_add_rule(rule)
                }),
            )
            .route(
                "/api/firewall/rules/{id}",
                delete(|State(ctrl): State<Arc<FirewallController>>, Path(id): Path<String>| async move {
                    ctrl.handle_delete_rule(&id)
                }),
            )
            .route(
                "/api/v1/firewall/rules/{id}",
                delete(|State(ctrl): State<Arc<FirewallController>>, Path(id): Path<String>| async move {
                    ctrl.handle_delete_rule(&id)
                }),
            )
            // Panic Mode
            .route(
                "/api/firewall/panic",
                post(|State(ctrl): State<Arc<FirewallController>>, Json(req): Json<PanicRequest>| async move {
                    ctrl.handle_panic(req)
                }),
            )
            .route(
                "/api/v1/firewall/panic",
                post(|State(ctrl): State<Arc<FirewallController>>, Json(req): Json<PanicRequest>| async move {
                    ctrl.handle_panic(req)
                }),
            )
            // NAT
            .route(
                "/api/firewall/nat",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_get_nat()
                })
                .post(|State(ctrl): State<Arc<FirewallController>>, Json(rule): Json<NatRule>| async move {
                    ctrl.handle_add_nat(rule)
                }),
            )
            .route(
                "/api/v1/firewall/nat",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_get_nat()
                })
                .post(|State(ctrl): State<Arc<FirewallController>>, Json(rule): Json<NatRule>| async move {
                    ctrl.handle_add_nat(rule)
                }),
            )
            .route(
                "/api/firewall/nat/{id}",
                delete(|State(ctrl): State<Arc<FirewallController>>, Path(id): Path<String>| async move {
                    ctrl.handle_delete_nat(&id)
                }),
            )
            .route(
                "/api/v1/firewall/nat/{id}",
                delete(|State(ctrl): State<Arc<FirewallController>>, Path(id): Path<String>| async move {
                    ctrl.handle_delete_nat(&id)
                }),
            )
            // Stats
            .route(
                "/api/firewall/stats",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_stats()
                }),
            )
            .route(
                "/api/v1/firewall/stats",
                get(|State(ctrl): State<Arc<FirewallController>>| async move {
                    ctrl.handle_stats()
                }),
            )
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(self.controller.clone())
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));
        info!("Astral Internet Security listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let router = self.build_router();
        axum::serve(listener, router).await?;
        Ok(())
    }
}
