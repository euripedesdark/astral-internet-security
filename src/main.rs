mod config;
mod controller;
mod domain;
mod server;
mod service;

use config::FirewallConfig;
use controller::FirewallController;
use server::FirewallServer;
use service::{IptablesBackend, StatefulFirewallEngine};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Initializing Astral Internet Security (Rust OOP Architecture)...");

    let config = Arc::new(FirewallConfig::load());
    let backend = Arc::new(IptablesBackend::new());
    let engine = Arc::new(StatefulFirewallEngine::new(backend, config.storage_path.clone()));
    let controller = Arc::new(FirewallController::new(engine));

    let server = FirewallServer::new(config, controller);
    server.run().await
}
