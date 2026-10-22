use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct FirewallConfig {
    pub port: u16,
    pub storage_path: PathBuf,
}

impl FirewallConfig {
    pub fn load() -> Self {
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8084);

        let storage_path = PathBuf::from("/etc/astral/firewall.json");

        Self {
            port,
            storage_path,
        }
    }
}
