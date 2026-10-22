use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct FirewallConfig {
    pub port: u16,
    pub storage_dir: PathBuf,
}

impl FirewallConfig {
    pub fn load() -> Self {
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8084);

        let storage_dir = PathBuf::from("/etc/astral");

        Self {
            port,
            storage_dir,
        }
    }

    pub fn firewall_path(&self) -> PathBuf {
        self.storage_dir.join("firewall.json")
    }

    pub fn nat_path(&self) -> PathBuf {
        self.storage_dir.join("nat.json")
    }

    pub fn gateway_path(&self) -> PathBuf {
        self.storage_dir.join("gateway.json")
    }

    pub fn zero_trust_path(&self) -> PathBuf {
        self.storage_dir.join("zero_trust.json")
    }

    pub fn vpn_path(&self) -> PathBuf {
        self.storage_dir.join("vpn.json")
    }

    pub fn antivirus_path(&self) -> PathBuf {
        self.storage_dir.join("antivirus.json")
    }

    pub fn compliance_path(&self) -> PathBuf {
        self.storage_dir.join("compliance.json")
    }
}
