use crate::domain::{AlgConfig, FirewallError, NatRule, NatType};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
struct PersistedNatData {
    rules: Vec<NatRule>,
    alg: Option<AlgConfig>,
}

pub trait NatEngine: Send + Sync {
    fn get_rules(&self) -> Vec<NatRule>;
    fn add_rule(&self, rule: NatRule) -> Result<NatRule, FirewallError>;
    fn delete_rule(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_alg_config(&self) -> AlgConfig;
    fn set_alg_config(&self, config: AlgConfig) -> Result<AlgConfig, FirewallError>;
}

pub struct StatefulNatEngine {
    storage_path: PathBuf,
    rules: Mutex<Vec<NatRule>>,
    alg: Mutex<AlgConfig>,
}

impl StatefulNatEngine {
    pub fn new(storage_path: PathBuf) -> Self {
        let (rules, alg) = Self::load_from_disk(&storage_path);
        Self {
            storage_path,
            rules: Mutex::new(rules),
            alg: Mutex::new(alg),
        }
    }

    fn load_from_disk(path: &PathBuf) -> (Vec<NatRule>, AlgConfig) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedNatData>(&content) {
                let alg = data.alg.unwrap_or(AlgConfig {
                    sip_enabled: false,
                    ftp_enabled: true,
                    pptp_enabled: false,
                    tftp_enabled: false,
                });
                return (data.rules, alg);
            }
        }

        let default_rules = vec![
            NatRule {
                id: "nat-masq-wan0".into(),
                name: "Default LAN Masquerade".into(),
                nat_type: NatType::SnatMasquerade,
                original_ip: Some("192.168.0.0/16".into()),
                original_port: "ANY".into(),
                destination_ip: "0.0.0.0/0".into(),
                destination_port: "ANY".into(),
                interface: "wan0".into(),
                protocol: "ALL".into(),
                enabled: true,
            },
        ];

        let default_alg = AlgConfig {
            sip_enabled: false,
            ftp_enabled: true,
            pptp_enabled: false,
            tftp_enabled: false,
        };

        (default_rules, default_alg)
    }

    fn persist(&self) {
        let data = PersistedNatData {
            rules: self.rules.lock().unwrap().clone(),
            alg: Some(self.alg.lock().unwrap().clone()),
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&data) {
            if let Some(parent) = self.storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.storage_path, serialized);
        }
    }
}

impl NatEngine for StatefulNatEngine {
    fn get_rules(&self) -> Vec<NatRule> {
        self.rules.lock().unwrap().clone()
    }

    fn add_rule(&self, mut rule: NatRule) -> Result<NatRule, FirewallError> {
        if rule.id.is_empty() {
            rule.id = Uuid::new_v4().to_string();
        }
        self.rules.lock().unwrap().push(rule.clone());
        self.persist();
        info!("Registered NAT rule: {} ({:?})", rule.name, rule.nat_type);
        Ok(rule)
    }

    fn delete_rule(&self, id: &str) -> Result<bool, FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(pos) = rules.iter().position(|r| r.id == id) {
            rules.remove(pos);
            drop(rules);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::RuleNotFound(id.to_string()))
        }
    }

    fn get_alg_config(&self) -> AlgConfig {
        self.alg.lock().unwrap().clone()
    }

    fn set_alg_config(&self, config: AlgConfig) -> Result<AlgConfig, FirewallError> {
        *self.alg.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated Application Layer Gateway (ALG) helpers: SIP={}, FTP={}", config.sip_enabled, config.ftp_enabled);
        Ok(config)
    }
}
