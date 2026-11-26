use crate::domain::{AlgConfig, FirewallError, NatRule, NatType};
use crate::service::backend::PacketFilterBackend;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
    fn reconcile_all(&self);
}

pub struct StatefulNatEngine {
    backend: Arc<dyn PacketFilterBackend>,
    storage_path: PathBuf,
    rules: Mutex<Vec<NatRule>>,
    alg: Mutex<AlgConfig>,
}

impl StatefulNatEngine {
    pub fn new(backend: Arc<dyn PacketFilterBackend>, storage_path: PathBuf) -> Self {
        let (rules, alg) = Self::load_from_disk(&storage_path);
        let engine = Self {
            backend,
            storage_path,
            rules: Mutex::new(rules),
            alg: Mutex::new(alg),
        };
        engine.reconcile_all();
        engine
    }

    pub fn reconcile_all(&self) {
        let rules = self.rules.lock().unwrap().clone();
        info!("Reconciling {} NAT & Masquerade rules into the Linux kernel...", rules.len());
        for rule in &rules {
            if rule.enabled {
                if let Err(e) = self.backend.apply_nat_rule(rule) {
                    tracing::warn!("Failed to apply NAT rule {} to kernel: {:?}", rule.name, e);
                }
            }
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

        let detected_wan = if let Ok(output) = std::process::Command::new("ip").args(["route", "show", "default"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = text.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&x| x == "dev") {
                parts.get(pos + 1).map(|s| s.to_string()).unwrap_or_else(|| "wan0".into())
            } else {
                "wan0".into()
            }
        } else {
            "wan0".into()
        };

        let default_rules = vec![
            NatRule {
                id: format!("nat-masq-{}", detected_wan),
                name: "Default LAN Masquerade".into(),
                nat_type: NatType::SnatMasquerade,
                original_ip: Some("192.168.0.0/16".into()),
                original_port: "ANY".into(),
                destination_ip: "0.0.0.0/0".into(),
                destination_port: "ANY".into(),
                interface: detected_wan,
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
        let mut rules = self.rules.lock().unwrap().clone();
        for r in &mut rules {
            if r.interface == "wan0" && !std::path::Path::new("/sys/class/net/wan0").exists() {
                if let Ok(output) = std::process::Command::new("ip").args(["route", "show", "default"]).output() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if let Some(pos) = parts.iter().position(|&x| x == "dev") {
                        if let Some(real_iface) = parts.get(pos + 1) {
                            r.interface = real_iface.to_string();
                        }
                    }
                }
            }
        }
        rules
    }

    fn add_rule(&self, mut rule: NatRule) -> Result<NatRule, FirewallError> {
        if rule.id.is_empty() {
            rule.id = Uuid::new_v4().to_string();
        }
        if rule.enabled {
            let _ = self.backend.apply_nat_rule(&rule);
        }
        self.rules.lock().unwrap().push(rule.clone());
        self.persist();
        info!("Registered & applied NAT rule: {} ({:?})", rule.name, rule.nat_type);
        Ok(rule)
    }

    fn delete_rule(&self, id: &str) -> Result<bool, FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(pos) = rules.iter().position(|r| r.id == id) {
            let removed = rules.remove(pos);
            drop(rules);
            let _ = self.backend.remove_nat_rule(&removed);
            self.persist();
            info!("Deleted & removed NAT rule from kernel: {}", removed.name);
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

    fn reconcile_all(&self) {
        let rules = self.rules.lock().unwrap().clone();
        info!("Reconciling {} NAT & Masquerade rules into the Linux kernel...", rules.len());
        for rule in &rules {
            if rule.enabled {
                if let Err(e) = self.backend.apply_nat_rule(rule) {
                    tracing::warn!("Failed to apply NAT rule {} to kernel: {:?}", rule.name, e);
                }
            }
        }
    }
}
