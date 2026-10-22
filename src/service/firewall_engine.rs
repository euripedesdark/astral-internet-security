use crate::domain::{FirewallError, FirewallRule, FirewallState, InterfaceStat, NatRule};
use crate::service::backend::PacketFilterBackend;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
struct PersistedData {
    rules: Vec<FirewallRule>,
    nat_rules: Vec<NatRule>,
    panic_mode: bool,
}

pub trait FirewallEngine: Send + Sync {
    fn get_state(&self) -> FirewallState;
    fn get_rules(&self) -> Vec<FirewallRule>;
    fn add_rule(&self, rule: FirewallRule) -> Result<FirewallRule, FirewallError>;
    fn delete_rule(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_nat_rules(&self) -> Vec<NatRule>;
    fn add_nat_rule(&self, rule: NatRule) -> Result<NatRule, FirewallError>;
    fn delete_nat_rule(&self, id: &str) -> Result<bool, FirewallError>;
    fn set_panic_mode(&self, enable: bool) -> Result<bool, FirewallError>;
    fn get_interface_stats(&self) -> Vec<InterfaceStat>;
}

pub struct StatefulFirewallEngine {
    backend: Arc<dyn PacketFilterBackend>,
    storage_path: PathBuf,
    rules: Mutex<Vec<FirewallRule>>,
    nat_rules: Mutex<Vec<NatRule>>,
    panic_mode: Mutex<bool>,
}

impl StatefulFirewallEngine {
    pub fn new(backend: Arc<dyn PacketFilterBackend>, storage_path: PathBuf) -> Self {
        let (rules, nat_rules, panic_mode) = Self::load_from_disk(&storage_path);
        Self {
            backend,
            storage_path,
            rules: Mutex::new(rules),
            nat_rules: Mutex::new(nat_rules),
            panic_mode: Mutex::new(panic_mode),
        }
    }

    fn load_from_disk(path: &PathBuf) -> (Vec<FirewallRule>, Vec<NatRule>, bool) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedData>(&content) {
                info!("Loaded {} firewall rules and {} NAT rules from disk", data.rules.len(), data.nat_rules.len());
                return (data.rules, data.nat_rules, data.panic_mode);
            }
        }
        (vec![], vec![], false)
    }

    fn persist(&self) {
        let data = PersistedData {
            rules: self.rules.lock().unwrap().clone(),
            nat_rules: self.nat_rules.lock().unwrap().clone(),
            panic_mode: *self.panic_mode.lock().unwrap(),
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&data) {
            if let Some(parent) = self.storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.storage_path, serialized);
        }
    }
}

impl FirewallEngine for StatefulFirewallEngine {
    fn get_state(&self) -> FirewallState {
        let rules_count = self.rules.lock().unwrap().len();
        let panic_mode = *self.panic_mode.lock().unwrap();

        let active_connections = if let Ok(conntrack) = fs::read_to_string("/proc/net/nf_conntrack") {
            conntrack.lines().count()
        } else {
            0
        };

        FirewallState {
            panic_mode,
            default_policy: if panic_mode { "DROP".to_string() } else { "ACCEPT".to_string() },
            rules_count,
            active_connections,
            last_synced: Utc::now().to_rfc3339(),
        }
    }

    fn get_rules(&self) -> Vec<FirewallRule> {
        self.rules.lock().unwrap().clone()
    }

    fn add_rule(&self, mut rule: FirewallRule) -> Result<FirewallRule, FirewallError> {
        if rule.id.is_empty() {
            rule.id = Uuid::new_v4().to_string();
        }
        if rule.created_at.is_empty() {
            rule.created_at = Utc::now().to_rfc3339();
        }

        if rule.enabled {
            self.backend.apply_rule(&rule)?;
        }

        self.rules.lock().unwrap().push(rule.clone());
        self.persist();
        Ok(rule)
    }

    fn delete_rule(&self, id: &str) -> Result<bool, FirewallError> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(pos) = rules.iter().position(|r| r.id == id) {
            let removed = rules.remove(pos);
            if removed.enabled {
                let _ = self.backend.remove_rule(&removed);
            }
            drop(rules);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::RuleNotFound(id.to_string()))
        }
    }

    fn get_nat_rules(&self) -> Vec<NatRule> {
        self.nat_rules.lock().unwrap().clone()
    }

    fn add_nat_rule(&self, mut rule: NatRule) -> Result<NatRule, FirewallError> {
        if rule.id.is_empty() {
            rule.id = Uuid::new_v4().to_string();
        }
        self.nat_rules.lock().unwrap().push(rule.clone());
        self.persist();
        Ok(rule)
    }

    fn delete_nat_rule(&self, id: &str) -> Result<bool, FirewallError> {
        let mut nat_rules = self.nat_rules.lock().unwrap();
        if let Some(pos) = nat_rules.iter().position(|r| r.id == id) {
            nat_rules.remove(pos);
            drop(nat_rules);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::RuleNotFound(id.to_string()))
        }
    }

    fn set_panic_mode(&self, enable: bool) -> Result<bool, FirewallError> {
        self.backend.apply_panic(enable)?;
        *self.panic_mode.lock().unwrap() = enable;
        self.persist();
        Ok(enable)
    }

    fn get_interface_stats(&self) -> Vec<InterfaceStat> {
        let mut stats = Vec::new();
        if let Ok(dev_content) = fs::read_to_string("/proc/net/dev") {
            for line in dev_content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let iface = parts[0].trim_end_matches(':').to_string();
                    let rx_bytes = parts[1].parse().unwrap_or(0);
                    let tx_bytes = parts[9].parse().unwrap_or(0);
                    stats.push(InterfaceStat {
                        name: iface,
                        rx_bytes,
                        tx_bytes,
                    });
                }
            }
        }
        stats
    }
}
