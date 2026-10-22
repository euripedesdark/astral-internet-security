use crate::domain::{FirewallError, FirewallRule};
use std::process::Command;
use tracing::{error, info};

pub trait PacketFilterBackend: Send + Sync {
    fn apply_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;
    fn remove_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;
    fn apply_panic(&self, enabled: bool) -> Result<(), FirewallError>;
}

pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self {
        Self
    }
}

impl PacketFilterBackend for IptablesBackend {
    fn apply_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let chain = match rule.direction.as_str() {
            "OUT" => "OUTPUT",
            "FORWARD" => "FORWARD",
            _ => "INPUT",
        };

        let mut cmd = Command::new("iptables");
        cmd.args(["-A", chain]);

        if !rule.protocol.is_empty() && rule.protocol != "ALL" {
            cmd.args(["-p", &rule.protocol.to_lowercase()]);
            if !rule.port.is_empty() && rule.port != "ANY" {
                cmd.args(["--dport", &rule.port]);
            }
        }

        if let Some(ref src) = rule.source_ip {
            if !src.is_empty() && src != "0.0.0.0/0" {
                cmd.args(["-s", src]);
            }
        }

        if let Some(ref dst) = rule.destination_ip {
            if !dst.is_empty() && dst != "0.0.0.0/0" {
                cmd.args(["-d", dst]);
            }
        }

        cmd.args(["-j", &rule.action]);

        let status = cmd.status().map_err(|e| FirewallError::BackendError(e.to_string()))?;
        if status.success() {
            info!("Applied iptables rule: {}", rule.name);
            Ok(())
        } else {
            Err(FirewallError::BackendError("iptables command exited with non-zero status".into()))
        }
    }

    fn remove_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let chain = match rule.direction.as_str() {
            "OUT" => "OUTPUT",
            "FORWARD" => "FORWARD",
            _ => "INPUT",
        };

        let mut cmd = Command::new("iptables");
        cmd.args(["-D", chain]);

        if !rule.protocol.is_empty() && rule.protocol != "ALL" {
            cmd.args(["-p", &rule.protocol.to_lowercase()]);
            if !rule.port.is_empty() && rule.port != "ANY" {
                cmd.args(["--dport", &rule.port]);
            }
        }

        cmd.args(["-j", &rule.action]);

        let _ = cmd.status();
        Ok(())
    }

    fn apply_panic(&self, enabled: bool) -> Result<(), FirewallError> {
        if enabled {
            info!("Activating PANIC MODE: Dropping all input packets");
            let _ = Command::new("iptables").args(["-P", "INPUT", "DROP"]).status();
            let _ = Command::new("iptables").args(["-P", "FORWARD", "DROP"]).status();
        } else {
            info!("Deactivating PANIC MODE: Restoring default ACCEPT");
            let _ = Command::new("iptables").args(["-P", "INPUT", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-P", "FORWARD", "ACCEPT"]).status();
        }
        Ok(())
    }
}
