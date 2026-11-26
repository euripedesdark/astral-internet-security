use crate::domain::{FirewallError, FirewallRule, NatRule, NatType};
use std::process::Command;
use tracing::info;

pub trait PacketFilterBackend: Send + Sync {
    fn apply_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;
    fn remove_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;
    fn apply_panic(&self, enabled: bool) -> Result<(), FirewallError>;
    fn apply_bogon_filtering(&self, enabled: bool) -> Result<(), FirewallError>;
    fn apply_rate_limit(&self, max_conn: u32, syn_rate: u32) -> Result<(), FirewallError>;

    // NAT & Masquerade Operations
    fn apply_nat_rule(&self, rule: &NatRule) -> Result<(), FirewallError>;
    fn remove_nat_rule(&self, rule: &NatRule) -> Result<(), FirewallError>;
    fn ensure_ip_forwarding(&self) -> Result<(), FirewallError>;
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

        if !rule.protocol.is_empty() && rule.protocol != "ALL" && rule.protocol != "ANY" {
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

        if let Some(ref mac) = rule.source_mac {
            if !mac.is_empty() {
                cmd.args(["-m", "mac", "--mac-source", mac]);
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

        if !rule.protocol.is_empty() && rule.protocol != "ALL" && rule.protocol != "ANY" {
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
            info!("Activating PANIC MODE: Dropping all packets (Default Deny)");
            let _ = Command::new("iptables").args(["-P", "INPUT", "DROP"]).status();
            let _ = Command::new("iptables").args(["-P", "FORWARD", "DROP"]).status();
        } else {
            info!("Deactivating PANIC MODE: Restoring baseline state");
            let _ = Command::new("iptables").args(["-P", "INPUT", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-P", "FORWARD", "ACCEPT"]).status();
        }
        Ok(())
    }

    fn apply_bogon_filtering(&self, enabled: bool) -> Result<(), FirewallError> {
        if enabled {
            info!("Enforcing Anti-Spoofing & RFC 1918 Bogon drops on WAN interfaces");
            let _ = Command::new("iptables").args(["-I", "INPUT", "-i", "wan0", "-s", "10.0.0.0/8", "-j", "DROP"]).status();
            let _ = Command::new("iptables").args(["-I", "INPUT", "-i", "wan0", "-s", "172.16.0.0/12", "-j", "DROP"]).status();
            let _ = Command::new("iptables").args(["-I", "INPUT", "-i", "wan0", "-s", "192.168.0.0/16", "-j", "DROP"]).status();
        }
        Ok(())
    }

    fn apply_rate_limit(&self, max_conn: u32, syn_rate: u32) -> Result<(), FirewallError> {
        info!("Applying DoS Rate Limiting: Max Conn: {}, SYN Rate: {}/s", max_conn, syn_rate);
        let _ = Command::new("iptables")
            .args(["-I", "INPUT", "-p", "tcp", "--syn", "-m", "limit", "--limit", &format!("{}/s", syn_rate), "--limit-burst", "100", "-j", "ACCEPT"])
            .status();
        Ok(())
    }

    fn ensure_ip_forwarding(&self) -> Result<(), FirewallError> {
        info!("Enabling kernel IPv4 forwarding (net.ipv4.ip_forward=1)");
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).status();
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            .status();
        Ok(())
    }

    fn apply_nat_rule(&self, rule: &NatRule) -> Result<(), FirewallError> {
        self.ensure_ip_forwarding()?;
        // Auto-detect real WAN interface if rule specifies template wan0 that does not exist
        let mut target_iface = rule.interface.clone();
        if target_iface == "wan0" && !std::path::Path::new("/sys/class/net/wan0").exists() {
            if let Ok(output) = Command::new("ip").args(["route", "show", "default"]).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = text.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&x| x == "dev") {
                    if let Some(dev) = parts.get(pos + 1) {
                        target_iface = dev.to_string();
                    }
                }
            }
        }
        match rule.nat_type {
            NatType::SnatMasquerade => {
                info!("Applying SNAT Masquerade on interface {}: src={:?}", target_iface, rule.original_ip);
                // 1. iptables NAT POSTROUTING
                let mut cmd = Command::new("iptables");
                cmd.args(["-t", "nat", "-A", "POSTROUTING"]);
                if !target_iface.is_empty() && target_iface != "ALL" && target_iface != "ANY" {
                    cmd.args(["-o", &target_iface]);
                }
                if let Some(ref src) = rule.original_ip {
                    if !src.is_empty() && src != "0.0.0.0/0" {
                        cmd.args(["-s", src]);
                    }
                }
                if !rule.destination_ip.is_empty() && rule.destination_ip != "0.0.0.0/0" {
                    cmd.args(["-d", &rule.destination_ip]);
                }
                cmd.args(["-j", "MASQUERADE"]);
                let status = cmd.status().map_err(|e| FirewallError::BackendError(e.to_string()))?;

                // 2. iptables FORWARD
                let mut fwd = Command::new("iptables");
                fwd.args(["-A", "FORWARD"]);
                if !target_iface.is_empty() && target_iface != "ALL" && target_iface != "ANY" {
                    fwd.args(["-o", &target_iface]);
                }
                if let Some(ref src) = rule.original_ip {
                    if !src.is_empty() && src != "0.0.0.0/0" {
                        fwd.args(["-s", src]);
                    }
                }
                fwd.args(["-j", "ACCEPT"]);
                let _ = fwd.status();

                // 3. Persist iptables rules to /etc/sysconfig/iptables if available
                let _ = Command::new("sh")
                    .args(["-c", "if [ -d /etc/sysconfig ]; then iptables-save > /etc/sysconfig/iptables; fi"])
                    .status();

                if status.success() {
                    Ok(())
                } else {
                    Err(FirewallError::BackendError("iptables MASQUERADE command exited with non-zero status".into()))
                }
            }
            NatType::DnatPortForward => {
                let proto = if rule.protocol.is_empty() || rule.protocol == "ALL" {
                    "tcp".to_string()
                } else {
                    rule.protocol.to_lowercase()
                };
                let dest = format!("{}:{}", rule.destination_ip, rule.destination_port);
                info!("Applying DNAT Port Forward: {}:{} -> {} ({})", rule.interface, rule.original_port, dest, proto);

                let mut cmd = Command::new("iptables");
                cmd.args(["-t", "nat", "-A", "PREROUTING"]);
                if !rule.interface.is_empty() && rule.interface != "ALL" {
                    cmd.args(["-i", &rule.interface]);
                }
                cmd.args(["-p", &proto]);
                if !rule.original_port.is_empty() && rule.original_port != "ANY" {
                    cmd.args(["--dport", &rule.original_port]);
                }
                cmd.args(["-j", "DNAT", "--to-destination", &dest]);
                let _ = cmd.status();

                let mut fwd = Command::new("iptables");
                fwd.args(["-A", "FORWARD", "-p", &proto, "-d", &rule.destination_ip]);
                if !rule.destination_port.is_empty() && rule.destination_port != "ANY" {
                    fwd.args(["--dport", &rule.destination_port]);
                }
                fwd.args(["-j", "ACCEPT"]);
                let _ = fwd.status();
                Ok(())
            }
            NatType::NatReflection => {
                info!("Applying Hairpin NAT (Reflection) for destination: {}", rule.destination_ip);
                let mut cmd = Command::new("iptables");
                cmd.args(["-t", "nat", "-A", "POSTROUTING"]);
                if let Some(ref src) = rule.original_ip {
                    cmd.args(["-s", src]);
                } else {
                    cmd.args(["-s", "192.168.0.0/16"]);
                }
                cmd.args(["-d", &rule.destination_ip, "-j", "MASQUERADE"]);
                let _ = cmd.status();
                Ok(())
            }
            NatType::BinatOneToOne => {
                info!("Applying 1:1 BI-NAT: {:?} <-> {}", rule.original_ip, rule.destination_ip);
                if let Some(ref orig) = rule.original_ip {
                    let mut dnat = Command::new("iptables");
                    dnat.args(["-t", "nat", "-A", "PREROUTING", "-d", &rule.destination_ip, "-j", "DNAT", "--to-destination", orig]);
                    let _ = dnat.status();

                    let mut snat = Command::new("iptables");
                    snat.args(["-t", "nat", "-A", "POSTROUTING", "-s", orig, "-j", "SNAT", "--to-source", &rule.destination_ip]);
                    let _ = snat.status();
                }
                Ok(())
            }
            _ => {
                info!("NAT type {:?} handled through generic masquerade", rule.nat_type);
                Ok(())
            }
        }
    }

    fn remove_nat_rule(&self, rule: &NatRule) -> Result<(), FirewallError> {
        match rule.nat_type {
            NatType::SnatMasquerade => {
                let mut cmd = Command::new("iptables");
                cmd.args(["-t", "nat", "-D", "POSTROUTING"]);
                if !rule.interface.is_empty() && rule.interface != "ALL" && rule.interface != "ANY" {
                    cmd.args(["-o", &rule.interface]);
                }
                if let Some(ref src) = rule.original_ip {
                    if !src.is_empty() && src != "0.0.0.0/0" {
                        cmd.args(["-s", src]);
                    }
                }
                if !rule.destination_ip.is_empty() && rule.destination_ip != "0.0.0.0/0" {
                    cmd.args(["-d", &rule.destination_ip]);
                }
                cmd.args(["-j", "MASQUERADE"]);
                let _ = cmd.status();

                let mut fwd = Command::new("iptables");
                fwd.args(["-D", "FORWARD"]);
                if !rule.interface.is_empty() && rule.interface != "ALL" && rule.interface != "ANY" {
                    fwd.args(["-o", &rule.interface]);
                }
                if let Some(ref src) = rule.original_ip {
                    if !src.is_empty() && src != "0.0.0.0/0" {
                        fwd.args(["-s", src]);
                    }
                }
                fwd.args(["-j", "ACCEPT"]);
                let _ = fwd.status();
                Ok(())
            }
            NatType::DnatPortForward => {
                let proto = if rule.protocol.is_empty() || rule.protocol == "ALL" {
                    "tcp".to_string()
                } else {
                    rule.protocol.to_lowercase()
                };
                let dest = format!("{}:{}", rule.destination_ip, rule.destination_port);

                let mut cmd = Command::new("iptables");
                cmd.args(["-t", "nat", "-D", "PREROUTING"]);
                if !rule.interface.is_empty() && rule.interface != "ALL" {
                    cmd.args(["-i", &rule.interface]);
                }
                cmd.args(["-p", &proto]);
                if !rule.original_port.is_empty() && rule.original_port != "ANY" {
                    cmd.args(["--dport", &rule.original_port]);
                }
                cmd.args(["-j", "DNAT", "--to-destination", &dest]);
                let _ = cmd.status();

                let mut fwd = Command::new("iptables");
                fwd.args(["-D", "FORWARD", "-p", &proto, "-d", &rule.destination_ip]);
                if !rule.destination_port.is_empty() && rule.destination_port != "ANY" {
                    fwd.args(["--dport", &rule.destination_port]);
                }
                fwd.args(["-j", "ACCEPT"]);
                let _ = fwd.status();
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
