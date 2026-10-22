use crate::domain::{
    AliasObject, AntiSpoofingConfig, FirewallError, FirewallRule, FirewallState, GeoIpPolicy,
    InterfaceStat, NetworkZone, RateLimitConfig, ZoneType,
};
use crate::service::backend::PacketFilterBackend;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::info;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
struct PersistedFirewallData {
    rules: Vec<FirewallRule>,
    zones: Vec<NetworkZone>,
    aliases: Vec<AliasObject>,
    anti_spoofing: Option<AntiSpoofingConfig>,
    rate_limiting: Option<RateLimitConfig>,
    geoip_policies: Vec<GeoIpPolicy>,
    panic_mode: bool,
}

pub trait FirewallEngine: Send + Sync {
    fn get_state(&self) -> FirewallState;
    fn get_rules(&self) -> Vec<FirewallRule>;
    fn add_rule(&self, rule: FirewallRule) -> Result<FirewallRule, FirewallError>;
    fn delete_rule(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_zones(&self) -> Vec<NetworkZone>;
    fn add_zone(&self, zone: NetworkZone) -> Result<NetworkZone, FirewallError>;
    fn get_aliases(&self) -> Vec<AliasObject>;
    fn add_alias(&self, alias: AliasObject) -> Result<AliasObject, FirewallError>;
    fn delete_alias(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_anti_spoofing(&self) -> AntiSpoofingConfig;
    fn set_anti_spoofing(&self, config: AntiSpoofingConfig) -> Result<AntiSpoofingConfig, FirewallError>;
    fn get_rate_limiting(&self) -> RateLimitConfig;
    fn set_rate_limiting(&self, config: RateLimitConfig) -> Result<RateLimitConfig, FirewallError>;
    fn get_geoip_policies(&self) -> Vec<GeoIpPolicy>;
    fn add_geoip_policy(&self, policy: GeoIpPolicy) -> Result<GeoIpPolicy, FirewallError>;
    fn delete_geoip_policy(&self, id: &str) -> Result<bool, FirewallError>;
    fn set_panic_mode(&self, enable: bool) -> Result<bool, FirewallError>;
    fn get_interface_stats(&self) -> Vec<InterfaceStat>;
}

pub struct StatefulFirewallEngine {
    backend: Arc<dyn PacketFilterBackend>,
    storage_path: PathBuf,
    rules: Mutex<Vec<FirewallRule>>,
    zones: Mutex<Vec<NetworkZone>>,
    aliases: Mutex<Vec<AliasObject>>,
    anti_spoofing: Mutex<AntiSpoofingConfig>,
    rate_limiting: Mutex<RateLimitConfig>,
    geoip_policies: Mutex<Vec<GeoIpPolicy>>,
    panic_mode: Mutex<bool>,
}

impl StatefulFirewallEngine {
    pub fn new(backend: Arc<dyn PacketFilterBackend>, storage_path: PathBuf) -> Self {
        let (rules, zones, aliases, anti_spoofing, rate_limiting, geoip_policies, panic_mode) =
            Self::load_from_disk(&storage_path);

        info!("Firewall Engine initialized with {} zones and {} rules", zones.len(), rules.len());

        Self {
            backend,
            storage_path,
            rules: Mutex::new(rules),
            zones: Mutex::new(zones),
            aliases: Mutex::new(aliases),
            anti_spoofing: Mutex::new(anti_spoofing),
            rate_limiting: Mutex::new(rate_limiting),
            geoip_policies: Mutex::new(geoip_policies),
            panic_mode: Mutex::new(panic_mode),
        }
    }

    fn load_from_disk(
        path: &PathBuf,
    ) -> (
        Vec<FirewallRule>,
        Vec<NetworkZone>,
        Vec<AliasObject>,
        AntiSpoofingConfig,
        RateLimitConfig,
        Vec<GeoIpPolicy>,
        bool,
    ) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedFirewallData>(&content) {
                let anti_spoofing = data.anti_spoofing.unwrap_or(AntiSpoofingConfig {
                    block_rfc1918_on_wan: true,
                    block_iana_unallocated: true,
                    enabled: true,
                });
                let rate_limiting = data.rate_limiting.unwrap_or(RateLimitConfig {
                    syn_flood_rate: 50,
                    icmp_flood_rate: 20,
                    udp_flood_rate: 100,
                    max_conn_per_ip: 500,
                    enabled: true,
                });

                let zones = if data.zones.is_empty() {
                    Self::default_zones()
                } else {
                    data.zones
                };

                return (
                    data.rules,
                    zones,
                    data.aliases,
                    anti_spoofing,
                    rate_limiting,
                    data.geoip_policies,
                    data.panic_mode,
                );
            }
        }

        (
            vec![],
            Self::default_zones(),
            Self::default_aliases(),
            AntiSpoofingConfig {
                block_rfc1918_on_wan: true,
                block_iana_unallocated: true,
                enabled: true,
            },
            RateLimitConfig {
                syn_flood_rate: 50,
                icmp_flood_rate: 20,
                udp_flood_rate: 100,
                max_conn_per_ip: 500,
                enabled: true,
            },
            vec![],
            false,
        )
    }

    fn default_zones() -> Vec<NetworkZone> {
        vec![
            NetworkZone {
                name: "WAN".into(),
                zone_type: ZoneType::WAN,
                interfaces: vec!["eth0".into(), "wan0".into()],
                default_policy: "DROP".into(),
                description: "Internet pública e operadoras (Default Deny)".into(),
            },
            NetworkZone {
                name: "LAN".into(),
                zone_type: ZoneType::LAN,
                interfaces: vec!["eth1".into(), "lan0".into()],
                default_policy: "ACCEPT".into(),
                description: "Rede local corporativa".into(),
            },
            NetworkZone {
                name: "DMZ".into(),
                zone_type: ZoneType::DMZ,
                interfaces: vec!["eth2".into(), "dmz0".into()],
                default_policy: "DROP".into(),
                description: "Servidores expostos e balanceadores".into(),
            },
            NetworkZone {
                name: "Guest".into(),
                zone_type: ZoneType::Guest,
                interfaces: vec!["guest0".into()],
                default_policy: "DROP".into(),
                description: "Rede isolada de visitantes".into(),
            },
            NetworkZone {
                name: "VPN_ZTNA".into(),
                zone_type: ZoneType::VpnZtna,
                interfaces: vec!["tun0".into(), "cloudflared".into()],
                default_policy: "ACCEPT".into(),
                description: "Túneis autenticados Zero Trust e OpenVPN".into(),
            },
        ]
    }

    fn default_aliases() -> Vec<AliasObject> {
        vec![
            AliasObject {
                id: "alias-web-ports".into(),
                name: "WEB_PORTS".into(),
                alias_type: "Port".into(),
                entries: vec!["80".into(), "443".into()],
                description: "Portas HTTP/HTTPS padrão".into(),
            },
            AliasObject {
                id: "alias-erp-ports".into(),
                name: "ERP_PORTS".into(),
                alias_type: "Port".into(),
                entries: vec!["8080".into(), "8084".into(), "8085".into(), "8091".into()],
                description: "Portas de serviços centrais Astral".into(),
            },
        ]
    }

    fn persist(&self) {
        let data = PersistedFirewallData {
            rules: self.rules.lock().unwrap().clone(),
            zones: self.zones.lock().unwrap().clone(),
            aliases: self.aliases.lock().unwrap().clone(),
            anti_spoofing: Some(self.anti_spoofing.lock().unwrap().clone()),
            rate_limiting: Some(self.rate_limiting.lock().unwrap().clone()),
            geoip_policies: self.geoip_policies.lock().unwrap().clone(),
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

        let (active_connections, conntrack_entries) = if let Ok(conntrack) = fs::read_to_string("/proc/net/nf_conntrack") {
            let count = conntrack.lines().count();
            (count, count)
        } else {
            (0, 0)
        };

        FirewallState {
            panic_mode,
            default_policy: "DROP".to_string(),
            rules_count,
            active_connections,
            conntrack_entries,
            last_synced: Utc::now().to_rfc3339(),
            spi_tracking_active: true,
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

    fn get_zones(&self) -> Vec<NetworkZone> {
        self.zones.lock().unwrap().clone()
    }

    fn add_zone(&self, zone: NetworkZone) -> Result<NetworkZone, FirewallError> {
        self.zones.lock().unwrap().push(zone.clone());
        self.persist();
        Ok(zone)
    }

    fn get_aliases(&self) -> Vec<AliasObject> {
        self.aliases.lock().unwrap().clone()
    }

    fn add_alias(&self, mut alias: AliasObject) -> Result<AliasObject, FirewallError> {
        if alias.id.is_empty() {
            alias.id = Uuid::new_v4().to_string();
        }
        self.aliases.lock().unwrap().push(alias.clone());
        self.persist();
        Ok(alias)
    }

    fn delete_alias(&self, id: &str) -> Result<bool, FirewallError> {
        let mut aliases = self.aliases.lock().unwrap();
        if let Some(pos) = aliases.iter().position(|a| a.id == id) {
            aliases.remove(pos);
            drop(aliases);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::NotFound(format!("Alias {} not found", id)))
        }
    }

    fn get_anti_spoofing(&self) -> AntiSpoofingConfig {
        self.anti_spoofing.lock().unwrap().clone()
    }

    fn set_anti_spoofing(&self, config: AntiSpoofingConfig) -> Result<AntiSpoofingConfig, FirewallError> {
        if config.enabled {
            self.backend.apply_bogon_filtering(true)?;
        }
        *self.anti_spoofing.lock().unwrap() = config.clone();
        self.persist();
        Ok(config)
    }

    fn get_rate_limiting(&self) -> RateLimitConfig {
        self.rate_limiting.lock().unwrap().clone()
    }

    fn set_rate_limiting(&self, config: RateLimitConfig) -> Result<RateLimitConfig, FirewallError> {
        if config.enabled {
            self.backend.apply_rate_limit(config.max_conn_per_ip, config.syn_flood_rate)?;
        }
        *self.rate_limiting.lock().unwrap() = config.clone();
        self.persist();
        Ok(config)
    }

    fn get_geoip_policies(&self) -> Vec<GeoIpPolicy> {
        self.geoip_policies.lock().unwrap().clone()
    }

    fn add_geoip_policy(&self, mut policy: GeoIpPolicy) -> Result<GeoIpPolicy, FirewallError> {
        if policy.id.is_empty() {
            policy.id = Uuid::new_v4().to_string();
        }
        self.geoip_policies.lock().unwrap().push(policy.clone());
        self.persist();
        Ok(policy)
    }

    fn delete_geoip_policy(&self, id: &str) -> Result<bool, FirewallError> {
        let mut policies = self.geoip_policies.lock().unwrap();
        if let Some(pos) = policies.iter().position(|p| p.id == id) {
            policies.remove(pos);
            drop(policies);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::NotFound(format!("GeoIP policy {} not found", id)))
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
