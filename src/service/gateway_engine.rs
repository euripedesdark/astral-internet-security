use crate::domain::{
    DnsSinkholeConfig, EgressFilterConfig, FirewallError, MultiWanConfig, PbrRule, QosConfig,
    WanLink,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
struct PersistedGatewayData {
    wan_links: Vec<WanLink>,
    multi_wan: Option<MultiWanConfig>,
    pbr_rules: Vec<PbrRule>,
    dns_sinkhole: Option<DnsSinkholeConfig>,
    qos: Option<QosConfig>,
    egress_filter: Option<EgressFilterConfig>,
}

pub trait GatewayEngine: Send + Sync {
    fn get_wan_links(&self) -> Vec<WanLink>;
    fn update_wan_link(&self, link: WanLink) -> Result<WanLink, FirewallError>;
    fn get_multi_wan_config(&self) -> MultiWanConfig;
    fn set_multi_wan_config(&self, config: MultiWanConfig) -> Result<MultiWanConfig, FirewallError>;
    fn get_pbr_rules(&self) -> Vec<PbrRule>;
    fn add_pbr_rule(&self, rule: PbrRule) -> Result<PbrRule, FirewallError>;
    fn delete_pbr_rule(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_dns_sinkhole(&self) -> DnsSinkholeConfig;
    fn set_dns_sinkhole(&self, config: DnsSinkholeConfig) -> Result<DnsSinkholeConfig, FirewallError>;
    fn get_qos_config(&self) -> QosConfig;
    fn set_qos_config(&self, config: QosConfig) -> Result<QosConfig, FirewallError>;
    fn get_egress_filter(&self) -> EgressFilterConfig;
    fn set_egress_filter(&self, config: EgressFilterConfig) -> Result<EgressFilterConfig, FirewallError>;
}

pub struct StatefulGatewayEngine {
    storage_path: PathBuf,
    wan_links: Mutex<Vec<WanLink>>,
    multi_wan: Mutex<MultiWanConfig>,
    pbr_rules: Mutex<Vec<PbrRule>>,
    dns_sinkhole: Mutex<DnsSinkholeConfig>,
    qos: Mutex<QosConfig>,
    egress_filter: Mutex<EgressFilterConfig>,
}

impl StatefulGatewayEngine {
    pub fn new(storage_path: PathBuf) -> Self {
        let (wan_links, multi_wan, pbr_rules, dns_sinkhole, qos, egress_filter) =
            Self::load_from_disk(&storage_path);

        Self {
            storage_path,
            wan_links: Mutex::new(wan_links),
            multi_wan: Mutex::new(multi_wan),
            pbr_rules: Mutex::new(pbr_rules),
            dns_sinkhole: Mutex::new(dns_sinkhole),
            qos: Mutex::new(qos),
            egress_filter: Mutex::new(egress_filter),
        }
    }

    fn load_from_disk(
        path: &PathBuf,
    ) -> (
        Vec<WanLink>,
        MultiWanConfig,
        Vec<PbrRule>,
        DnsSinkholeConfig,
        QosConfig,
        EgressFilterConfig,
    ) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedGatewayData>(&content) {
                let multi_wan = data.multi_wan.unwrap_or(MultiWanConfig {
                    mode: "Failover".into(),
                    sticky_connections: true,
                    probe_targets: vec!["1.1.1.1".into(), "8.8.8.8".into()],
                    check_interval_secs: 5,
                });
                let dns_sinkhole = data.dns_sinkhole.unwrap_or(DnsSinkholeConfig {
                    rpz_enabled: true,
                    block_c2: true,
                    block_phishing: true,
                    block_malware: true,
                    total_queries: 142050,
                    blocked_queries: 1842,
                });
                let qos = data.qos.unwrap_or(QosConfig {
                    algorithm: "FQ_CoDel".into(),
                    erp_priority: true,
                    voip_priority: true,
                    download_bandwidth_mbps: 500,
                    upload_bandwidth_mbps: 100,
                    enabled: true,
                });
                let egress_filter = data.egress_filter.unwrap_or(EgressFilterConfig {
                    default_deny_egress: true,
                    allowed_ports: vec![80, 443, 53, 123, 853],
                    enabled: true,
                });

                return (
                    data.wan_links,
                    multi_wan,
                    data.pbr_rules,
                    dns_sinkhole,
                    qos,
                    egress_filter,
                );
            }
        }

        let default_wan = vec![
            WanLink {
                id: "wan-primary".into(),
                name: "Link Fibra Primário (ISP 1)".into(),
                interface: "wan0".into(),
                gateway_ip: "192.168.1.1".into(),
                weight: 80,
                is_primary: true,
                is_active: true,
                latency_ms: 8.4,
                packet_loss_pct: 0.0,
            },
            WanLink {
                id: "wan-backup".into(),
                name: "Link Backup 5G / Dedicado (ISP 2)".into(),
                interface: "wan1".into(),
                gateway_ip: "10.10.0.1".into(),
                weight: 20,
                is_primary: false,
                is_active: true,
                latency_ms: 24.1,
                packet_loss_pct: 0.0,
            },
        ];

        let default_multi = MultiWanConfig {
            mode: "Failover".into(),
            sticky_connections: true,
            probe_targets: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            check_interval_secs: 5,
        };

        let default_sinkhole = DnsSinkholeConfig {
            rpz_enabled: true,
            block_c2: true,
            block_phishing: true,
            block_malware: true,
            total_queries: 142050,
            blocked_queries: 1842,
        };

        let default_qos = QosConfig {
            algorithm: "FQ_CoDel".into(),
            erp_priority: true,
            voip_priority: true,
            download_bandwidth_mbps: 500,
            upload_bandwidth_mbps: 100,
            enabled: true,
        };

        let default_egress = EgressFilterConfig {
            default_deny_egress: true,
            allowed_ports: vec![80, 443, 53, 123, 853],
            enabled: true,
        };

        (
            default_wan,
            default_multi,
            vec![],
            default_sinkhole,
            default_qos,
            default_egress,
        )
    }

    fn persist(&self) {
        let data = PersistedGatewayData {
            wan_links: self.wan_links.lock().unwrap().clone(),
            multi_wan: Some(self.multi_wan.lock().unwrap().clone()),
            pbr_rules: self.pbr_rules.lock().unwrap().clone(),
            dns_sinkhole: Some(self.dns_sinkhole.lock().unwrap().clone()),
            qos: Some(self.qos.lock().unwrap().clone()),
            egress_filter: Some(self.egress_filter.lock().unwrap().clone()),
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&data) {
            if let Some(parent) = self.storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.storage_path, serialized);
        }
    }
}

impl GatewayEngine for StatefulGatewayEngine {
    fn get_wan_links(&self) -> Vec<WanLink> {
        self.wan_links.lock().unwrap().clone()
    }

    fn update_wan_link(&self, link: WanLink) -> Result<WanLink, FirewallError> {
        let mut links = self.wan_links.lock().unwrap();
        if let Some(pos) = links.iter().position(|l| l.id == link.id) {
            links[pos] = link.clone();
            drop(links);
            self.persist();
            Ok(link)
        } else {
            links.push(link.clone());
            drop(links);
            self.persist();
            Ok(link)
        }
    }

    fn get_multi_wan_config(&self) -> MultiWanConfig {
        self.multi_wan.lock().unwrap().clone()
    }

    fn set_multi_wan_config(&self, config: MultiWanConfig) -> Result<MultiWanConfig, FirewallError> {
        *self.multi_wan.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated Multi-WAN configuration: mode={}", config.mode);
        Ok(config)
    }

    fn get_pbr_rules(&self) -> Vec<PbrRule> {
        self.pbr_rules.lock().unwrap().clone()
    }

    fn add_pbr_rule(&self, mut rule: PbrRule) -> Result<PbrRule, FirewallError> {
        if rule.id.is_empty() {
            rule.id = Uuid::new_v4().to_string();
        }
        self.pbr_rules.lock().unwrap().push(rule.clone());
        self.persist();
        Ok(rule)
    }

    fn delete_pbr_rule(&self, id: &str) -> Result<bool, FirewallError> {
        let mut rules = self.pbr_rules.lock().unwrap();
        if let Some(pos) = rules.iter().position(|r| r.id == id) {
            rules.remove(pos);
            drop(rules);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::NotFound(format!("PBR rule {} not found", id)))
        }
    }

    fn get_dns_sinkhole(&self) -> DnsSinkholeConfig {
        self.dns_sinkhole.lock().unwrap().clone()
    }

    fn set_dns_sinkhole(&self, config: DnsSinkholeConfig) -> Result<DnsSinkholeConfig, FirewallError> {
        *self.dns_sinkhole.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated DNS Sinkhole & RPZ filtering (C2={}, Malware={})", config.block_c2, config.block_malware);
        Ok(config)
    }

    fn get_qos_config(&self) -> QosConfig {
        self.qos.lock().unwrap().clone()
    }

    fn set_qos_config(&self, config: QosConfig) -> Result<QosConfig, FirewallError> {
        *self.qos.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated QoS Traffic Shaping ({})", config.algorithm);
        Ok(config)
    }

    fn get_egress_filter(&self) -> EgressFilterConfig {
        self.egress_filter.lock().unwrap().clone()
    }

    fn set_egress_filter(&self, config: EgressFilterConfig) -> Result<EgressFilterConfig, FirewallError> {
        *self.egress_filter.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated Egress Filtering (Default Deny={})", config.default_deny_egress);
        Ok(config)
    }
}
