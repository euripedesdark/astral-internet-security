use crate::domain::{
    DnsSinkholeConfig, EgressFilterConfig, FirewallError, MultiWanConfig, MultiWanSetupRequest,
    NetworkInterfaceInfo, PbrRule, QosConfig, WanLink, WifiHotspotConfig, WifiRouterStatus,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
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

    // Interface Detection, Multi-WAN (1-10) e Roteador Wi-Fi
    fn get_system_interfaces(&self) -> Vec<NetworkInterfaceInfo>;
    fn apply_multi_wan_setup(&self, req: MultiWanSetupRequest) -> Result<Vec<WanLink>, FirewallError>;
    fn get_wifi_status(&self) -> WifiRouterStatus;
    fn start_wifi_hotspot(&self, config: WifiHotspotConfig) -> Result<WifiRouterStatus, FirewallError>;
    fn stop_wifi_hotspot(&self) -> Result<WifiRouterStatus, FirewallError>;
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
                interface: "enp0s20u2".into(),
                gateway_ip: "192.168.2.1".into(),
                weight: 100,
                is_primary: true,
                is_active: true,
                latency_ms: 8.4,
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

    fn get_system_interfaces(&self) -> Vec<NetworkInterfaceInfo> {
        let mut list = Vec::new();
        if let Ok(output) = Command::new("ip").args(["-j", "addr", "show"]).output() {
            if let Ok(json_str) = String::from_utf8(output.stdout) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    if let Some(arr) = val.as_array() {
                        for item in arr {
                            let name = item["ifname"].as_str().unwrap_or("").to_string();
                            if name == "lo" {
                                continue;
                            }
                            let mac = item["address"].as_str().map(|s| s.to_string());
                            let operstate = item["operstate"].as_str().unwrap_or("DOWN");
                            let is_up = operstate == "UP" || item["flags"].as_array().map_or(false, |f| f.iter().any(|v| v.as_str() == Some("UP")));
                            let link_type = item["link_type"].as_str().unwrap_or("ether").to_string();

                            let is_wireless = std::path::Path::new(&format!("/sys/class/net/{}/wireless", name)).exists()
                                || std::path::Path::new(&format!("/sys/class/net/{}/phy80211", name)).exists()
                                || name.starts_with("wl");

                            let mut ip = None;
                            let mut netmask = None;
                            let mut has_ip = false;

                            if let Some(addrs) = item["addr_info"].as_array() {
                                for a in addrs {
                                    if a["family"].as_str() == Some("inet") {
                                        if let Some(local_ip) = a["local"].as_str() {
                                            ip = Some(local_ip.to_string());
                                            has_ip = true;
                                            if let Some(prefix) = a["prefixlen"].as_u64() {
                                                netmask = Some(format!("/{}", prefix));
                                            }
                                            break;
                                        }
                                    }
                                }
                            }

                            let suggested_role = if ip.as_deref() == Some("192.168.2.10") || name == "enp0s20u2" {
                                "WAN".to_string()
                            } else if is_wireless {
                                "WIFI".to_string()
                            } else if ip.as_deref() == Some("192.168.1.1") || name == "enp3s0f1" {
                                "LAN".to_string()
                            } else if name.starts_with("tailscale") {
                                "VPN".to_string()
                            } else {
                                "OTHER".to_string()
                            };

                            list.push(NetworkInterfaceInfo {
                                name,
                                ip,
                                netmask,
                                mac,
                                is_up,
                                is_wireless,
                                has_ip,
                                link_type,
                                suggested_role,
                            });
                        }
                    }
                }
            }
        }
        list
    }

    fn apply_multi_wan_setup(&self, req: MultiWanSetupRequest) -> Result<Vec<WanLink>, FirewallError> {
        if req.wan_count < 1 || req.wan_count > 10 {
            return Err(FirewallError::InvalidRule("O número de interfaces WAN deve ser entre 1 e 10.".into()));
        }

        info!("Applying Multi-WAN setup: count={}, mode={}", req.wan_count, req.mode);

        let mut current_links = self.wan_links.lock().unwrap();
        let old_interfaces: Vec<String> = current_links.iter().map(|l| l.interface.clone()).collect();

        let mut new_links = Vec::new();
        let mut reconfigured_any = false;

        for (idx, setup_link) in req.links.into_iter().take(req.wan_count).enumerate() {
            let iface = setup_link.interface.clone();
            let action = setup_link.action.to_lowercase();

            if action == "reconfigure" {
                reconfigured_any = true;
                info!("Reconfiguring WAN link for interface {}", iface);
            }

            let link_id = if setup_link.id.is_empty() { format!("wan-{}", idx + 1) } else { setup_link.id };
            let link_name = if setup_link.name.is_empty() { format!("WAN {} ({})", idx + 1, iface) } else { setup_link.name };

            let link = WanLink {
                id: link_id,
                name: link_name,
                interface: iface,
                gateway_ip: setup_link.gateway.unwrap_or_else(|| "192.168.2.1".into()),
                weight: if setup_link.weight == 0 { 100 } else { setup_link.weight },
                is_primary: setup_link.is_primary || idx == 0,
                is_active: true,
                latency_ms: 10.0,
                packet_loss_pct: 0.0,
            };
            new_links.push(link);
        }

        // Se reconfigurado, remove o masquerade (e somente ele) e aplica de novo, mas nada de limpar config das portas.
        if reconfigured_any {
            info!("Reconfiguring MASQUERADE in iptables NAT table without touching port forwarding or filter tables...");
            for old_if in &old_interfaces {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-D", "POSTROUTING", "-o", old_if, "-j", "MASQUERADE"])
                    .status();
            }
            for nl in &new_links {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-A", "POSTROUTING", "-o", &nl.interface, "-j", "MASQUERADE"])
                    .status();
            }
            let _ = Command::new("sh")
                .args(["-c", "iptables-save > /etc/sysconfig/iptables 2>/dev/null || true"])
                .status();
        }

        let mut mw = self.multi_wan.lock().unwrap();
        mw.mode = req.mode;

        *current_links = new_links.clone();
        drop(current_links);
        drop(mw);

        self.persist();
        Ok(new_links)
    }

    fn get_wifi_status(&self) -> WifiRouterStatus {
        let ifaces = self.get_system_interfaces();
        let wifi_iface = ifaces.into_iter().find(|i| i.is_wireless);

        let Some(wifi) = wifi_iface else {
            return WifiRouterStatus {
                has_wifi: false,
                interface_name: None,
                is_active: false,
                ssid: None,
                channel: None,
                band: None,
                ip_gateway: None,
                clients_count: 0,
                mode_supported: vec![],
            };
        };

        let mut is_active = false;
        let mut ssid = None;
        let mut ip_gateway = wifi.ip.clone();

        if let Ok(out) = Command::new("nmcli").args(["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split(":").collect();
                if parts.len() >= 3 && parts[1].contains("wifi") && parts[2] == wifi.name {
                    is_active = true;
                    ssid = Some(parts[0].to_string());
                    break;
                }
            }
        }

        if is_active && ip_gateway.is_none() {
            ip_gateway = Some("10.42.0.1".into());
        }

        let mut clients_count = 0;
        if is_active {
            if let Ok(out) = Command::new("iw").args(["dev", &wifi.name, "station", "dump"]).output() {
                let s = String::from_utf8_lossy(&out.stdout);
                clients_count = s.lines().filter(|l| l.starts_with("Station ")).count() as u32;
            }
        }

        WifiRouterStatus {
            has_wifi: true,
            interface_name: Some(wifi.name),
            is_active,
            ssid: ssid.or_else(|| Some("Astral-WiFi-Hotspot".into())),
            channel: Some(6),
            band: Some("bg (2.4GHz)".into()),
            ip_gateway: ip_gateway.or_else(|| Some("10.42.0.1".into())),
            clients_count,
            mode_supported: vec!["AP (Ponto de Acesso)".into(), "Managed (Cliente)".into(), "P2P".into()],
        }
    }

    fn start_wifi_hotspot(&self, config: WifiHotspotConfig) -> Result<WifiRouterStatus, FirewallError> {
        let iface = config.interface_name;
        let ssid = config.ssid;
        let password = config.password.unwrap_or_else(|| "astral12345".into());
        let band = if config.band.is_empty() { "bg".to_string() } else { config.band };
        let wan_if = config.wan_interface.unwrap_or_else(|| "enp0s20u2".into());

        info!("Starting Wi-Fi Hotspot Router on interface {} with SSID: {}", iface, ssid);

        let _ = Command::new("nmcli").args(["connection", "delete", "Astral-WiFi-Hotspot"]).output();

        let mut create_cmd = Command::new("nmcli");
        create_cmd.args([
            "con", "add", "type", "wifi",
            "ifname", &iface,
            "con-name", "Astral-WiFi-Hotspot",
            "autoconnect", "yes",
            "ssid", &ssid,
            "802-11-wireless.mode", "ap",
            "802-11-wireless.band", &band,
            "ipv4.method", "shared",
            "wifi-sec.key-mgmt", "wpa-psk",
            "wifi-sec.psk", &password,
        ]);

        let create_out = create_cmd.output().map_err(|e| FirewallError::BackendError(format!("Falha ao criar conexão hotspot: {}", e)))?;
        if !create_out.status.success() {
            let err = String::from_utf8_lossy(&create_out.stderr);
            return Err(FirewallError::BackendError(format!("Erro ao configurar hotspot nmcli: {}", err)));
        }

        let up_out = Command::new("nmcli").args(["con", "up", "Astral-WiFi-Hotspot"]).output()
            .map_err(|e| FirewallError::BackendError(format!("Falha ao ativar hotspot: {}", e)))?;

        if !up_out.status.success() {
            let err = String::from_utf8_lossy(&up_out.stderr);
            return Err(FirewallError::BackendError(format!("Erro ao ativar hotspot: {}", err)));
        }

        if config.enable_nat_routing {
            let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", &iface, "-o", &wan_if, "-j", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", &wan_if, "-o", &iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).status();
            let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-o", &wan_if, "-j", "MASQUERADE"]).status();
            let _ = Command::new("sh").args(["-c", "iptables-save > /etc/sysconfig/iptables 2>/dev/null || true"]).status();
        }

        Ok(self.get_wifi_status())
    }

    fn stop_wifi_hotspot(&self) -> Result<WifiRouterStatus, FirewallError> {
        info!("Stopping Wi-Fi Hotspot Router...");
        let _ = Command::new("nmcli").args(["con", "down", "Astral-WiFi-Hotspot"]).output();
        Ok(self.get_wifi_status())
    }
}
