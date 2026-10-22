use serde::{Deserialize, Serialize};

fn default_nat_type() -> NatType {
    NatType::DnatPortForward
}
fn default_interface() -> String {
    "wan0".to_string()
}
fn default_true() -> bool {
    true
}
fn default_policy_drop() -> String {
    "DROP".to_string()
}

// ==============================================================================
// 1. MOTOR DE FIREWALL (SPI, ZONAS, REGRAS, RATE LIMITING, GEOIP)
// Alinhado à ISO 27001: A.8.20, A.8.21, A.8.22
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ZoneType {
    WAN,
    LAN,
    DMZ,
    Guest,
    VpnZtna,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NetworkZone {
    pub name: String,
    pub zone_type: ZoneType,
    pub interfaces: Vec<String>,
    #[serde(default = "default_policy_drop")]
    pub default_policy: String, // "DROP", "REJECT", "ACCEPT"
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TimeSchedule {
    pub id: String,
    pub name: String,
    pub days_of_week: Vec<u8>, // 1 = Monday .. 7 = Sunday
    pub start_time: String,    // "HH:MM"
    pub end_time: String,      // "HH:MM"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AliasObject {
    pub id: String,
    pub name: String,
    pub alias_type: String, // "Host", "Network", "Port", "Url"
    pub entries: Vec<String>,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub zone: String,
    pub protocol: String, // "TCP", "UDP", "ICMP", "ANY"
    pub port: String,
    pub action: String, // "ACCEPT", "DROP", "REJECT"
    pub direction: String, // "IN", "OUT", "FORWARD"
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub destination_ip: Option<String>,
    #[serde(default)]
    pub source_mac: Option<String>,
    #[serde(default)]
    pub schedule: Option<TimeSchedule>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AntiSpoofingConfig {
    pub block_rfc1918_on_wan: bool,
    pub block_iana_unallocated: bool,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    pub syn_flood_rate: u32,
    pub icmp_flood_rate: u32,
    pub udp_flood_rate: u32,
    pub max_conn_per_ip: u32,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GeoIpPolicy {
    pub id: String,
    pub country_code: String, // "CN", "RU", "US", etc.
    pub action: String,       // "ALLOW", "BLOCK"
    pub direction: String,    // "IN", "OUT"
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FirewallState {
    pub panic_mode: bool,
    pub default_policy: String, // "DROP"
    pub rules_count: usize,
    pub active_connections: usize,
    #[serde(default)]
    pub conntrack_entries: usize,
    pub last_synced: String,
    #[serde(default = "default_true")]
    pub spi_tracking_active: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceStat {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// ==============================================================================
// 2. MOTOR DE NAT (SNAT, DNAT, 1:1, REFLECTION, NPTv6, ALG)
// Alinhado à ISO 27001: A.8.20, A.8.22
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NatType {
    SnatMasquerade,
    DnatPortForward,
    BinatOneToOne,
    NatReflection,
    Nptv6Prefix,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NatRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_nat_type")]
    pub nat_type: NatType,
    #[serde(default)]
    pub original_ip: Option<String>,
    pub original_port: String,
    pub destination_ip: String,
    pub destination_port: String,
    #[serde(default = "default_interface")]
    pub interface: String,
    pub protocol: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AlgConfig {
    pub sip_enabled: bool,
    pub ftp_enabled: bool,
    pub pptp_enabled: bool,
    pub tftp_enabled: bool,
}

// ==============================================================================
// 3. GATEWAY DE ACESSO À INTERNET (MULTI-WAN, PBR, SINKHOLE, QOS, EGRESS)
// Alinhado à ISO 27001: A.8.14, A.8.23, A.8.6
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WanLink {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub gateway_ip: String,
    pub weight: u32,
    pub is_primary: bool,
    pub is_active: bool,
    pub latency_ms: f32,
    pub packet_loss_pct: f32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MultiWanConfig {
    pub mode: String, // "Failover", "LoadBalanceWeighted", "RoundRobin"
    pub sticky_connections: bool,
    pub probe_targets: Vec<String>, // e.g., ["1.1.1.1", "8.8.8.8"]
    pub check_interval_secs: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PbrRule {
    pub id: String,
    pub name: String,
    pub source_network: String,
    pub destination_port: Option<String>,
    pub protocol: String,
    pub target_gateway: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DnsSinkholeConfig {
    pub rpz_enabled: bool,
    pub block_c2: bool,
    pub block_phishing: bool,
    pub block_malware: bool,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QosConfig {
    pub algorithm: String, // "FQ_CoDel", "Cake"
    pub erp_priority: bool,
    pub voip_priority: bool,
    pub download_bandwidth_mbps: u32,
    pub upload_bandwidth_mbps: u32,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EgressFilterConfig {
    pub default_deny_egress: bool,
    pub allowed_ports: Vec<u16>, // e.g. [80, 443, 53]
    pub enabled: bool,
}

// ==============================================================================
// 4. INTEGRAÇÃO ZERO TRUST (CLOUDFLARE TUNNEL, ZTNA, WARP, JWT, DoH)
// Alinhado à ISO 27001: A.5.15, A.8.5, A.8.21
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareTunnelConfig {
    pub tunnel_id: String,
    pub tunnel_name: String,
    pub status: String, // "Connected", "Degraded", "Offline"
    pub active_connectors: u32,
    pub ingress_rules_count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ZtnaAppPublish {
    pub id: String,
    pub hostname: String,
    pub internal_service_url: String,
    pub require_mfa: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EdgeJwtValidator {
    pub enabled: bool,
    pub team_domain: String,
    pub audience_tag: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DohConfig {
    pub doh_url: String,
    pub dot_fallback: bool,
    pub enabled: bool,
}

// ==============================================================================
// 5. TÚNEL VPN COMPATÍVEL COM OPENVPN (PKI, DCO, AES-256-GCM, MFA, .OVPN)
// Alinhado à ISO 27001: A.8.24, A.6.7
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnConfig {
    pub mode: String, // "SiteToSite", "RoadWarrior"
    pub port: u16,
    pub protocol: String, // "UDP", "TCP"
    pub cipher: String,   // "AES-256-GCM", "CHACHA20-POLY1305"
    pub tls_version: String, // "1.3"
    pub dco_enabled: bool,
    pub split_tunnel: bool,
    pub subnet: String,
    pub mfa_required: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PkiCert {
    pub id: String,
    pub common_name: String,
    pub cert_type: String, // "CA", "Server", "Client"
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
    pub serial: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientSpecificOverride {
    pub client_name: String,
    pub assigned_ip: String,
    pub custom_routes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OvpnProfile {
    pub client_name: String,
    pub inline_profile: String,
}

// ==============================================================================
// 6. ANTIVÍRUS DE GATEWAY (CLAMAV, ICAP, QUARENTENA, LIMITES, BYPASS)
// Alinhado à ISO 27001: A.8.7
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClamAvStatus {
    pub clamd_active: bool,
    pub freshclam_last_update: String,
    pub signatures_total: u64,
    pub icap_bridge_active: bool,
    pub scanned_files_count: u64,
    pub threats_detected_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: String,
    pub file_name: String,
    pub threat_name: String,
    pub timestamp: String,
    pub file_size_bytes: u64,
    pub encrypted_path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DecompressionLimits {
    pub max_recursion: u32,
    pub max_stream_size_mb: u32,
    pub scan_timeout_seconds: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AntivirusBypass {
    pub bypass_media_streams: bool,
    pub bypass_signed_os_updates: bool,
}

// ==============================================================================
// 7. GOVERNANÇA, AUDITORIA E CONFORMIDADE ISO 27001
// A.8.15 (Logs e Imutabilidade), A.8.17 (NTP), A.8.2 (RBAC/MFA), A.8.32 (Rollback), A.8.13 (Backup)
// ==============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub operator: String,
    pub action: String,
    pub module: String,
    pub status: String, // "SUCCESS", "FAILURE", "BLOCKED"
    pub details: String,
    pub client_ip: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SyslogRemoteConfig {
    pub enabled: bool,
    pub server_host: String,
    pub server_port: u16,
    pub use_tls: bool,
    pub rfc5424_format: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NtpStatus {
    pub synchronized: bool,
    pub ntp_server: String,
    pub stratum: u8,
    pub offset_ms: f32,
    pub precision_us: f32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSnapshot {
    pub id: String,
    pub version: u32,
    pub timestamp: String,
    pub author: String,
    pub description: String,
    pub can_rollback: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
    pub automated: bool,
    pub encrypted: bool,
    pub last_backup: String,
    pub target_storage: String,
}
