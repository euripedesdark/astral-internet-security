use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub zone: String,
    pub protocol: String,
    pub port: String,
    pub action: String, // "ACCEPT", "DROP", "REJECT"
    pub direction: String, // "IN", "OUT", "FORWARD"
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NatRule {
    pub id: String,
    pub name: String,
    pub original_port: String,
    pub destination_ip: String,
    pub destination_port: String,
    pub protocol: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FirewallState {
    pub panic_mode: bool,
    pub default_policy: String,
    pub rules_count: usize,
    pub active_connections: usize,
    pub last_synced: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfaceStat {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
