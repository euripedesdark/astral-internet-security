use crate::domain::{
    CloudflareTunnelConfig, DohConfig, EdgeJwtValidator, FirewallError, ZtnaAppPublish,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
struct PersistedZeroTrustData {
    tunnel: Option<CloudflareTunnelConfig>,
    apps: Vec<ZtnaAppPublish>,
    jwt_validator: Option<EdgeJwtValidator>,
    doh: Option<DohConfig>,
}

pub trait ZeroTrustEngine: Send + Sync {
    fn get_tunnel_status(&self) -> CloudflareTunnelConfig;
    fn get_ztna_apps(&self) -> Vec<ZtnaAppPublish>;
    fn publish_ztna_app(&self, app: ZtnaAppPublish) -> Result<ZtnaAppPublish, FirewallError>;
    fn delete_ztna_app(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_jwt_validator(&self) -> EdgeJwtValidator;
    fn set_jwt_validator(&self, config: EdgeJwtValidator) -> Result<EdgeJwtValidator, FirewallError>;
    fn get_doh_config(&self) -> DohConfig;
    fn set_doh_config(&self, config: DohConfig) -> Result<DohConfig, FirewallError>;
}

pub struct StatefulZeroTrustEngine {
    storage_path: PathBuf,
    tunnel: Mutex<CloudflareTunnelConfig>,
    apps: Mutex<Vec<ZtnaAppPublish>>,
    jwt_validator: Mutex<EdgeJwtValidator>,
    doh: Mutex<DohConfig>,
}

impl StatefulZeroTrustEngine {
    pub fn new(storage_path: PathBuf) -> Self {
        let (tunnel, apps, jwt_validator, doh) = Self::load_from_disk(&storage_path);
        Self {
            storage_path,
            tunnel: Mutex::new(tunnel),
            apps: Mutex::new(apps),
            jwt_validator: Mutex::new(jwt_validator),
            doh: Mutex::new(doh),
        }
    }

    fn load_from_disk(
        path: &PathBuf,
    ) -> (
        CloudflareTunnelConfig,
        Vec<ZtnaAppPublish>,
        EdgeJwtValidator,
        DohConfig,
    ) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedZeroTrustData>(&content) {
                let tunnel = data.tunnel.unwrap_or(CloudflareTunnelConfig {
                    tunnel_id: "astral-argo-tunnel-01".into(),
                    tunnel_name: "astral-enterprise-edge".into(),
                    status: "Connected".into(),
                    active_connectors: 2,
                    ingress_rules_count: 5,
                });
                let jwt = data.jwt_validator.unwrap_or(EdgeJwtValidator {
                    enabled: true,
                    team_domain: "astral-sec.cloudflareaccess.com".into(),
                    audience_tag: "cf-access-aud-astral-erp".into(),
                });
                let doh = data.doh.unwrap_or(DohConfig {
                    doh_url: "https://cloudflare-dns.com/dns-query".into(),
                    dot_fallback: true,
                    enabled: true,
                });
                return (tunnel, data.apps, jwt, doh);
            }
        }

        let default_tunnel = CloudflareTunnelConfig {
            tunnel_id: "astral-argo-tunnel-01".into(),
            tunnel_name: "astral-enterprise-edge".into(),
            status: "Connected".into(),
            active_connectors: 2,
            ingress_rules_count: 5,
        };

        let default_apps = vec![
            ZtnaAppPublish {
                id: "ztna-erp".into(),
                hostname: "erp.srvcloud.cloud".into(),
                internal_service_url: "http://192.168.2.10:8080".into(),
                require_mfa: true,
            },
            ZtnaAppPublish {
                id: "ztna-security".into(),
                hostname: "security.srvcloud.cloud".into(),
                internal_service_url: "http://192.168.2.10:8084".into(),
                require_mfa: true,
            },
        ];

        let default_jwt = EdgeJwtValidator {
            enabled: true,
            team_domain: "astral-sec.cloudflareaccess.com".into(),
            audience_tag: "cf-access-aud-astral-erp".into(),
        };

        let default_doh = DohConfig {
            doh_url: "https://cloudflare-dns.com/dns-query".into(),
            dot_fallback: true,
            enabled: true,
        };

        (default_tunnel, default_apps, default_jwt, default_doh)
    }

    fn persist(&self) {
        let data = PersistedZeroTrustData {
            tunnel: Some(self.tunnel.lock().unwrap().clone()),
            apps: self.apps.lock().unwrap().clone(),
            jwt_validator: Some(self.jwt_validator.lock().unwrap().clone()),
            doh: Some(self.doh.lock().unwrap().clone()),
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&data) {
            if let Some(parent) = self.storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.storage_path, serialized);
        }
    }
}

impl ZeroTrustEngine for StatefulZeroTrustEngine {
    fn get_tunnel_status(&self) -> CloudflareTunnelConfig {
        self.tunnel.lock().unwrap().clone()
    }

    fn get_ztna_apps(&self) -> Vec<ZtnaAppPublish> {
        self.apps.lock().unwrap().clone()
    }

    fn publish_ztna_app(&self, mut app: ZtnaAppPublish) -> Result<ZtnaAppPublish, FirewallError> {
        if app.id.is_empty() {
            app.id = Uuid::new_v4().to_string();
        }
        self.apps.lock().unwrap().push(app.clone());
        self.persist();
        info!("Published internal app via Cloudflare ZTNA: {}", app.hostname);
        Ok(app)
    }

    fn delete_ztna_app(&self, id: &str) -> Result<bool, FirewallError> {
        let mut apps = self.apps.lock().unwrap();
        if let Some(pos) = apps.iter().position(|a| a.id == id) {
            apps.remove(pos);
            drop(apps);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::NotFound(format!("ZTNA app {} not found", id)))
        }
    }

    fn get_jwt_validator(&self) -> EdgeJwtValidator {
        self.jwt_validator.lock().unwrap().clone()
    }

    fn set_jwt_validator(&self, config: EdgeJwtValidator) -> Result<EdgeJwtValidator, FirewallError> {
        *self.jwt_validator.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated Cloudflare Edge JWT validation: domain={}", config.team_domain);
        Ok(config)
    }

    fn get_doh_config(&self) -> DohConfig {
        self.doh.lock().unwrap().clone()
    }

    fn set_doh_config(&self, config: DohConfig) -> Result<DohConfig, FirewallError> {
        *self.doh.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated DoH Gateway DNS: url={}", config.doh_url);
        Ok(config)
    }
}
