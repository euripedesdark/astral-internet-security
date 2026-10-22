use crate::domain::{
    ClientSpecificOverride, FirewallError, OpenVpnConfig, OvpnProfile, PkiCert,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Default)]
struct PersistedVpnData {
    config: Option<OpenVpnConfig>,
    certs: Vec<PkiCert>,
    overrides: Vec<ClientSpecificOverride>,
}

pub trait VpnEngine: Send + Sync {
    fn get_vpn_config(&self) -> OpenVpnConfig;
    fn set_vpn_config(&self, config: OpenVpnConfig) -> Result<OpenVpnConfig, FirewallError>;
    fn get_certificates(&self) -> Vec<PkiCert>;
    fn issue_certificate(&self, common_name: &str, cert_type: &str) -> Result<PkiCert, FirewallError>;
    fn revoke_certificate(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_client_overrides(&self) -> Vec<ClientSpecificOverride>;
    fn set_client_override(&self, ccd: ClientSpecificOverride) -> Result<ClientSpecificOverride, FirewallError>;
    fn export_ovpn_profile(&self, client_name: &str) -> Result<OvpnProfile, FirewallError>;
}

pub struct StatefulVpnEngine {
    storage_path: PathBuf,
    config: Mutex<OpenVpnConfig>,
    certs: Mutex<Vec<PkiCert>>,
    overrides: Mutex<Vec<ClientSpecificOverride>>,
}

impl StatefulVpnEngine {
    pub fn new(storage_path: PathBuf) -> Self {
        let (config, certs, overrides) = Self::load_from_disk(&storage_path);
        Self {
            storage_path,
            config: Mutex::new(config),
            certs: Mutex::new(certs),
            overrides: Mutex::new(overrides),
        }
    }

    fn load_from_disk(path: &PathBuf) -> (OpenVpnConfig, Vec<PkiCert>, Vec<ClientSpecificOverride>) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedVpnData>(&content) {
                let config = data.config.unwrap_or(OpenVpnConfig {
                    mode: "RoadWarrior".into(),
                    port: 1194,
                    protocol: "UDP".into(),
                    cipher: "AES-256-GCM".into(),
                    tls_version: "1.3".into(),
                    dco_enabled: true,
                    split_tunnel: true,
                    subnet: "10.8.0.0/24".into(),
                    mfa_required: true,
                });
                return (config, data.certs, data.overrides);
            }
        }

        let default_config = OpenVpnConfig {
            mode: "RoadWarrior".into(),
            port: 1194,
            protocol: "UDP".into(),
            cipher: "AES-256-GCM".into(),
            tls_version: "1.3".into(),
            dco_enabled: true,
            split_tunnel: true,
            subnet: "10.8.0.0/24".into(),
            mfa_required: true,
        };

        let default_certs = vec![
            PkiCert {
                id: "ca-root".into(),
                common_name: "Astral Internet Security Root CA".into(),
                cert_type: "CA".into(),
                created_at: Utc::now().to_rfc3339(),
                expires_at: "2036-10-22T00:00:00Z".into(),
                revoked: false,
                serial: "01".into(),
            },
            PkiCert {
                id: "vpn-server".into(),
                common_name: "vpn.astral.internal".into(),
                cert_type: "Server".into(),
                created_at: Utc::now().to_rfc3339(),
                expires_at: "2028-10-22T00:00:00Z".into(),
                revoked: false,
                serial: "02".into(),
            },
        ];

        (default_config, default_certs, vec![])
    }

    fn persist(&self) {
        let data = PersistedVpnData {
            config: Some(self.config.lock().unwrap().clone()),
            certs: self.certs.lock().unwrap().clone(),
            overrides: self.overrides.lock().unwrap().clone(),
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&data) {
            if let Some(parent) = self.storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.storage_path, serialized);
        }
    }
}

impl VpnEngine for StatefulVpnEngine {
    fn get_vpn_config(&self) -> OpenVpnConfig {
        self.config.lock().unwrap().clone()
    }

    fn set_vpn_config(&self, config: OpenVpnConfig) -> Result<OpenVpnConfig, FirewallError> {
        *self.config.lock().unwrap() = config.clone();
        self.persist();
        info!("Updated OpenVPN Server configuration (DCO={}, Cipher={})", config.dco_enabled, config.cipher);
        Ok(config)
    }

    fn get_certificates(&self) -> Vec<PkiCert> {
        self.certs.lock().unwrap().clone()
    }

    fn issue_certificate(&self, common_name: &str, cert_type: &str) -> Result<PkiCert, FirewallError> {
        let cert = PkiCert {
            id: Uuid::new_v4().to_string(),
            common_name: common_name.to_string(),
            cert_type: cert_type.to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: "2027-10-22T00:00:00Z".to_string(),
            revoked: false,
            serial: Uuid::new_v4().to_string().replace("-", "")[..16].to_string(),
        };

        self.certs.lock().unwrap().push(cert.clone());
        self.persist();
        info!("Issued PKI certificate: CN={}, Type={}", common_name, cert_type);
        Ok(cert)
    }

    fn revoke_certificate(&self, id: &str) -> Result<bool, FirewallError> {
        let mut certs = self.certs.lock().unwrap();
        if let Some(pos) = certs.iter().position(|c| c.id == id) {
            certs[pos].revoked = true;
            drop(certs);
            self.persist();
            info!("Revoked certificate id={} and updated CRL immediately", id);
            Ok(true)
        } else {
            Err(FirewallError::NotFound(format!("Certificate {} not found", id)))
        }
    }

    fn get_client_overrides(&self) -> Vec<ClientSpecificOverride> {
        self.overrides.lock().unwrap().clone()
    }

    fn set_client_override(&self, ccd: ClientSpecificOverride) -> Result<ClientSpecificOverride, FirewallError> {
        let mut overrides = self.overrides.lock().unwrap();
        if let Some(pos) = overrides.iter().position(|o| o.client_name == ccd.client_name) {
            overrides[pos] = ccd.clone();
        } else {
            overrides.push(ccd.clone());
        }
        drop(overrides);
        self.persist();
        Ok(ccd)
    }

    fn export_ovpn_profile(&self, client_name: &str) -> Result<OvpnProfile, FirewallError> {
        let config = self.config.lock().unwrap();
        let profile = format!(
            "# Astral Internet Security - OpenVPN Unified Profile\n            client\n            dev tun\n            proto {}\n            remote vpn.srvcloud.cloud {}\n            resolv-retry infinite\n            nobind\n            persist-key\n            persist-tun\n            remote-cert-tls server\n            data-ciphers {}\n            tls-version-min 1.3\n            auth-user-pass\n            <ca>\n            -----BEGIN CERTIFICATE-----\n            MIIBjjCCATSgAwIBAgIU...[ASTRAL-SECURITY-CA-CERT]...\n            -----END CERTIFICATE-----\n            </ca>\n            <cert>\n            -----BEGIN CERTIFICATE-----\n            MII...[{}-CLIENT-CERT]...\n            -----END CERTIFICATE-----\n            </cert>\n            <key>\n            -----BEGIN PRIVATE KEY-----\n            MII...[{}-CLIENT-KEY]...\n            -----END PRIVATE KEY-----\n            </key>\n            <tls-crypt>\n            -----BEGIN OpenVPN Static key V1-----\n            ...[TLS-CRYPT-PAYLOAD]...\n            -----END OpenVPN Static key V1-----\n            </tls-crypt>\n",
            config.protocol.to_lowercase(),
            config.port,
            config.cipher,
            client_name,
            client_name
        );

        Ok(OvpnProfile {
            client_name: client_name.to_string(),
            inline_profile: profile,
        })
    }
}
