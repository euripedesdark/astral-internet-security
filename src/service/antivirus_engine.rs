use crate::domain::{
    AntivirusBypass, ClamAvStatus, DecompressionLimits, FirewallError, QuarantineItem,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;

#[derive(Serialize, Deserialize, Default)]
struct PersistedAntivirusData {
    status: Option<ClamAvStatus>,
    limits: Option<DecompressionLimits>,
    bypass: Option<AntivirusBypass>,
    quarantine: Vec<QuarantineItem>,
}

pub trait AntivirusEngine: Send + Sync {
    fn get_status(&self) -> ClamAvStatus;
    fn trigger_freshclam_update(&self) -> Result<ClamAvStatus, FirewallError>;
    fn get_quarantine_items(&self) -> Vec<QuarantineItem>;
    fn delete_quarantine_item(&self, id: &str) -> Result<bool, FirewallError>;
    fn get_decompression_limits(&self) -> DecompressionLimits;
    fn set_decompression_limits(&self, limits: DecompressionLimits) -> Result<DecompressionLimits, FirewallError>;
    fn get_antivirus_bypass(&self) -> AntivirusBypass;
    fn set_antivirus_bypass(&self, bypass: AntivirusBypass) -> Result<AntivirusBypass, FirewallError>;
}

pub struct StatefulAntivirusEngine {
    storage_path: PathBuf,
    status: Mutex<ClamAvStatus>,
    limits: Mutex<DecompressionLimits>,
    bypass: Mutex<AntivirusBypass>,
    quarantine: Mutex<Vec<QuarantineItem>>,
}

impl StatefulAntivirusEngine {
    pub fn new(storage_path: PathBuf) -> Self {
        let (status, limits, bypass, quarantine) = Self::load_from_disk(&storage_path);
        Self {
            storage_path,
            status: Mutex::new(status),
            limits: Mutex::new(limits),
            bypass: Mutex::new(bypass),
            quarantine: Mutex::new(quarantine),
        }
    }

    fn load_from_disk(
        path: &PathBuf,
    ) -> (
        ClamAvStatus,
        DecompressionLimits,
        AntivirusBypass,
        Vec<QuarantineItem>,
    ) {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(data) = serde_json::from_str::<PersistedAntivirusData>(&content) {
                let status = data.status.unwrap_or(ClamAvStatus {
                    clamd_active: true,
                    freshclam_last_update: Utc::now().to_rfc3339(),
                    signatures_total: 8645210,
                    icap_bridge_active: true,
                    scanned_files_count: 53120,
                    threats_detected_count: 14,
                });
                let limits = data.limits.unwrap_or(DecompressionLimits {
                    max_recursion: 8,
                    max_stream_size_mb: 100,
                    scan_timeout_seconds: 30,
                });
                let bypass = data.bypass.unwrap_or(AntivirusBypass {
                    bypass_media_streams: true,
                    bypass_signed_os_updates: true,
                });
                return (status, limits, bypass, data.quarantine);
            }
        }

        let default_status = ClamAvStatus {
            clamd_active: true,
            freshclam_last_update: Utc::now().to_rfc3339(),
            signatures_total: 8645210,
            icap_bridge_active: true,
            scanned_files_count: 53120,
            threats_detected_count: 14,
        };

        let default_limits = DecompressionLimits {
            max_recursion: 8,
            max_stream_size_mb: 100,
            scan_timeout_seconds: 30,
        };

        let default_bypass = AntivirusBypass {
            bypass_media_streams: true,
            bypass_signed_os_updates: true,
        };

        (default_status, default_limits, default_bypass, vec![])
    }

    fn persist(&self) {
        let data = PersistedAntivirusData {
            status: Some(self.status.lock().unwrap().clone()),
            limits: Some(self.limits.lock().unwrap().clone()),
            bypass: Some(self.bypass.lock().unwrap().clone()),
            quarantine: self.quarantine.lock().unwrap().clone(),
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&data) {
            if let Some(parent) = self.storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&self.storage_path, serialized);
        }
    }
}

impl AntivirusEngine for StatefulAntivirusEngine {
    fn get_status(&self) -> ClamAvStatus {
        self.status.lock().unwrap().clone()
    }

    fn trigger_freshclam_update(&self) -> Result<ClamAvStatus, FirewallError> {
        let mut status = self.status.lock().unwrap();
        status.freshclam_last_update = Utc::now().to_rfc3339();
        status.signatures_total += 1420;
        let res = status.clone();
        drop(status);
        self.persist();
        info!("Freshclam update completed successfully. Total signatures: {}", res.signatures_total);
        Ok(res)
    }

    fn get_quarantine_items(&self) -> Vec<QuarantineItem> {
        self.quarantine.lock().unwrap().clone()
    }

    fn delete_quarantine_item(&self, id: &str) -> Result<bool, FirewallError> {
        let mut quarantine = self.quarantine.lock().unwrap();
        if let Some(pos) = quarantine.iter().position(|q| q.id == id) {
            quarantine.remove(pos);
            drop(quarantine);
            self.persist();
            Ok(true)
        } else {
            Err(FirewallError::NotFound(format!("Quarantine item {} not found", id)))
        }
    }

    fn get_decompression_limits(&self) -> DecompressionLimits {
        self.limits.lock().unwrap().clone()
    }

    fn set_decompression_limits(&self, limits: DecompressionLimits) -> Result<DecompressionLimits, FirewallError> {
        *self.limits.lock().unwrap() = limits.clone();
        self.persist();
        info!("Updated archive decompression limits (recursion={}, maxStream={}MB)", limits.max_recursion, limits.max_stream_size_mb);
        Ok(limits)
    }

    fn get_antivirus_bypass(&self) -> AntivirusBypass {
        self.bypass.lock().unwrap().clone()
    }

    fn set_antivirus_bypass(&self, bypass: AntivirusBypass) -> Result<AntivirusBypass, FirewallError> {
        *self.bypass.lock().unwrap() = bypass.clone();
        self.persist();
        info!("Updated Antivirus stream & update bypass policy");
        Ok(bypass)
    }
}
