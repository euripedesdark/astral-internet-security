use crate::config::FirewallConfig;
use crate::controller::{
    AntivirusController, ComplianceController, CreateSnapshotRequest, FirewallController,
    GatewayController, IssueCertRequest, NatController, PanicRequest, VpnController,
    ZeroTrustController,
};
use crate::domain::{
    AliasObject, AlgConfig, AntiSpoofingConfig, AntivirusBypass, ClientSpecificOverride,
    DecompressionLimits, DnsSinkholeConfig, DohConfig, EdgeJwtValidator, EgressFilterConfig,
    FirewallRule, GeoIpPolicy, MultiWanConfig, MultiWanSetupRequest, NatRule, NetworkZone,
    OpenVpnConfig, PbrRule, QosConfig, RateLimitConfig, SyslogRemoteConfig, WanLink,
    WifiHotspotConfig, ZtnaAppPublish,
};
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub firewall: Arc<FirewallController>,
    pub nat: Arc<NatController>,
    pub gateway: Arc<GatewayController>,
    pub zero_trust: Arc<ZeroTrustController>,
    pub vpn: Arc<VpnController>,
    pub antivirus: Arc<AntivirusController>,
    pub compliance: Arc<ComplianceController>,
}

pub struct FirewallServer {
    config: Arc<FirewallConfig>,
    state: Arc<AppState>,
}

impl FirewallServer {
    pub fn new(config: Arc<FirewallConfig>, state: Arc<AppState>) -> Self {
        Self { config, state }
    }

    pub fn build_router(&self) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let static_dir = if std::path::Path::new("/opt/astral-internet-security/static/firewall/index.html").exists() {
            std::path::PathBuf::from("/opt/astral-internet-security/static/firewall")
        } else if std::path::Path::new("./src/main/resources/static/firewall/index.html").exists() {
            std::path::PathBuf::from("./src/main/resources/static/firewall")
        } else if std::path::Path::new("/opt/astral-internet-security/static/app/index.html").exists() {
            std::path::PathBuf::from("/opt/astral-internet-security/static/app")
        } else if std::path::Path::new("./src/main/resources/static/app/index.html").exists() {
            std::path::PathBuf::from("./src/main/resources/static/app")
        } else {
            std::path::PathBuf::from("/opt/astral-internet-security/static/firewall")
        };

        let index_file = static_dir.join("index.html");
        let serve_dir = ServeDir::new(&static_dir).fallback(ServeFile::new(index_file));

        Router::new()
            .route("/", get(|| async { axum::response::Redirect::temporary("/firewall/") }))
            .nest_service("/firewall", serve_dir)
            // 0. Health checks
            .route(
                "/health",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_health() }),
            )
            .route(
                "/actuator/health",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_health() }),
            )
            // =========================================================
            // 1. FIREWALL ENGINE (SPI, Zonas, Regras, Anti-Spoofing, Rate Limit, GeoIP)
            // =========================================================
            .route(
                "/api/firewall/state",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_state() }),
            )
            .route(
                "/api/v1/firewall/state",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_state() }),
            )
            .route(
                "/api/firewall/rules",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_rules() })
                    .post(|State(st): State<Arc<AppState>>, Json(rule): Json<FirewallRule>| async move {
                        st.firewall.handle_add_rule(rule)
                    }),
            )
            .route(
                "/api/v1/firewall/rules",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_rules() })
                    .post(|State(st): State<Arc<AppState>>, Json(rule): Json<FirewallRule>| async move {
                        st.firewall.handle_add_rule(rule)
                    }),
            )
            .route(
                "/api/firewall/rules/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.firewall.handle_delete_rule(&id)
                }),
            )
            .route(
                "/api/v1/firewall/rules/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.firewall.handle_delete_rule(&id)
                }),
            )
            .route(
                "/api/v1/firewall/zones",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_zones() })
                    .post(|State(st): State<Arc<AppState>>, Json(zone): Json<NetworkZone>| async move {
                        st.firewall.handle_add_zone(zone)
                    }),
            )
            .route(
                "/api/v1/firewall/aliases",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_aliases() })
                    .post(|State(st): State<Arc<AppState>>, Json(alias): Json<AliasObject>| async move {
                        st.firewall.handle_add_alias(alias)
                    }),
            )
            .route(
                "/api/v1/firewall/aliases/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.firewall.handle_delete_alias(&id)
                }),
            )
            .route(
                "/api/v1/firewall/anti-spoofing",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_anti_spoofing() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<AntiSpoofingConfig>| async move {
                        st.firewall.handle_set_anti_spoofing(cfg)
                    }),
            )
            .route(
                "/api/v1/firewall/rate-limiting",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_rate_limiting() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<RateLimitConfig>| async move {
                        st.firewall.handle_set_rate_limiting(cfg)
                    }),
            )
            .route(
                "/api/v1/firewall/geoip",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_get_geoip() })
                    .post(|State(st): State<Arc<AppState>>, Json(policy): Json<GeoIpPolicy>| async move {
                        st.firewall.handle_add_geoip(policy)
                    }),
            )
            .route(
                "/api/v1/firewall/geoip/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.firewall.handle_delete_geoip(&id)
                }),
            )
            .route(
                "/api/firewall/panic",
                post(|State(st): State<Arc<AppState>>, Json(req): Json<PanicRequest>| async move {
                    st.firewall.handle_panic(req)
                }),
            )
            .route(
                "/api/v1/firewall/panic",
                post(|State(st): State<Arc<AppState>>, Json(req): Json<PanicRequest>| async move {
                    st.firewall.handle_panic(req)
                }),
            )
            .route(
                "/api/firewall/stats",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_stats() }),
            )
            .route(
                "/api/v1/firewall/stats",
                get(|State(st): State<Arc<AppState>>| async move { st.firewall.handle_stats() }),
            )
            // =========================================================
            // 2. NAT ENGINE (SNAT, DNAT, 1:1, Hairpinning, NPTv6, ALG)
            // =========================================================
            .route(
                "/api/firewall/nat",
                get(|State(st): State<Arc<AppState>>| async move { st.nat.handle_get_rules() })
                    .post(|State(st): State<Arc<AppState>>, Json(rule): Json<NatRule>| async move {
                        st.nat.handle_add_rule(rule)
                    }),
            )
            .route(
                "/api/v1/firewall/nat",
                get(|State(st): State<Arc<AppState>>| async move { st.nat.handle_get_rules() })
                    .post(|State(st): State<Arc<AppState>>, Json(rule): Json<NatRule>| async move {
                        st.nat.handle_add_rule(rule)
                    }),
            )
            .route(
                "/api/firewall/nat/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.nat.handle_delete_rule(&id)
                }),
            )
            .route(
                "/api/v1/firewall/nat/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.nat.handle_delete_rule(&id)
                }),
            )
            .route(
                "/api/v1/nat/rules",
                get(|State(st): State<Arc<AppState>>| async move { st.nat.handle_get_rules() })
                    .post(|State(st): State<Arc<AppState>>, Json(rule): Json<NatRule>| async move {
                        st.nat.handle_add_rule(rule)
                    }),
            )
            .route(
                "/api/v1/nat/rules/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.nat.handle_delete_rule(&id)
                }),
            )
            .route(
                "/api/v1/nat/alg",
                get(|State(st): State<Arc<AppState>>| async move { st.nat.handle_get_alg() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<AlgConfig>| async move {
                        st.nat.handle_set_alg(cfg)
                    }),
            )
            // =========================================================
            // 3. GATEWAY ENGINE (Multi-WAN, PBR, Sinkhole, QoS, Egress)
            // =========================================================
            .route(
                "/api/v1/gateway/wan-links",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_wan_links() })
                    .post(|State(st): State<Arc<AppState>>, Json(link): Json<WanLink>| async move {
                        st.gateway.handle_update_wan_link(link)
                    }),
            )
            .route(
                "/api/v1/gateway/multi-wan",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_multi_wan() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<MultiWanConfig>| async move {
                        st.gateway.handle_set_multi_wan(cfg)
                    }),
            )
            .route(
                "/api/v1/gateway/pbr",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_pbr() })
                    .post(|State(st): State<Arc<AppState>>, Json(rule): Json<PbrRule>| async move {
                        st.gateway.handle_add_pbr(rule)
                    }),
            )
            .route(
                "/api/v1/gateway/pbr/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.gateway.handle_delete_pbr(&id)
                }),
            )
            .route(
                "/api/v1/gateway/dns-sinkhole",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_sinkhole() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<DnsSinkholeConfig>| async move {
                        st.gateway.handle_set_sinkhole(cfg)
                    }),
            )
            .route(
                "/api/v1/gateway/qos",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_qos() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<QosConfig>| async move {
                        st.gateway.handle_set_qos(cfg)
                    }),
            )
            .route(
                "/api/v1/gateway/egress-filter",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_egress() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<EgressFilterConfig>| async move {
                        st.gateway.handle_set_egress(cfg)
                    }),
            )
            .route(
                "/api/v1/gateway/interfaces",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_interfaces() }),
            )
            .route(
                "/api/v1/gateway/setup-wans",
                post(
                    |State(st): State<Arc<AppState>>, Json(req): Json<MultiWanSetupRequest>| async move {
                        st.gateway.handle_setup_multi_wan(req)
                    },
                ),
            )
            .route(
                "/api/v1/gateway/wifi/status",
                get(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_get_wifi_status() }),
            )
            .route(
                "/api/v1/gateway/wifi/hotspot",
                post(
                    |State(st): State<Arc<AppState>>, Json(cfg): Json<WifiHotspotConfig>| async move {
                        st.gateway.handle_start_wifi_hotspot(cfg)
                    },
                ),
            )
            .route(
                "/api/v1/gateway/wifi/stop",
                post(|State(st): State<Arc<AppState>>| async move { st.gateway.handle_stop_wifi_hotspot() }),
            )
            // =========================================================
            // 4. ZERO TRUST ENGINE (Cloudflare Tunnel, ZTNA, JWT, DoH)
            // =========================================================
            .route(
                "/api/v1/zero-trust/tunnel",
                get(|State(st): State<Arc<AppState>>| async move { st.zero_trust.handle_get_tunnel() }),
            )
            .route(
                "/api/v1/zero-trust/apps",
                get(|State(st): State<Arc<AppState>>| async move { st.zero_trust.handle_get_apps() })
                    .post(|State(st): State<Arc<AppState>>, Json(app): Json<ZtnaAppPublish>| async move {
                        st.zero_trust.handle_add_app(app)
                    }),
            )
            .route(
                "/api/v1/zero-trust/apps/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.zero_trust.handle_delete_app(&id)
                }),
            )
            .route(
                "/api/v1/zero-trust/jwt-validator",
                get(|State(st): State<Arc<AppState>>| async move { st.zero_trust.handle_get_jwt() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<EdgeJwtValidator>| async move {
                        st.zero_trust.handle_set_jwt(cfg)
                    }),
            )
            .route(
                "/api/v1/zero-trust/doh",
                get(|State(st): State<Arc<AppState>>| async move { st.zero_trust.handle_get_doh() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<DohConfig>| async move {
                        st.zero_trust.handle_set_doh(cfg)
                    }),
            )
            // =========================================================
            // 5. VPN ENGINE (OpenVPN, PKI, DCO, MFA, .OVPN)
            // =========================================================
            .route(
                "/api/v1/vpn/config",
                get(|State(st): State<Arc<AppState>>| async move { st.vpn.handle_get_config() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<OpenVpnConfig>| async move {
                        st.vpn.handle_set_config(cfg)
                    }),
            )
            .route(
                "/api/v1/vpn/certificates",
                get(|State(st): State<Arc<AppState>>| async move { st.vpn.handle_get_certs() })
                    .post(|State(st): State<Arc<AppState>>, Json(req): Json<IssueCertRequest>| async move {
                        st.vpn.handle_issue_cert(req)
                    }),
            )
            .route(
                "/api/v1/vpn/certificates/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.vpn.handle_revoke_cert(&id)
                }),
            )
            .route(
                "/api/v1/vpn/overrides",
                get(|State(st): State<Arc<AppState>>| async move { st.vpn.handle_get_overrides() })
                    .post(|State(st): State<Arc<AppState>>, Json(ccd): Json<ClientSpecificOverride>| async move {
                        st.vpn.handle_set_override(ccd)
                    }),
            )
            .route(
                "/api/v1/vpn/export/{clientName}",
                get(|State(st): State<Arc<AppState>>, Path(client_name): Path<String>| async move {
                    st.vpn.handle_export_ovpn(&client_name)
                }),
            )
            // =========================================================
            // 6. ANTIVIRUS ENGINE (ClamAV, ICAP, Freshclam, Quarentena, Limites, Bypass)
            // =========================================================
            .route(
                "/api/v1/antivirus/status",
                get(|State(st): State<Arc<AppState>>| async move { st.antivirus.handle_get_status() }),
            )
            .route(
                "/api/v1/antivirus/update",
                post(|State(st): State<Arc<AppState>>| async move { st.antivirus.handle_trigger_update() }),
            )
            .route(
                "/api/v1/antivirus/quarantine",
                get(|State(st): State<Arc<AppState>>| async move { st.antivirus.handle_get_quarantine() }),
            )
            .route(
                "/api/v1/antivirus/quarantine/{id}",
                delete(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.antivirus.handle_delete_quarantine(&id)
                }),
            )
            .route(
                "/api/v1/antivirus/decompression-limits",
                get(|State(st): State<Arc<AppState>>| async move { st.antivirus.handle_get_limits() })
                    .post(|State(st): State<Arc<AppState>>, Json(limits): Json<DecompressionLimits>| async move {
                        st.antivirus.handle_set_limits(limits)
                    }),
            )
            .route(
                "/api/v1/antivirus/bypass",
                get(|State(st): State<Arc<AppState>>| async move { st.antivirus.handle_get_bypass() })
                    .post(|State(st): State<Arc<AppState>>, Json(bypass): Json<AntivirusBypass>| async move {
                        st.antivirus.handle_set_bypass(bypass)
                    }),
            )
            // =========================================================
            // 7. COMPLIANCE ENGINE (ISO 27001 Audit Logs, TLS Syslog RFC 5424, NTP, Rollback, Backup)
            // =========================================================
            .route(
                "/api/v1/compliance/audit-logs",
                get(|State(st): State<Arc<AppState>>| async move { st.compliance.handle_get_audit_logs() }),
            )
            .route(
                "/api/v1/compliance/syslog",
                get(|State(st): State<Arc<AppState>>| async move { st.compliance.handle_get_syslog() })
                    .post(|State(st): State<Arc<AppState>>, Json(cfg): Json<SyslogRemoteConfig>| async move {
                        st.compliance.handle_set_syslog(cfg)
                    }),
            )
            .route(
                "/api/v1/compliance/ntp",
                get(|State(st): State<Arc<AppState>>| async move { st.compliance.handle_get_ntp() }),
            )
            .route(
                "/api/v1/compliance/snapshots",
                get(|State(st): State<Arc<AppState>>| async move { st.compliance.handle_get_snapshots() })
                    .post(|State(st): State<Arc<AppState>>, Json(req): Json<CreateSnapshotRequest>| async move {
                        st.compliance.handle_create_snapshot(req)
                    }),
            )
            .route(
                "/api/v1/compliance/snapshots/{id}/rollback",
                post(|State(st): State<Arc<AppState>>, Path(id): Path<String>| async move {
                    st.compliance.handle_rollback_snapshot(&id)
                }),
            )
            .route(
                "/api/v1/compliance/backup",
                get(|State(st): State<Arc<AppState>>| async move { st.compliance.handle_get_backup() })
                    .post(|State(st): State<Arc<AppState>>| async move { st.compliance.handle_trigger_backup() }),
            )
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(self.state.clone())
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));
        info!("Astral Internet Security listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let router = self.build_router();
        axum::serve(listener, router).await?;
        Ok(())
    }
}
