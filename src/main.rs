mod config;
mod controller;
mod domain;
mod server;
mod service;

use config::FirewallConfig;
use controller::{
    AntivirusController, ComplianceController, FirewallController, GatewayController,
    NatController, VpnController, ZeroTrustController,
};
use server::{AppState, FirewallServer};
use service::{
    IptablesBackend, StatefulAntivirusEngine, StatefulComplianceEngine,
    StatefulFirewallEngine, StatefulGatewayEngine, StatefulNatEngine, StatefulVpnEngine,
    StatefulZeroTrustEngine,
};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("============================================================");
    info!("   Astral Internet Security - ISO 27001 Architecture v1.4   ");
    info!("   Filtragem, NAT, Multi-WAN, ZTNA, OpenVPN, ClamAV, Auditoria");
    info!("============================================================");

    let config = Arc::new(FirewallConfig::load());
    let backend = Arc::new(IptablesBackend::new());

    // 1. Motor de Firewall (SPI, Conntrack, Default Deny, Zonas, Spoofing, DoS, GeoIP)
    let firewall_engine = Arc::new(StatefulFirewallEngine::new(backend.clone(), config.firewall_path()));
    let firewall_controller = Arc::new(FirewallController::new(firewall_engine));

    // 2. Motor de NAT (SNAT Masquerade, DNAT Port Forward, 1:1, Hairpinning, NPTv6, ALG)
    let nat_engine = Arc::new(StatefulNatEngine::new(config.nat_path()));
    let nat_controller = Arc::new(NatController::new(nat_engine));

    // 3. Gateway de Acesso (Multi-WAN Failover/LB, PBR, DNS Sinkhole RPZ, QoS Cake, Egress)
    let gateway_engine = Arc::new(StatefulGatewayEngine::new(config.gateway_path()));
    let gateway_controller = Arc::new(GatewayController::new(gateway_engine));

    // 4. Integração Zero Trust (Cloudflare Tunnel, ZTNA Apps, JWT Assertion, DoH)
    let zero_trust_engine = Arc::new(StatefulZeroTrustEngine::new(config.zero_trust_path()));
    let zero_trust_controller = Arc::new(ZeroTrustController::new(zero_trust_engine));

    // 5. Túnel VPN (OpenVPN DCO, PKI Integrado, AES-256-GCM, MFA TOTP, .ovpn)
    let vpn_engine = Arc::new(StatefulVpnEngine::new(config.vpn_path()));
    let vpn_controller = Arc::new(VpnController::new(vpn_engine));

    // 6. Antivírus de Gateway (ClamAV clamd, ICAP, Freshclam, Quarentena, Archive Limits)
    let antivirus_engine = Arc::new(StatefulAntivirusEngine::new(config.antivirus_path()));
    let antivirus_controller = Arc::new(AntivirusController::new(antivirus_engine));

    // 7. Governança & Conformidade ISO 27001 (Auditoria, TLS Syslog RFC 5424, NTP, Rollback, Backup)
    let compliance_engine = Arc::new(StatefulComplianceEngine::new(config.compliance_path()));
    let compliance_controller = Arc::new(ComplianceController::new(compliance_engine));

    let app_state = Arc::new(AppState {
        firewall: firewall_controller,
        nat: nat_controller,
        gateway: gateway_controller,
        zero_trust: zero_trust_controller,
        vpn: vpn_controller,
        antivirus: antivirus_controller,
        compliance: compliance_controller,
    });

    let server = FirewallServer::new(config, app_state);
    server.run().await
}
