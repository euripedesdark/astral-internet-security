# Astral Internet Security — Documentation (English)

![License](https://img.shields.io/badge/License-Proprietary-red.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![ISO 27001](https://img.shields.io/badge/Security-ISO%2FIEC%2027001-blue.svg)
![i18n](https://img.shields.io/badge/i18n-4%20Languages-green.svg)

High-Performance Edge Security Gateway and Perimeter Defense in Rust, designed according to ISO/IEC 27001:2022 standards.

---

## 7 Core Security Modules

1. **Stateful Firewall Engine (SPI & Zones)**:
   - Packet inspection with real-time connection tracking (Conntrack).
   - Anti-spoofing and Bogon filter (RFC 1918) on external interfaces.
   - Adaptive rate limiting mitigating SYN, ICMP, and UDP floods.
   - GeoIP filtering with directional country blocking.
2. **NAT & Forwarding Engine**:
   - DNAT (Port Forwarding), SNAT Masquerade, 1:1 Static NAT, and NPTv6.
   - NAT Reflection / Hairpinning for LAN-to-LAN access via external IP.
   - Application Layer Gateway (ALG) helpers for SIP, FTP, TFTP, and PPTP.
3. **Multi-WAN Gateway & Web Filter**:
   - Real-time WAN link health monitoring (RTT, Jitter, Packet Loss).
   - Dynamic failover and weighted round-robin load balancing.
   - Policy-Based Routing (PBR) and Cake QoS traffic shaping.
   - DNS Sinkhole blocking malware command and control (C2) domains.
4. **Cloudflare Zero Trust (ZTNA)**:
   - Native Argo Tunnel (`cloudflared`) connector with zero open inbound ports.
   - Edge JWT assertion verification (`Cf-Access-Jwt-Assertion`).
   - Encrypted DNS resolution via DNS over HTTPS (DoH) / DNS over TLS (DoT).
5. **OpenVPN & PKI Manager**:
   - Internal X.509 Certificate Authority with immediate CRL revocation.
   - Kernel Data Channel Offload (DCO) acceleration for gigabit throughput.
   - Ready-to-use `.ovpn` client profile export.
6. **ClamAV Antivirus & ICAP**:
   - Low-latency stream inspection via ICAP protocol.
   - Automatic signature synchronization via Freshclam.
   - Forensic quarantine and archive decompression bomb prevention.
7. **ISO 27001 Governance & SIEM Audit**:
   - Strict Change Management workflow (Control A.8.32) requiring Diff review and technical justification.
   - Immutable configuration snapshots with one-click emergency rollback.
   - NTP clock synchronization compliance (Control A.8.17).
   - RFC 5424 TLS remote syslog forwarding for SIEM integration.

---

## Multilingual NOC/SOC Web Console

React 18 SPA console with full internationalization across 4 languages:
- English (en-US)
- Portuguese (pt-BR)
- Spanish (es-ES)
- French (fr-FR)

---

## License

Copyright (C) Astral Software. All rights reserved. Commercial Proprietary License.
