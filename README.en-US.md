# Astral Internet Security

![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite%20%2B%20PrimeReact-61dafb.svg)
![ISO 27001](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027001-emerald.svg)

**Stateful Firewall, NAT, Edge Gateway, Zero Trust & Antivirus in Rust & React** — Enterprise high-density perimeter security system strictly aligned with **ISO/IEC 27001** controls. Built in pure **Rust** (OOP architecture with Tokio & Axum) and a **React 18** SPA interface using PrimeReact in a high-density NOC/SOC dark theme.

Licensed under **GNU AGPL v3**. See [`LICENSE.md`](LICENSE.md).

---

## 🛡️ The 7 Pillars of the ISO/IEC 27001 Architecture

1. **Stateful Firewall Engine (SPI & Traffic Control):** Connection tracking (conntrack), default deny policy, zone segregation (WAN, LAN, DMZ, Guest, VPN/ZTNA), granular filtering, anti-spoofing (RFC 1918 WAN drop), IANA bogon filtering, DoS rate limiting, and GeoIP blocking.
2. **NAT Engine:** Port forwarding (DNAT), outbound masquerading (SNAT), 1:1 NAT (Binat), NPTv6 prefix translation, NAT loopback reflection, and ALG helpers (SIP, FTP, PPTP, TFTP).
3. **Gateway, Multi-WAN & Web Filter:** Automatic failover, weighted load balancing with sticky connections, policy-based routing (PBR), FQ_CoDel/Cake QoS bufferbloat mitigation, egress filtering, and DNS Sinkhole (RPZ C2 & malware blocking).
4. **Cloudflare Zero Trust (ZTNA):** Native cloudflared connector (Argo Tunnel with zero inbound ports), private WARP routing, edge JWT assertion validation (`Cf-Access-Jwt-Assertion`), and DoH/DoT resolution.
5. **OpenVPN & PKI Manager:** Built-in Local CA and cert manager, instant CRL revocation, kernel DCO acceleration, AES-256-GCM / ChaCha20-Poly1305, MFA TOTP enforcement, client-specific overrides (CCD), and 1-click unified `.ovpn` profile export.
6. **Gateway Antivirus (ClamAV & ICAP):** clamd daemon with ICAP streaming inspection, freshclam updater with extended community feeds, encrypted quarantine vault, decompression bomb defense limits, and intelligent streaming bypass.
7. **ISO/IEC 27001 Governance & Audit:** Change management approval workflow with Before/After Diff viewer (A.8.32), version history with 1-click rollback, live tail console with TLS RFC 5424 Syslog SIEM export (A.8.15), authenticated NTP synchronization check (A.8.17), semantic compliance risk badges (A.8.20), and encrypted backup (A.8.13).

---

## 🚀 1-Command Clean Build & Deploy

```bash
./deploy.py
```
Access the operational dashboard at: `http://<FIREWALL-IP>:8084/app/`
