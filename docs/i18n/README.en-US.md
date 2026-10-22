# Astral Internet Security

![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![Netfilter](https://img.shields.io/badge/Firewall-Netfilter%20%2F%20eBPF-brightgreen.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61dafb.svg)

**Next-Generation Firewall (NGFW), Stateful Packet Inspection (SPI) and Threat Mitigation in Rust** — Enterprise security module of the Astral ecosystem. Built with Object-Oriented Architecture in Rust, Tokio runtime, and Axum web server, providing network perimeter security, packet filtering, NAT, zone isolation, and active defense.

This project is licensed under **GNU AGPL v3**. See [`LICENSE.md`](LICENSE.md).

---

## 🎯 Key Features

- **Object-Oriented Architecture in Rust**:
  - Clean layered structure: Domain Models (`domain/`), Service Traits and Implementations (`service/`), and REST Controllers (`controller/`).
  - Polymorphic services via `Arc<dyn FirewallService>` and dependency inversion.
- **Stateful Rule Management**:
  - Auditable manipulation of Linux kernel `filter`, `nat`, and `mangle` tables via Netfilter/nftables/eBPF.
  - Multi-zone network definitions (WAN, LAN, DMZ, Isolated) and interface binding.
  - Reusable CIDR host groups and port groups for clean policy composition.
- **NAT, Gateway and Port Forwarding**:
  - Port Forwarding (DNAT) for publishing internal services.
  - Automated Masquerade (SNAT) for secure Internet egress.
- **Active Defense and Threat Mitigation**:
  - Real-time Rate Limiting and Auto-Ban policies against port scanners and DoS attempts.
  - **Panic Mode**: Immediate zero-trust barrier blocking non-essential ingress traffic during incidents.
  - Rule snapshot history with instant rollback capabilities.
- **Modern Management UI**:
  - React 18, TypeScript, and Vite single-page dashboard with native 4-language i18n support.

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Core Language** | Rust 1.80+ (Edition 2021/2024) | Memory safety, zero-cost abstractions, fearless concurrency |
| **Architecture** | Object-Oriented (OOP) | Domain traits, encapsulation, dynamic dispatch, clean interfaces |
| **Web Server** | Axum 0.8 + Tower | High-throughput asynchronous HTTP REST API |
| **Async Runtime** | Tokio 1.x (Full) | Scalable non-blocking asynchronous I/O execution |
| **Packet Filtering** | Linux Netfilter / nftables / eBPF | Kernel packet evaluation, state tracking, and IP tables manipulation |
| **Frontend UI** | React 18, TypeScript, Vite | Modern responsive administration console |

---

## 💖 Support the Project

Astral Internet Security is open-source software maintained by an independent engineer:

### International Transfer (Wise)

| | |
|---|---|
| **Beneficiary** | Euripedes Batista de Paiva Junior |
| **Account Type** | Checking |
| **Routing number (Wire & ACH)** | `101019628` |
| **Account number** | `215822927677` |
| **Bank Name** | Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States |
| **SWIFT / BIC** | `TRWIUS35XXX` |

### Brazil (PIX)

```text
24adc62c-b073-4587-974d-03fe35f6733f
```

---

## 📄 License

This project is licensed under **GNU Affero General Public License v3.0 (AGPLv3)**. See [`LICENSE.md`](LICENSE.md).

(c) 2026 Astral Internet Security — **Created by: Euripedes Batista de Paiva Junior**
