# Astral Internet Security — ISO/IEC 27001 Edge Gateway

![Licença](https://img.shields.io/badge/License-Proprietary-red.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Netfilter](https://img.shields.io/badge/Engine-Netfilter%20%2F%20eBPF-brightgreen.svg)
![ISO 27001](https://img.shields.io/badge/Security-ISO%2FIEC%2027001%20Compliant-blue.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61dafb.svg)
![i18n](https://img.shields.io/badge/i18n-4%20Languages-green.svg)

🇧🇷 **Gateway de Borda e Segurança Perimetral em Rust com Conformidade ISO/IEC 27001** — Módulo corporativo do ecossistema Astral que consolida firewall stateful (SPI), NAT avançado, gateway Multi-WAN com failover, Cloudflare Zero Trust (ZTNA), túnel OpenVPN com PKI local, antivírus de fluxo ClamAV/ICAP e auditoria contínua com gestão de mudanças (Controle A.8.32).

🇺🇸 **Edge Security Gateway and Perimeter Protection in Rust with ISO/IEC 27001 Compliance** — Enterprise module of the Astral ecosystem consolidating stateful firewall (SPI), advanced NAT, Multi-WAN gateway with failover, Cloudflare Zero Trust (ZTNA), OpenVPN tunnel with local PKI, ClamAV/ICAP stream antivirus, and continuous audit trail with change management (Control A.8.32).

---

## 🌐 Idiomas / Languages

| | Idioma / Language | Documentação / Documentation |
|---|---|---|
| 🇧🇷 | **Português (Brasil)** | [README.pt-BR.md](README.pt-BR.md) |
| 🇺🇸 | **English** | [README.en-US.md](README.en-US.md) |
| 🇪🇸 | **Español** | [README.es-ES.md](README.es-ES.md) |
| 🇫🇷 | **Français** | [README.fr-FR.md](README.fr-FR.md) |

---

## 🛡️ 7 Módulos de Segurança ISO 27001 / 7 Edge Security Modules

1. **Motor de Firewall (SPI & Zonas)**:
   - Inspeção de estados (Conntrack), Anti-Spoofing (RFC 1918 Bogons), Rate Limiting contra DoS/DDoS (SYN/UDP/ICMP Flood) e bloqueio geográfico GeoIP.
2. **Motor de NAT & Forwarding**:
   - Port Forwarding (DNAT), Outbound NAT (SNAT Masquerade), NAT 1:1 (BINAT), NPTv6, NAT Reflection (Hairpinning) e helpers ALG.
3. **Gateway Multi-WAN & Web Filter**:
   - Failover automático, Balanceamento de Carga ponderado, Roteamento Baseado em Políticas (PBR), QoS Cake contra Bufferbloat e DNS Sinkhole RPZ contra botnets.
4. **Cloudflare Zero Trust (ZTNA)**:
   - Conector Argo Tunnel (`cloudflared`) nativo sem portas de entrada expostas, validação criptográfica de tokens JWT (`Cf-Access-Jwt-Assertion`) e DNS over HTTPS (DoH).
5. **Túnel OpenVPN & PKI**:
   - Autoridade Certificadora X.509 local, aceleração de kernel DCO (Data Channel Offload), revogação instantânea via CRL e download de arquivos `.ovpn`.
6. **Antivírus ClamAV & ICAP**:
   - Varredura de tráfego HTTP/FTP via protocolo ICAP, mitigação contra Zip Bombs, quarentena forense e liberação auditada de falsos positivos.
7. **Governança ISO 27001 & Auditoria**:
   - Gestão de Mudanças obrigatória com revisão de Diff (Controle A.8.32), sincronização de relógio NTP (A.8.17), exportação Syslog TLS (RFC 5424) e snapshots com rollback instantâneo.

---

## 🖥️ Console SPA em 4 Idiomas

Toda a interface de operações NOC/SOC foi desenvolvida em **React 18 + PrimeReact + Vite**, permitindo alternância dinâmica em tempo de execução entre:
- 🇧🇷 **Português (pt-BR)**
- 🇺🇸 **English (en-US)**
- 🇪🇸 **Español (es-ES)**
- 🇫🇷 **Français (fr-FR)**

---

## 🔒 Licença / License

Copyright (C) Astral Software / Astral Corporation. Todos os direitos reservados. Licença Proprietária Comercial.
