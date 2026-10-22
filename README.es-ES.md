# Astral Internet Security

![Licencia](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite%20%2B%20PrimeReact-61dafb.svg)
![ISO 27001](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027001-emerald.svg)

**Firewall Stateful, NAT, Gateway de Borde, Zero Trust y Antivirus en Rust & React** — Sistema de seguridad perimetral de alta densidad alineado estrictamente con los controles de la norma **ISO/IEC 27001**. Desarrollado en **Rust** (arquitectura orientada a objetos con Tokio y Axum) y frontend **React 18** con PrimeReact en tema NOC/SOC oscuro.

Licencia **GNU AGPL v3**. Consulte [`LICENSE.md`](LICENSE.md).

---

## 🛡️ Los 7 Pilares de la Arquitectura ISO/IEC 27001

1. **Motor de Firewall Stateful:** Conntrack SPI, política default deny, segregación de zonas (WAN, LAN, DMZ, Guest, VPN), reglas granulares, anti-spoofing RFC 1918, filtrado bogon, mitigación DoS y bloqueo GeoIP.
2. **Motor de NAT:** Port forwarding (DNAT), mascarada de salida (SNAT), NAT 1:1 (Binat), NPTv6, NAT reflection (hairpinning) y helpers ALG (SIP, FTP, PPTP, TFTP).
3. **Gateway Multi-WAN y Filtrado Web:** Conmutación por error automática (failover), balanceo de carga con sesiones persistentes, PBR, QoS FQ_CoDel/Cake, filtrado de salida (egress) y sinkhole DNS RPZ.
4. **Cloudflare Zero Trust (ZTNA):** Conector cloudflared integrado (túnel Argo sin puertos WAN abiertos), publicación ZTNA con MFA, enrutamiento WARP y validación JWT.
5. **Túnel OpenVPN y PKI:** CA integrada, revocación inmediata por CRL, aceleración DCO en kernel, cifrado AES-256-GCM, MFA TOTP y exportador de perfil unificado `.ovpn`.
6. **Antivirus de Gateway (ClamAV):** Inspección ICAP en streaming, actualizaciones freshclam, bóveda de cuarentena cifrada y protección contra bombas de descompresión.
7. **Gobernanza y Auditoría ISO 27001:** Gestión de cambios con visor Diff antes de aplicar (A.8.32), historial y rollback en 1 clic, consola live tail con exportación Syslog TLS RFC 5424 (A.8.15), sincronización NTP (A.8.17) y copias de seguridad cifradas (A.8.13).

---

## 🚀 Despliegue Limpio en 1 Comando

```bash
./deploy.py
```
Acceda a la interfaz en: `http://<IP-FIREWALL>:8084/app/`
