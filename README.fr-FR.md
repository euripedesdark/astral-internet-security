# Astral Internet Security

![Licence](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite%20%2B%20PrimeReact-61dafb.svg)
![ISO 27001](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027001-emerald.svg)

**Pare-feu Stateful, NAT, Passerelle Edge, Zero Trust et Antivirus en Rust & React** — Système de sécurité périmétrique haute densité strictement conforme aux contrôles de la norme **ISO/IEC 27001**. Développé en **Rust** (architecture orientée objet avec Tokio et Axum) et interface **React 18** avec PrimeReact dans un thème NOC/SOC sombre.

Licence **GNU AGPL v3**. Voir [`LICENSE.md`](LICENSE.md).

---

## 🛡️ Les 7 Piliers de l'Architecture ISO/IEC 27001

1. **Moteur Pare-feu Stateful:** Suivi des connexions conntrack, politique default deny, ségrégation des zones (WAN, LAN, DMZ, Guest, VPN), anti-spoofing RFC 1918, filtrage bogon, atténuation DoS et blocage GeoIP.
2. **Moteur NAT:** Redirection de ports (DNAT), masquage de sortie (SNAT), NAT 1:1 (Binat), NPTv6, NAT reflection (hairpinning) et assistants ALG (SIP, FTP, PPTP, TFTP).
3. **Passerelle Multi-WAN & Filtrage Web:** Basculement automatique (failover), équilibrage de charge avec sessions persistantes, PBR, QoS FQ_CoDel/Cake, filtrage de sortie et sinkhole DNS RPZ.
4. **Cloudflare Zero Trust (ZTNA):** Connecteur natif cloudflared (tunnel Argo sans ports WAN ouverts), publication ZTNA avec MFA, routage WARP et validation JWT.
5. **Tunnel OpenVPN & PKI:** Gestionnaire d'autorité de certification intégrée, révocation immédiate CRL, accélération DCO dans le noyau, chiffrement AES-256-GCM, MFA TOTP et exportateur `.ovpn`.
6. **Antivirus de Passerelle (ClamAV):** Inspection en continu ICAP via clamd, mises à jour freshclam, coffre-fort de quarantaine chiffré et protection contre les bombes de décompression.
7. **Gouvernance & Conformité ISO 27001:** Gestion des changements avec visualiseur Diff avant application (A.8.32), historique et rollback en 1 clic, console en direct avec Syslog TLS RFC 5424 (A.8.15), synchronisation NTP (A.8.17) et sauvegarde chiffrée (A.8.13).

---

## 🚀 Déploiement Propre en 1 Commande

```bash
./deploy.py
```
Accédez au tableau de bord: `http://<IP-PARE-FEU>:8084/app/`
