# Astral Internet Security — Documentation (Français)

![Licence](https://img.shields.io/badge/License-Propriétaire-red.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![ISO 27001](https://img.shields.io/badge/Security-ISO%2FIEC%2027001-blue.svg)
![i18n](https://img.shields.io/badge/i18n-4%20Langues-green.svg)

Passerelle de Sécurité Périmétrique Haute Performance en Rust, conçue selon les exigences de la norme ISO/IEC 27001:2022.

---

## 7 Modules de Sécurité

1. **Moteur Pare-feu Stateful (SPI & Zones)**:
   - Suivi d'état des connexions en temps réel (Conntrack).
   - Protection Anti-Spoofing et filtrage Bogon (RFC 1918).
   - Atténuation DoS/DDoS adaptative (SYN, ICMP, UDP Flood) et filtrage GeoIP.
2. **Moteur NAT & Redirection**:
   - DNAT (Port Forwarding), SNAT Masquerade, NAT statique 1:1 et NPTv6.
   - NAT Hairpinning pour accès interne via IP publique.
   - Prise en charge des ALGs (SIP, FTP, TFTP, PPTP).
3. **Passerelle Multi-WAN & Filtrage Web**:
   - Surveillance de la santé des liens WAN avec basculement automatique (Failover).
   - Routage basé sur des politiques (PBR) et QoS Cake.
   - Sinkhole DNS neutralisant les connexions de botnets vers les centres C2.
4. **Cloudflare Zero Trust (ZTNA)**:
   - Connecteur Argo Tunnel (`cloudflared`) natif sans port d'entrée ouvert.
   - Validation des assertions JWT et résolution DNS sécurisée (DoH).
5. **OpenVPN & Gestionnaire PKI**:
   - Autorité de Certification locale X.509 avec révocation CRL instantanée.
   - Accélération DCO dans le noyau Linux et téléchargement de profils `.ovpn`.
6. **Antivirus ClamAV & ICAP**:
   - Analyse de flux via protocole ICAP et mise à jour Freshclam.
   - Quarantaine judiciaire et prévention des bombes de décompression.
7. **Gouvernance ISO 27001 & Audit**:
   - Gestion des Changements (Contrôle A.8.32) avec revue de Diff et justification requise.
   - Instantanés de configuration avec restauration d'urgence (Rollback).
   - Synchronisation d'horloge NTP (Contrôle A.8.17) et transfert Syslog TLS vers SIEM.

---

## Console NOC/SOC en 4 Langues

Interface SPA React 18 avec prise en charge dynamique de 4 langues :
- Français (fr-FR)
- Portugais (pt-BR)
- Anglais (en-US)
- Espagnol (es-ES)

---

## Licence

Copyright (C) Astral Software. Tous droits réservés. Licence Commerciale Propriétaire.

### 🌐 Multi-WAN (1 à 10 Liens) et Routeur Wi-Fi (AP)
- **Configuration Déclarative Multi-WAN**: Sélection de 1 à 10 liens WAN avec option de conserver les configurations ou reconfigurer, réappliquant le Masquerade sans effacer les règles de ports.
- **Routeur Wi-Fi Hotspot**: Détection automatique des interfaces sans fil et mode AP pour la création de SSID, chiffrement WPA2/WPA3, DHCP intégré et routage de périphérie.
