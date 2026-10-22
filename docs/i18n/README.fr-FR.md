# Astral Internet Security

![Licence](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![Netfilter](https://img.shields.io/badge/Firewall-Netfilter%20%2F%20eBPF-brightgreen.svg)

**Pare-feu Stateful, Passerelle et Atténuation des Menaces en Rust** — Module de sécurité périmétrique haute performance de l'écosystème Astral, conçu avec une architecture orientée objet en Rust, le runtime Tokio et le serveur Axum.

Distribué sous licence **GNU AGPL v3**. Voir [`LICENSE.md`](LICENSE.md).

---

## 🎯 Fonctionnalités Clés

- **Architecture Orientée Objet en Rust** : Structuration en couches (`domain/`, `service/`, `controller/`), traits asynchrones et dispatch dynamique.
- **Filtrage Stateful & Passerelle** : Inspection de paquets Netfilter/nftables/eBPF, translation d'adresses (NAT/SNAT), et redirection de ports (DNAT).
- **Protection Active & Anti-Abus** : Limitation de débit (Rate Limiting), bannissement automatique (Auto-Ban) et Mode Panique instantané.
- **Console Web Réactive** : Interface SPA moderne avec React 18, Vite et TypeScript supportant 4 langues.

---

## 💖 Soutenir le Projet

**Virement International (Wise):**
- **Bénéficiaire:** Euripedes Batista de Paiva Junior
- **Routing number (Wire / ACH):** `101019628`
- **Numéro de compte:** `215822927677`
- **Banque:** Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States
- **SWIFT / BIC:** `TRWIUS35XXX`
- **PIX (Brésil):** `24adc62c-b073-4587-974d-03fe35f6733f`

---

(c) 2026 Astral Internet Security — **Créé par : Euripedes Batista de Paiva Junior**
