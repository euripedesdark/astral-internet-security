# Astral Internet Security

![Licencia](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![Netfilter](https://img.shields.io/badge/Firewall-Netfilter%20%2F%20eBPF-brightgreen.svg)

**Firewall Stateful, Gateway y Mitigación de Amenazas en Rust** — Módulo de seguridad perimetral de alto rendimiento del ecosistema Astral, desarrollado con arquitectura orientada a objetos en Rust, runtime Tokio y framework Axum.

Consulte [`LICENSE.md`](LICENSE.md) para la licencia **GNU AGPL v3**.

---

## 🎯 Características Principales

- **Arquitectura Orientada a Objetos en Rust**: Separación estricta en capas (`domain/`, `service/`, `controller/`), polimorfismo mediante traits dinámicos e inyección de dependencias.
- **Firewall Stateful**: Control de flujo de paquetes en tablas `filter`, `nat` y `mangle` mediante Netfilter y eBPF.
- **Gestión de Zonas y Gateway**: Zonas WAN, LAN, DMZ con NAT automático (Masquerade) y redirección de puertos (DNAT).
- **Protección Activa**: Políticas de Rate Limiting, Auto-Ban y Modo de Pánico para contingencias.
- **Consola Web**: Panel en React 18, Vite y TypeScript con soporte multilíngüe.

---

## 💖 Apoye el Proyecto

**Transferencia Internacional (Wise):**
- **Titular:** Euripedes Batista de Paiva Junior
- **Routing number (Wire / ACH):** `101019628`
- **Número de cuenta:** `215822927677`
- **Banco:** Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States
- **SWIFT / BIC:** `TRWIUS35XXX`
- **PIX (Brasil):** `24adc62c-b073-4587-974d-03fe35f6733f`

---

(c) 2026 Astral Internet Security — **Creado por: Euripedes Batista de Paiva Junior**
