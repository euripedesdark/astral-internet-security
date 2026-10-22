# Astral Internet Security

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![Netfilter](https://img.shields.io/badge/Firewall-Netfilter%20%2F%20eBPF-brightgreen.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61dafb.svg)

🇧🇷 **Next-Generation Firewall (NGFW), Stateful Packet Inspection (SPI) e Segurança de Borda em Rust** — Módulo corporativo de alta performance do ecossistema Astral responsável pela segurança de rede perimetral, controle de fluxo de pacotes, NAT/Port Forwarding, auto-ban, e mitigação ativa de ameaças, construído com arquitetura Orientada a Objetos em Rust assíncrono.

🇺🇸 **Next-Generation Firewall (NGFW), Stateful Packet Inspection (SPI) and Edge Security in Rust** — High-performance enterprise module of the Astral ecosystem responsible for perimeter network security, packet flow control, NAT/Port Forwarding, auto-ban, and active threat mitigation, built with Object-Oriented Architecture in asynchronous Rust.

---

## 🌐 Escolha o seu idioma / Choose your language

| | Idioma / Language | Documentação / Documentation |
|---|---|---|
| 🇧🇷 | **Português (Brasil)** | [README.pt-BR.md](README.pt-BR.md) |
| 🇺🇸 | **English** | [README.en-US.md](README.en-US.md) |
| 🇪🇸 | **Español** | [README.es-ES.md](README.es-ES.md) |
| 🇫🇷 | **Français** | [README.fr-FR.md](README.fr-FR.md) |

🇧🇷 [Português](README.pt-BR.md) · 🇺🇸 [English](README.en-US.md) · 🇪🇸 [Español](README.es-ES.md) · 🇫🇷 [Français](README.fr-FR.md)

---

## 🎯 Principais Recursos / Core Highlights

- **Arquitetura Orientada a Objetos em Rust**:
  - Modelagem rica de domínio (`domain/`), separação em serviços (`service/`) e controladores (`controller/`) com injeção de dependências via traits e dynamic dispatch (`Arc<dyn FirewallService>`).
  - Runtime assíncrono Tokio com servidor HTTP/REST Axum 0.8.
- **Firewall Stateful e Controle de Borda**:
  - Manipulação declarativa e auditável de tabelas `filter`, `nat` e `mangle` do Linux (Netfilter/nftables/eBPF).
  - Definição flexível de zonas de rede (WAN, LAN, DMZ, isoladas) e mapeamento dinâmico de interfaces.
  - Grupos de hosts (CIDR) e grupos de portas para reuso limpo e modular de regras.
- **NAT, Gateway e Port Forwarding**:
  - Port Forwarding (DNAT) para publicação de serviços internos.
  - Masquerade automático (SNAT) para saída à Internet com roteamento balanceado.
- **Mitigação Ativa e Proteção Contra Abusos**:
  - Rate Limiting e Auto-Ban em tempo real contra varreduras de porta e ataques DoS.
  - Modo Pânico com bloqueio instantâneo de pacotes não essenciais em emergências de segurança.
  - Histórico de snapshots de regras com capacidade de reversão instantânea (rollback).
- **Interface Web Moderna**:
  - Single Page Application (SPA) em React 18, Vite e TypeScript com suporte nativo aos 4 idiomas (PT, EN, ES, FR).

---

## 💖 Apoie o Projeto / Support the Project

Astral Internet Security é um projeto Open Source mantido por um único desenvolvedor independente.

Se este projeto ajudou você, sua infraestrutura ou sua empresa, considere apoiar o desenvolvimento:

### Brasil (PIX)

```text
24adc62c-b073-4587-974d-03fe35f6733f
```

### Internacional (Wise)

| Campo | Dados |
|---|---|
| **Beneficiário / Name** | Euripedes Batista de Paiva Junior |
| **Tipo de conta / Account Type** | Checking |
| **Routing Number (Wire & ACH)** | `101019628` |
| **Número da conta / Account Number** | `215822927677` |
| **Banco / Bank Name** | Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States |
| **SWIFT / BIC** | `TRWIUS35XXX` |

Instruções completas de apoio: [DONATE.md](DONATE.md).

---

## 📄 Licença / License

Distribuído sob a licença **GNU Affero General Public License v3.0 (AGPLv3)**. Consulte [LICENSE.md](LICENSE.md).

(c) 2026 Astral Internet Security — **Criado por: Euripedes Batista de Paiva Junior**
