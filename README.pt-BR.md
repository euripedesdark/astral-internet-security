# Astral Internet Security

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![Netfilter](https://img.shields.io/badge/Firewall-Netfilter%20%2F%20eBPF-brightgreen.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61dafb.svg)

**Firewall Stateful, Gateway e Mitigação de Ameaças em Rust** — Módulo corporativo de segurança perimetral do ecossistema Astral. Implementado em Rust com arquitetura Orientada a Objetos, runtime Tokio e servidor Axum, provendo controle de fluxo de pacotes, NAT, isolamento de zonas e proteção em tempo real.

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🎯 Principais Recursos

- **Arquitetura Orientada a Objetos em Rust**:
  - Separação em camadas: Entidades e Objetos de Domínio (`domain/`), Serviços com Traits assíncronas (`service/`), e Controladores de API (`controller/`).
  - Polimorfismo e encapsulamento com `Arc<dyn FirewallService>` e `Arc<dyn SystemExecutor>`.
- **Gerenciamento de Regras Stateful**:
  - Manipulação auditável de tabelas `filter`, `nat` e `mangle` do Linux via Netfilter / nftables / eBPF.
  - Definição de zonas de rede (WAN, LAN, DMZ, isoladas) e associação dinâmica com interfaces de rede.
  - Grupos de hosts (CIDR) e grupos de portas para composição modular de políticas.
- **NAT e Redirecionamento de Portas (Gateway)**:
  - Port Forwarding (DNAT) para servidores internos.
  - Masquerade automático (SNAT) para saída transparente à Internet.
- **Proteção e Resposta a Incidentes**:
  - Políticas de **Rate Limiting** para prevenção de Denial of Service (DoS).
  - Regras de **Auto-Ban** contra tentativas reiteradas de intrusão e escaneamento.
  - **Modo Pânico**: Acionamento instantâneo que bloqueia todo tráfego não essencial em caso de ataque.
  - Snapshots de regras e histórico com capacidade de rollback rápido.
- **Frontend SPA Moderno**:
  - Painel de administração em React 18, Vite e TypeScript com i18n nativo para 4 idiomas.

---

## 🏗️ Estrutura do Projeto

```
astral-internet-security/
├── Cargo.toml                                # Manifest Rust (Axum, Tokio, Serde, Tower, Tracing)
├── Cargo.lock                                # Lockfile de dependências Rust
├── src/
│   ├── main.rs                               # Ponto de entrada da aplicação
│   ├── server.rs                             # Configuração do servidor HTTP Axum
│   ├── domain/                               # Modelos de domínio e tipos fortemente tipados
│   ├── service/                              # Camada de serviços (traits e implementações)
│   ├── controller/                           # Controladores de rotas REST
│   └── config/                               # Carregamento de configurações
├── frontend/                                 # Painel de Controle SPA (React + TypeScript + Vite)
├── scripts/                                  # Scripts auxiliares de rede e observabilidade
├── docs/                                     # Documentação técnica e guias i18n
├── LICENSE.md                                # Licença GNU AGPLv3
└── DONATE.md                                 # Dados de apoio e doações
```

---

## 🛠️ Stack Tecnológica

| Camada | Tecnologia | Finalidade |
|---|---|---|
| **Linguagem Principal** | Rust 1.80+ (Edition 2021/2024) | Performance nativa, segurança de memória e concorrência sem race conditions |
| **Design Pattern** | Orientado a Objetos (OOP) | Encapsulamento, domain traits, dynamic dispatch e inversão de controle |
| **Framework Web** | Axum 0.8 + Tower | Roteamento assíncrono de alto desempenho |
| **Runtime Assíncrono** | Tokio 1.x (Full) | Event loop de alta escalabilidade I/O-bound |
| **Filtragem de Pacotes** | Linux Netfilter / nftables / eBPF | Inspeção de pacotes no kernel e manipulação de tabelas IP |
| **Frontend** | React 18, TypeScript, Vite | Interface web reativa com suporte a i18n |

---

## 🚀 Como Executar

### Pré-requisitos
- Rust 1.80+ (`cargo`, `rustc`)
- Node.js 20+ e npm (para o frontend)
- Linux com privilégios de `sudo` para manipulação de regras de firewall

### Compilação e Execução
```bash
# Compilar o backend em Rust
cargo build --release

# Executar o serviço
sudo ./target/release/astral-internet-security
```

---

## 💖 Apoie o Projeto

Astral Internet Security é mantido por um único desenvolvedor independente. Se este projeto ajudou você ou sua empresa, considere apoiar:

**PIX:**
```text
24adc62c-b073-4587-974d-03fe35f6733f
```

### Transferência Internacional (Wise)

| | |
|---|---|
| **Nome** | Euripedes Batista de Paiva Junior |
| **Tipo de conta** | Checking |
| **Routing number (wire e ACH)** | `101019628` |
| **Número da conta** | `215822927677` |
| **Banco** | Wise US Inc, 108 W 13th St, Wilmington, DE, 19801, United States |
| **SWIFT/BIC** | `TRWIUS35XXX` |

---

## 📄 Licença

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

(c) 2026 Astral Internet Security — **Criado por: Euripedes Batista de Paiva Junior**
