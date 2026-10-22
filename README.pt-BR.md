# Astral Internet Security

![Licença](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B%20%2F%20OOP-orange.svg)
![Axum](https://img.shields.io/badge/Axum-0.8-blue.svg)
![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-brightgreen.svg)
![Netfilter](https://img.shields.io/badge/Firewall-Netfilter%20%2F%20eBPF-brightgreen.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite%20%2B%20PrimeReact-61dafb.svg)
![ISO 27001](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027001-emerald.svg)

**Firewall Stateful, NAT, Gateway de Borda, Zero Trust e Antivírus em Rust & React** — Sistema corporativo de alta densidade e segurança perimetral alinhado rigorosamente aos controles da **ISO/IEC 27001**. Implementado em **Rust** (arquitetura Orientada a Objetos com Tokio e Axum) e interface **React 18** com PrimeReact em tema NOC/SOC dark de alta densidade.

Este projeto está sob **GNU AGPL v3**. Ver [`LICENSE.md`](LICENSE.md).

---

## 🛡️ Os 7 Pilares da Arquitetura ISO/IEC 27001

### 1. Motor de Firewall Stateful (Filtragem & Controle de Tráfego)
*Alinhado a: A.8.20 (Segurança de redes), A.8.21 (Segurança dos serviços de rede), A.8.22 (Segregação de redes)*
- **Inspeção Stateful (SPI):** Rastreamento de conexões ativas via tabela de estados (`conntrack`), permitindo apenas pacotes de retorno legítimos.
- **Política Default Deny:** Bloqueio implícito de todo tráfego de entrada e passagem sem regra de liberação prévia.
- **Segregação de Zonas:** Isolamento lógico e físico entre WAN, LAN, DMZ, Guest e VPN/ZTNA.
- **Regras Granulares:** Filtragem por IP, CIDR, MAC, protocolo, porta, direção (IN/OUT/FORWARD) e agendamento.
- **Proteções DoS & Bogon:** Anti-Spoofing (descarte incondicional de RFC 1918 na WAN), descarte de bogons não alocados da IANA e mitigação de SYN/UDP flood.
- **Bloqueio GeoIP:** Restrição geográfica por país de origem do endereço IP.

### 2. Motor de NAT (Network Address Translation)
*Alinhado a: A.8.20 (Ocultação da topologia interna) e A.8.22*
- **DNAT / Port Forwarding:** Redirecionamento de portas WAN para IPs da LAN/DMZ com filtro restritivo de origem.
- **SNAT / Masquerading:** Tradução dinâmica de múltiplos IPs internos para saída WAN.
- **NAT 1:1 (Binat) & NPTv6:** Mapeamento estático bidirecional e tradução de prefixos IPv6 ULA para GUA.
- **NAT Reflection (Hairpinning) & ALGs:** Acesso local via IP público e controle restrito de helpers ALG (SIP, FTP, PPTP, TFTP).

### 3. Gateway de Acesso, Multi-WAN & Filtragem Web
*Alinhado a: A.8.14 (Redundância), A.8.23 (Filtragem Web), A.8.6 (Gestão de capacidade)*
- **Multi-WAN Inteligente:** Failover automático em milissegundos e Load Balancing ponderado com sessões persistentes (*Sticky Connections*).
- **Policy-Based Routing (PBR):** Roteamento condicional de sub-redes e aplicações para links específicos.
- **QoS & Traffic Shaping:** Algoritmos modernos de fila `FQ_CoDel` e `Cake` para mitigação de Bufferbloat e priorização de ERP e VoIP.
- **Egress Filtering & DNS Sinkhole:** Bloqueio por padrão de portas de saída na LAN e sinkhole RPZ de domínios C2, malware e phishing.

### 4. Integração Cloudflare Zero Trust (ZTNA)
*Alinhado a: A.5.15 (Controle de acesso), A.8.5 (Autenticação segura), A.8.21*
- **Conector Nativo cloudflared (Argo Tunnel):** Túnel de saída criptografado eliminando a necessidade de portas abertas na WAN.
- **Publicação ZTNA:** Mapeamento de ERPs e serviços internos para subdomínios protegidos pelo Cloudflare Access com MFA obrigatório.
- **Validação de Token JWT:** Verificação no gateway do header criptográfico `Cf-Access-Jwt-Assertion`.
- **DoH / DoT Gateway:** Resolução segura de consultas DNS para a nuvem Zero Trust.

### 5. Túnel VPN Compatível com OpenVPN & PKI
*Alinhado a: A.8.24 (Criptografia) e A.6.7 (Trabalho remoto)*
- **Criptografia Forte:** Kernel Data Channel Offload (DCO), cifras AES-256-GCM / ChaCha20-Poly1305 e TLS 1.3.
- **Gerenciador de PKI Integrado:** Autoridade Certificadora local, certificados de cliente/servidor e revogação instantânea via CRL.
- **MFA e CCD:** Autenticação combinada com TOTP e Client-Specific Overrides (IPs fixos por usuário).
- **Exportador 1-Clique:** Geração de arquivo unificado `.ovpn` com certificados embutidos inline.

### 6. Antivírus de Gateway (ClamAV & ICAP)
*Alinhado a: A.8.7 (Proteção contra malware)*
- **Streaming ICAP:** Daemon `clamd` integrado via protocolo ICAP para inspeção em tempo real de downloads/uploads na memória.
- **freshclam com Feeds Estendidos:** Atualização automática de assinaturas oficiais e comunitárias (URLhaus, Sanesecurity).
- **Cofre de Quarentena Criptografada:** Isolamento seguro de artefatos suspeitos com liberação auditável de falsos positivos.
- **Proteção contra Zip Bombs:** Limites estritos de recursão, tamanho máximo de stream e timeout de descompactação.

### 7. Governança, Auditoria e Conformidade ISO/IEC 27001
- **Gestão de Mudanças (A.8.32):** Barra flutuante de alterações pendentes exigindo justificativa técnica e exibindo Diff (Antes vs Depois) antes de aplicar.
- **Histórico e Rollback (A.8.32):** Snapshots imutáveis de versão com restauração em 1 clique.
- **Alertas Visuais de Risco (A.8.20):** Badges semânticos de não conformidade para regras inseguras (ex: ANY na WAN ou SSH exposto).
- **Live Tail & Syslog TLS (A.8.15):** Console em tempo real e exportação RFC 5424 TLS para SIEMs externos.
- **NTP Auditado (A.8.17):** Sincronismo temporal com estrato primário e alerta de desvio no topo da tela.
- **Backup Criptografado (A.8.13):** Exportação completa protegida por senha e criptografia forte.

---

## 🚀 Compilação e Deploy com 1 Comando

Para compilar o frontend React/Vite, efetuar compilação limpa em Rust (release), publicar no diretório do sistema e reiniciar o serviço:

```bash
./deploy.py
```

Acesse a interface operacional em: `http://<IP-DO-FIREWALL>:8084/app/`
