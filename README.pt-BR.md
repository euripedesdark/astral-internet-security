# Astral Internet Security — Documentação (Português)

![Licença](https://img.shields.io/badge/License-Proprietária-red.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![ISO 27001](https://img.shields.io/badge/Security-ISO%2FIEC%2027001-blue.svg)
![i18n](https://img.shields.io/badge/i18n-4%20Idiomas-green.svg)

Gateway de Borda e Segurança Perimetral Corporativa de Alta Performance em Rust, estruturado com base nas normas ISO/IEC 27001:2022.

---

## Arquitetura dos 7 Módulos de Segurança

1. **Firewall Stateful (SPI & Zonas)**:
   - Filtragem de pacotes com rastreamento de conexões (Conntrack).
   - Bloqueio de pacotes spoofados e redes Bogon (RFC 1918) na WAN.
   - Mitigação de SYN Flood, ICMP Flood e UDP Flood com limitação adaptativa.
   - Filtro geográfico GeoIP por país e direção.
2. **Motor de NAT & Encaminhamento**:
   - DNAT (Port Forwarding), SNAT Masquerade, mapeamento estático 1:1 e NPTv6.
   - NAT Loopback / Hairpinning para acesso interno via IP público.
   - Suporte a ALGs para SIP, FTP, TFTP e PPTP.
3. **Gateway Multi-WAN & Web Filter**:
   - Monitoramento de saúde dos links WAN (RTT, Jitter, Perda de Pacotes).
   - Comutação transparente em caso de falha (Failover) e balanceamento ponderado.
   - Roteamento por políticas (PBR) e modelagem de tráfego QoS.
   - DNS Sinkhole para retenção de chamadas a servidores de comando e controle (C2).
4. **Cloudflare Zero Trust (ZTNA)**:
   - Túnel Argo `cloudflared` bidirecional sem portas de entrada abertas.
   - Asserção de tokens JWT para validação de identidade em borda.
   - Resolução de DNS criptografada (DoH / DoT).
5. **OpenVPN & Gerenciador PKI**:
   - Emissão e revogação de certificados digitais X.509 locais.
   - Aceleração por módulo de kernel DCO para throughput gigabit.
   - Exportação de perfis de conexão `.ovpn` completos.
6. **Antivírus ClamAV & ICAP**:
   - Inspeção em streaming via ICAP Bridge.
   - Atualização automática de assinaturas Freshclam.
   - Quarentena forense e mitigação de bombas de descompactação.
7. **Governança ISO 27001 & Auditoria**:
   - Gestão de Mudanças (Controle A.8.32): nenhuma regra é aplicada sem justificativa técnica e registro do operador.
   - Snapshots de configuração com rollback instantâneo de segurança.
   - Sincronização estrita de horário via NTP (Controle A.8.17).
   - Exportador Syslog TLS com padrão RFC 5424 para ingestão em SIEM corporativo.

---

## Interface Web NOC/SOC Multilíngue

Console React 18 com suporte nativo e completo a 4 idiomas:
- Português (pt-BR)
- English (en-US)
- Español (es-ES)
- Français (fr-FR)

---

## Licença

Copyright (C) Astral Software. Todos os direitos reservados. Licença Proprietária Comercial.

## 🔐 Política Unificada de Acesso e Autenticação

O **Astral Internet Security** implementa a política unificada de autenticação e governança do ecossistema Astral:

1. **OAuth2 / Samba Active Directory / Postgres**:
   - Autenticação federada orquestrada via `astral-auth-service` (`http://127.0.0.1:8181`). Operadores do domínio Samba AD com privilégios de rede/firewall são autorizados com mapeamento LDAP.
2. **Via `auth-service` (SSO)**:
   - Validação direta de cabeçalhos `Authorization: Bearer <token>` e cookies de sessão (`sso_token` e `astral_token`) assinados com o segredo compartilhado (`AUTH_TOKEN_SECRET` em `/etc/auth-service/auth.env`).
3. **Usuário Local Linux (`root` ou `sudo`)**:
   - Autenticação do sistema operacional validando se o usuário é `root` ou membro dos grupos `wheel` ou `sudo`.
4. **Superusuário PostgreSQL**:
   - Acesso administrativo para qualquer conta PostgreSQL com `rolsuper = true` (ex: `postgres`).

### 🌐 Multi-WAN (1 a 10 Links) & Roteador Wi-Fi (AP)
- **Configuração Declarativa Multi-WAN**: Seleção de 1 a 10 links WAN com opção de manter configurações ou reconfigurar, aplicando Masquerade sem limpar regras de portas.
- **Roteador Wi-Fi Hotspot**: Detecção automática de placas wireless e modo AP para criação de SSID, criptografia WPA2/WPA3, DHCP integrado e roteamento de borda.
