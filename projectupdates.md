# Astral Internet Security – Documento de Referência e Atualizações

**Documento Vivo – Versão 2.0**
**Última atualização:** 21 DE OUTUBRO DE 2026

---

## 📅 LINHA DO TEMPO DE ATUALIZAÇÕES

### **21 DE OUTUBRO DE 2026 – Versão 2.0 (Isolamento como Solução Autônoma de Firewall)**
**Desacoplamento do Módulo Astral Internet Security**:
- Projeto isolado da antiga base unificada e consolidado como aplicação autônoma de Firewall Stateful e Gateway.
- **Porta Padronizada**: `:8084` para API REST, streaming WebSocket e console de administração web.
- **Schema Próprio**: Dono exclusivo das migrações de schema `V1__baseline_schema_astral.sql` (tabelas de regras, zonas, NAT, rate limit e threat lists).
- **Sincronização no Boot**: Inicialização limpa com carregamento automático de grupos, proteções, NAT e zonas no iptables.
