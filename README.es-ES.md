# Astral Internet Security — Documentación (Español)

![Licencia](https://img.shields.io/badge/License-Propietaria-red.svg)
![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)
![ISO 27001](https://img.shields.io/badge/Security-ISO%2FIEC%2027001-blue.svg)
![i18n](https://img.shields.io/badge/i18n-4%20Idiomas-green.svg)

Gateway de Borde y Seguridad Perimetral de Alto Rendimiento en Rust, diseñado en conformidad con la norma ISO/IEC 27001:2022.

---

## 7 Módulos de Seguridad

1. **Motor de Firewall Stateful (SPI & Zonas)**:
   - Inspección profunda con seguimiento de conexiones (Conntrack).
   - Bloqueo de paquetes falsificados (Anti-Spoofing) y redes Bogon (RFC 1918).
   - Mitigación DoS adaptativa contra inundaciones SYN, ICMP y UDP.
   - Filtrado geográfico GeoIP por país y dirección de tráfico.
2. **Motor de NAT & Reenvío**:
   - DNAT (Port Forwarding), SNAT Masquerade, NAT 1:1 estático y NPTv6.
   - Loopback / Hairpinning para resolución interna de IPs públicas.
   - Soporte para Application Layer Gateways (ALGs).
3. **Gateway Multi-WAN & Filtro Web**:
   - Supervisión activa de enlaces WAN con conmutación por error (Failover).
   - Balanceo de carga y Enrutamiento Basado en Políticas (PBR).
   - Moldeado de tráfico QoS y DNS Sinkhole contra botnets C2.
4. **Cloudflare Zero Trust (ZTNA)**:
   - Túnel Argo `cloudflared` bidireccional sin puertos abiertos de entrada.
   - Validación criptográfica de tokens JWT y resolución DNS segura (DoH).
5. **Túnel OpenVPN y Gestor PKI**:
   - Autoridad Certificadora local con revocación CRL inmediata.
   - Aceleración en kernel DCO y descarga de perfiles `.ovpn`.
6. **Antivirus ClamAV & ICAP**:
   - Escaneo en flujo continuo mediante protocolo ICAP.
   - Actualización continua de firmas Freshclam y aislamiento en cuarentena.
7. **Gobernanza ISO 27001 y Auditoría**:
   - Gestión de Cambios (Control A.8.32) con revisión de Diff y justificación obligatoria.
   - Snapshots de configuración con rollback inmediato.
   - Sincronización NTP (Control A.8.17) y exportación Syslog TLS para SIEM.

---

## Consola NOC/SOC en 4 Idiomas

Interfaz SPA desarrollada en React 18 con soporte completo para:
- Español (es-ES)
- Portugués (pt-BR)
- Inglés (en-US)
- Francés (fr-FR)

---

## Licencia

Copyright (C) Astral Software. Todos los derechos reservados. Licencia Comercial Propietaria.
