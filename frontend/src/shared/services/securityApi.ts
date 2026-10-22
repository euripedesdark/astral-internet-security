import { api } from './api';
import * as T from '../types/security';

export const SecurityApi = {
  // 1. Firewall
  getFirewallState: () => api<T.FirewallState>('/api/v1/firewall/state'),
  getRules: () => api<T.FirewallRule[]>('/api/v1/firewall/rules'),
  addRule: (rule: Partial<T.FirewallRule>) => api<T.FirewallRule>('/api/v1/firewall/rules', { method: 'POST', body: JSON.stringify(rule) }),
  deleteRule: (id: string) => api<{ deleted: boolean }>(`/api/v1/firewall/rules/${id}`, { method: 'DELETE' }),
  getZones: () => api<T.NetworkZone[]>('/api/v1/firewall/zones'),
  addZone: (zone: T.NetworkZone) => api<T.NetworkZone>('/api/v1/firewall/zones', { method: 'POST', body: JSON.stringify(zone) }),
  getAliases: () => api<T.AliasObject[]>('/api/v1/firewall/aliases'),
  addAlias: (alias: T.AliasObject) => api<T.AliasObject>('/api/v1/firewall/aliases', { method: 'POST', body: JSON.stringify(alias) }),
  deleteAlias: (id: string) => api<{ deleted: boolean }>(`/api/v1/firewall/aliases/${id}`, { method: 'DELETE' }),
  getAntiSpoofing: () => api<T.AntiSpoofingConfig>('/api/v1/firewall/anti-spoofing'),
  setAntiSpoofing: (cfg: T.AntiSpoofingConfig) => api<T.AntiSpoofingConfig>('/api/v1/firewall/anti-spoofing', { method: 'POST', body: JSON.stringify(cfg) }),
  getRateLimiting: () => api<T.RateLimitConfig>('/api/v1/firewall/rate-limiting'),
  setRateLimiting: (cfg: T.RateLimitConfig) => api<T.RateLimitConfig>('/api/v1/firewall/rate-limiting', { method: 'POST', body: JSON.stringify(cfg) }),
  getGeoIp: () => api<T.GeoIpPolicy[]>('/api/v1/firewall/geoip'),
  addGeoIp: (policy: T.GeoIpPolicy) => api<T.GeoIpPolicy>('/api/v1/firewall/geoip', { method: 'POST', body: JSON.stringify(policy) }),
  deleteGeoIp: (id: string) => api<{ deleted: boolean }>(`/api/v1/firewall/geoip/${id}`, { method: 'DELETE' }),
  setPanicMode: (enabled: boolean) => api<{ panicMode: boolean }>('/api/v1/firewall/panic', { method: 'POST', body: JSON.stringify({ enabled }) }),
  getStats: () => api<{ timestamp: string; interfaces: T.InterfaceStat[] }>('/api/v1/firewall/stats'),

  // 2. NAT
  getNatRules: () => api<T.NatRule[]>('/api/v1/nat/rules'),
  addNatRule: (rule: Partial<T.NatRule>) => api<T.NatRule>('/api/v1/nat/rules', { method: 'POST', body: JSON.stringify(rule) }),
  deleteNatRule: (id: string) => api<{ deleted: boolean }>(`/api/v1/nat/rules/${id}`, { method: 'DELETE' }),
  getAlg: () => api<T.AlgConfig>('/api/v1/nat/alg'),
  setAlg: (cfg: T.AlgConfig) => api<T.AlgConfig>('/api/v1/nat/alg', { method: 'POST', body: JSON.stringify(cfg) }),

  // 3. Gateway & Multi-WAN
  getWanLinks: () => api<T.WanLink[]>('/api/v1/gateway/wan-links'),
  updateWanLink: (link: T.WanLink) => api<T.WanLink>('/api/v1/gateway/wan-links', { method: 'POST', body: JSON.stringify(link) }),
  getMultiWan: () => api<T.MultiWanConfig>('/api/v1/gateway/multi-wan'),
  setMultiWan: (cfg: T.MultiWanConfig) => api<T.MultiWanConfig>('/api/v1/gateway/multi-wan', { method: 'POST', body: JSON.stringify(cfg) }),
  getPbr: () => api<T.PbrRule[]>('/api/v1/gateway/pbr'),
  addPbr: (rule: T.PbrRule) => api<T.PbrRule>('/api/v1/gateway/pbr', { method: 'POST', body: JSON.stringify(rule) }),
  deletePbr: (id: string) => api<{ deleted: boolean }>(`/api/v1/gateway/pbr/${id}`, { method: 'DELETE' }),
  getSinkhole: () => api<T.DnsSinkholeConfig>('/api/v1/gateway/dns-sinkhole'),
  setSinkhole: (cfg: T.DnsSinkholeConfig) => api<T.DnsSinkholeConfig>('/api/v1/gateway/dns-sinkhole', { method: 'POST', body: JSON.stringify(cfg) }),
  getQos: () => api<T.QosConfig>('/api/v1/gateway/qos'),
  setQos: (cfg: T.QosConfig) => api<T.QosConfig>('/api/v1/gateway/qos', { method: 'POST', body: JSON.stringify(cfg) }),
  getEgress: () => api<T.EgressFilterConfig>('/api/v1/gateway/egress-filter'),
  setEgress: (cfg: T.EgressFilterConfig) => api<T.EgressFilterConfig>('/api/v1/gateway/egress-filter', { method: 'POST', body: JSON.stringify(cfg) }),

  // 4. Zero Trust
  getTunnelStatus: () => api<T.CloudflareTunnelConfig>('/api/v1/zero-trust/tunnel'),
  getZtnaApps: () => api<T.ZtnaAppPublish[]>('/api/v1/zero-trust/apps'),
  publishZtnaApp: (app: T.ZtnaAppPublish) => api<T.ZtnaAppPublish>('/api/v1/zero-trust/apps', { method: 'POST', body: JSON.stringify(app) }),
  deleteZtnaApp: (id: string) => api<{ deleted: boolean }>(`/api/v1/zero-trust/apps/${id}`, { method: 'DELETE' }),
  getJwtValidator: () => api<T.EdgeJwtValidator>('/api/v1/zero-trust/jwt-validator'),
  setJwtValidator: (cfg: T.EdgeJwtValidator) => api<T.EdgeJwtValidator>('/api/v1/zero-trust/jwt-validator', { method: 'POST', body: JSON.stringify(cfg) }),
  getDoh: () => api<T.DohConfig>('/api/v1/zero-trust/doh'),
  setDoh: (cfg: T.DohConfig) => api<T.DohConfig>('/api/v1/zero-trust/doh', { method: 'POST', body: JSON.stringify(cfg) }),

  // 5. OpenVPN & PKI
  getVpnConfig: () => api<T.OpenVpnConfig>('/api/v1/vpn/config'),
  setVpnConfig: (cfg: T.OpenVpnConfig) => api<T.OpenVpnConfig>('/api/v1/vpn/config', { method: 'POST', body: JSON.stringify(cfg) }),
  getCerts: () => api<T.PkiCert[]>('/api/v1/vpn/certificates'),
  issueCert: (commonName: string, certType: string) => api<T.PkiCert>('/api/v1/vpn/certificates', { method: 'POST', body: JSON.stringify({ commonName, certType }) }),
  revokeCert: (id: string) => api<{ revoked: boolean }>(`/api/v1/vpn/certificates/${id}`, { method: 'DELETE' }),
  getCcdOverrides: () => api<T.ClientSpecificOverride[]>('/api/v1/vpn/overrides'),
  setCcdOverride: (ccd: T.ClientSpecificOverride) => api<T.ClientSpecificOverride>('/api/v1/vpn/overrides', { method: 'POST', body: JSON.stringify(ccd) }),
  exportOvpnProfile: (clientName: string) => api<T.OvpnProfile>(`/api/v1/vpn/export/${clientName}`),

  // 6. Antivirus ClamAV
  getAvStatus: () => api<T.ClamAvStatus>('/api/v1/antivirus/status'),
  triggerAvUpdate: () => api<T.ClamAvStatus>('/api/v1/antivirus/update', { method: 'POST' }),
  getQuarantine: () => api<T.QuarantineItem[]>('/api/v1/antivirus/quarantine'),
  deleteQuarantine: (id: string) => api<{ deleted: boolean }>(`/api/v1/antivirus/quarantine/${id}`, { method: 'DELETE' }),
  getAvLimits: () => api<T.DecompressionLimits>('/api/v1/antivirus/decompression-limits'),
  setAvLimits: (limits: T.DecompressionLimits) => api<T.DecompressionLimits>('/api/v1/antivirus/decompression-limits', { method: 'POST', body: JSON.stringify(limits) }),
  getAvBypass: () => api<T.AntivirusBypass>('/api/v1/antivirus/bypass'),
  setAvBypass: (bypass: T.AntivirusBypass) => api<T.AntivirusBypass>('/api/v1/antivirus/bypass', { method: 'POST', body: JSON.stringify(bypass) }),

  // 7. Compliance & Governance
  getAuditLogs: () => api<T.AuditLogEntry[]>('/api/v1/compliance/audit-logs'),
  getSyslog: () => api<T.SyslogRemoteConfig>('/api/v1/compliance/syslog'),
  setSyslog: (cfg: T.SyslogRemoteConfig) => api<T.SyslogRemoteConfig>('/api/v1/compliance/syslog', { method: 'POST', body: JSON.stringify(cfg) }),
  getNtpStatus: () => api<T.NtpStatus>('/api/v1/compliance/ntp'),
  getSnapshots: () => api<T.ConfigSnapshot[]>('/api/v1/compliance/snapshots'),
  createSnapshot: (author: string, description: string) => api<T.ConfigSnapshot>('/api/v1/compliance/snapshots', { method: 'POST', body: JSON.stringify({ author, description }) }),
  rollbackSnapshot: (id: string) => api<{ rollback: boolean }>(`/api/v1/compliance/snapshots/${id}/rollback`, { method: 'POST' }),
  getBackupStatus: () => api<T.BackupStatus>('/api/v1/compliance/backup'),
  triggerBackup: () => api<T.BackupStatus>('/api/v1/compliance/backup', { method: 'POST' }),
};
