export type ZoneType = 'WAN' | 'LAN' | 'DMZ' | 'Guest' | 'VpnZtna';

export interface NetworkZone {
  name: string;
  zoneType: ZoneType;
  interfaces: string[];
  defaultPolicy: string;
  description: string;
}

export interface TimeSchedule {
  id: string;
  name: string;
  daysOfWeek: number[];
  startTime: string;
  endTime: string;
}

export interface AliasObject {
  id: string;
  name: string;
  aliasType: 'Host' | 'Network' | 'Port' | 'Url';
  entries: string[];
  description: string;
}

export interface FirewallRule {
  id: string;
  name: string;
  zone: string;
  protocol: string;
  port: string;
  action: 'ACCEPT' | 'DROP' | 'REJECT';
  direction: 'IN' | 'OUT' | 'FORWARD';
  sourceIp?: string;
  destinationIp?: string;
  sourceMac?: string;
  schedule?: TimeSchedule;
  enabled: boolean;
  createdAt: string;
  logEnabled?: boolean;
  hits?: number;
  bytes?: number;
}

export interface AntiSpoofingConfig {
  blockRfc1918OnWan: boolean;
  blockIanaUnallocated: boolean;
  enabled: boolean;
}

export interface RateLimitConfig {
  synFloodRate: number;
  icmpFloodRate: number;
  udpFloodRate: number;
  maxConnPerIp: number;
  enabled: boolean;
}

export interface GeoIpPolicy {
  id: string;
  countryCode: string;
  action: 'ALLOW' | 'BLOCK';
  direction: 'IN' | 'OUT';
  enabled: boolean;
}

export interface FirewallState {
  panicMode: boolean;
  defaultPolicy: string;
  rulesCount: number;
  activeConnections: number;
  conntrackEntries: number;
  lastSynced: string;
  spiTrackingActive: boolean;
}

export interface InterfaceStat {
  name: string;
  rxBytes: number;
  txBytes: number;
}

export type NatType = 'SnatMasquerade' | 'DnatPortForward' | 'BinatOneToOne' | 'NatReflection' | 'Nptv6Prefix';

export interface NatRule {
  id: string;
  name: string;
  natType: NatType;
  originalIp?: string;
  originalPort: string;
  destinationIp: string;
  destinationPort: string;
  interface: string;
  protocol: string;
  enabled: boolean;
}

export interface AlgConfig {
  sipEnabled: boolean;
  ftpEnabled: boolean;
  pptpEnabled: boolean;
  tftpEnabled: boolean;
}

export interface WanLink {
  id: string;
  name: string;
  interface: string;
  gatewayIp: string;
  weight: number;
  isPrimary: boolean;
  isActive: boolean;
  latencyMs: number;
  packetLossPct: number;
}

export interface MultiWanConfig {
  mode: 'Failover' | 'LoadBalanceWeighted' | 'RoundRobin';
  stickyConnections: boolean;
  probeTargets: string[];
  checkIntervalSecs: number;
}

export interface PbrRule {
  id: string;
  name: string;
  sourceNetwork: string;
  destinationPort?: string;
  protocol: string;
  targetGateway: string;
  enabled: boolean;
}

export interface DnsSinkholeConfig {
  rpzEnabled: boolean;
  blockC2: boolean;
  blockPhishing: boolean;
  blockMalware: boolean;
  totalQueries: number;
  blockedQueries: number;
}

export interface QosConfig {
  algorithm: 'FQ_CoDel' | 'Cake';
  erpPriority: boolean;
  voipPriority: boolean;
  downloadBandwidthMbps: number;
  uploadBandwidthMbps: number;
  enabled: boolean;
}

export interface EgressFilterConfig {
  defaultDenyEgress: boolean;
  allowedPorts: number[];
  enabled: boolean;
}

export interface CloudflareTunnelConfig {
  tunnelId: string;
  tunnelName: string;
  status: string;
  activeConnectors: number;
  ingressRulesCount: number;
  tunnelToken?: string;
}

export interface ZtnaAppPublish {
  id: string;
  hostname: string;
  internalServiceUrl: string;
  requireMfa: boolean;
}

export interface EdgeJwtValidator {
  enabled: boolean;
  teamDomain: string;
  audienceTag: string;
}

export interface DohConfig {
  dohUrl: string;
  dotFallback: boolean;
  enabled: boolean;
}

export interface OpenVpnConfig {
  mode: 'SiteToSite' | 'RoadWarrior';
  port: number;
  protocol: 'UDP' | 'TCP';
  cipher: string;
  tlsVersion: string;
  dcoEnabled: boolean;
  splitTunnel: boolean;
  subnet: string;
  mfaRequired: boolean;
}

export interface PkiCert {
  id: string;
  commonName: string;
  certType: 'CA' | 'Server' | 'Client';
  createdAt: string;
  expiresAt: string;
  revoked: boolean;
  serial: string;
}

export interface ClientSpecificOverride {
  clientName: string;
  assignedIp: string;
  customRoutes: string[];
}

export interface OvpnProfile {
  clientName: string;
  inlineProfile: string;
}

export interface ClamAvStatus {
  clamdActive: boolean;
  freshclamLastUpdate: string;
  signaturesTotal: number;
  icapBridgeActive: boolean;
  scannedFilesCount: number;
  threatsDetectedCount: number;
}

export interface QuarantineItem {
  id: string;
  fileName: string;
  threatName: string;
  timestamp: string;
  fileSizeBytes: number;
  encryptedPath: string;
}

export interface DecompressionLimits {
  maxRecursion: number;
  maxStreamSizeMb: number;
  scanTimeoutSeconds: number;
}

export interface AntivirusBypass {
  bypassMediaStreams: boolean;
  bypassSignedOsUpdates: boolean;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  operator: string;
  action: string;
  module: string;
  status: 'SUCCESS' | 'FAILURE' | 'BLOCKED' | 'WARN';
  details: string;
  clientIp: string;
}

export interface SyslogRemoteConfig {
  enabled: boolean;
  serverHost: string;
  serverPort: number;
  useTls: boolean;
  rfc5424Format: boolean;
}

export interface NtpStatus {
  synchronized: boolean;
  ntpServer: string;
  stratum: number;
  offsetMs: number;
  precisionUs: number;
}

export interface ConfigSnapshot {
  id: string;
  version: number;
  timestamp: string;
  author: string;
  description: string;
  canRollback: boolean;
}

export interface BackupStatus {
  automated: boolean;
  encrypted: boolean;
  lastBackup: string;
  targetStorage: string;
}
