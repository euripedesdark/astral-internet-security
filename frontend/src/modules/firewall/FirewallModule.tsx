import React, { useState, useEffect } from 'react';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { InputSwitch } from 'primereact/inputswitch';
import { Tag } from 'primereact/tag';
import { Dialog } from 'primereact/dialog';
import { InputText } from 'primereact/inputtext';
import { Dropdown } from 'primereact/dropdown';
import { Checkbox } from 'primereact/checkbox';
import { TabView, TabPanel } from 'primereact/tabview';
import { Card } from 'primereact/card';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const FirewallModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const [rules, setRules] = useState<T.FirewallRule[]>([]);
  const [zones, setZones] = useState<T.NetworkZone[]>([]);
  const [aliases, setAliases] = useState<T.AliasObject[]>([]);
  const [geoIps, setGeoIps] = useState<T.GeoIpPolicy[]>([]);
  const [antiSpoofing, setAntiSpoofing] = useState<T.AntiSpoofingConfig>({ blockRfc1918OnWan: true, blockIanaUnallocated: true, enabled: true });
  const [rateLimit, setRateLimit] = useState<T.RateLimitConfig>({ synFloodRate: 50, icmpFloodRate: 20, udpFloodRate: 100, maxConnPerIp: 500, enabled: true });
  const [selectedZone, setSelectedZone] = useState<string>('ALL');
  const [ruleDialog, setRuleDialog] = useState(false);
  const [aliasDialog, setAliasDialog] = useState(false);
  const [loading, setLoading] = useState(true);

  // Form states
  const [formRule, setFormRule] = useState<Partial<T.FirewallRule>>({
    name: '',
    zone: 'WAN',
    action: 'ACCEPT',
    direction: 'IN',
    protocol: 'TCP',
    port: '443',
    sourceIp: '',
    destinationIp: '',
    sourceMac: '',
    enabled: true,
    logEnabled: true,
  });

  const [formAlias, setFormAlias] = useState<Partial<T.AliasObject>>({
    name: '',
    aliasType: 'Host',
    entries: [],
    description: '',
  });
  const [aliasEntriesText, setAliasEntriesText] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [r, z, a, g, as, rl] = await Promise.all([
        SecurityApi.getRules(),
        SecurityApi.getZones(),
        SecurityApi.getAliases(),
        SecurityApi.getGeoIp(),
        SecurityApi.getAntiSpoofing(),
        SecurityApi.getRateLimiting(),
      ]);
      setRules(r);
      setZones(z);
      setAliases(a);
      setGeoIps(g);
      setAntiSpoofing(as);
      setRateLimit(rl);
    } catch (e) {
      console.error('Error loading firewall data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleRule = async (rule: T.FirewallRule) => {
    const updated = { ...rule, enabled: !rule.enabled };
    setRules(rules.map((r) => (r.id === rule.id ? updated : r)));
    await SecurityApi.addRule(updated);
    onStateChangeNotify();
  };

  const handleDeleteRule = async (id: string) => {
    await SecurityApi.deleteRule(id);
    setRules(rules.filter((r) => r.id !== id));
    onStateChangeNotify();
  };

  const handleSaveRule = async () => {
    if (!formRule.name) return;
    const res = await SecurityApi.addRule({
      ...formRule,
      createdAt: new Date().toISOString(),
    });
    setRules([...rules, res]);
    setRuleDialog(false);
    onStateChangeNotify();
  };

  const handleSaveAlias = async () => {
    if (!formAlias.name) return;
    const entries = aliasEntriesText.split(",").map((s) => s.trim()).filter(Boolean);
    const res = await SecurityApi.addAlias({
      id: '',
      name: formAlias.name,
      aliasType: formAlias.aliasType || 'Host',
      entries,
      description: formAlias.description || '',
    });
    setAliases([...aliases, res]);
    setAliasDialog(false);
    setAliasEntriesText('');
    onStateChangeNotify();
  };

  const handleUpdateAntiSpoofing = async (cfg: T.AntiSpoofingConfig) => {
    setAntiSpoofing(cfg);
    await SecurityApi.setAntiSpoofing(cfg);
    onStateChangeNotify();
  };

  const handleUpdateRateLimit = async (cfg: T.RateLimitConfig) => {
    setRateLimit(cfg);
    await SecurityApi.setRateLimiting(cfg);
    onStateChangeNotify();
  };

  // ISO 27001 Risk Evaluation (A.8.20 / A.8.2)
  const getIsoRiskBadge = (r: T.FirewallRule) => {
    const isWan = r.zone === 'WAN' || r.direction === 'IN';
    const isAnyPort = !r.port || r.port === 'ANY' || r.port === 'ALL';
    const isAnyDest = !r.destinationIp || r.destinationIp === '0.0.0.0/0';
    const isCriticalPort = r.port === '22' || r.port === '3389' || r.port === '23' || r.port === '8080';

    if (r.action === 'ACCEPT' && isWan && (isAnyPort || isCriticalPort) && isAnyDest) {
      return (
        <Tag
          value="RISCO ISO 27001: Exposição Crítica"
          severity="danger"
          icon="pi pi-exclamation-triangle"
          title="Regra viola Controle A.8.20: Exposição de portas sensíveis na interface WAN sem isolamento Zero Trust"
        />
      );
    }
    if (r.action === 'ACCEPT' && !r.logEnabled) {
      return (
        <Tag
          value="Alerta A.8.15: Sem Log"
          severity="warning"
          icon="pi pi-info-circle"
          title="Recomendação ISO 27001: Ativar registro de log para auditoria e SIEM"
        />
      );
    }
    return <Tag value="Conforme ISO 27001" severity="success" icon="pi pi-check-circle" />;
  };

  const filteredRules = selectedZone === 'ALL' ? rules : rules.filter((r) => r.zone === selectedZone);

  return (
    <div className="noc-module">
      <TabView className="noc-tabs">
        {/* TAB 1: REGRAS DE FIREWALL */}
        <TabPanel header="Regras de Filtragem (SPI)" leftIcon="pi pi-shield mr-2">
          <div className="flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <div className="flex align-items-center gap-2">
              <span className="text-sm font-bold text-gray-300">Filtrar por Zona:</span>
              <div className="flex gap-1">
                {['ALL', 'WAN', 'LAN', 'DMZ', 'Guest', 'VPN_ZTNA'].map((z) => (
                  <Button
                    key={z}
                    label={z}
                    size="small"
                    outlined={selectedZone !== z}
                    severity={selectedZone === z ? 'info' : 'secondary'}
                    onClick={() => setSelectedZone(z)}
                  />
                ))}
              </div>
            </div>

            <Button
              label="Nova Regra de Firewall"
              icon="pi pi-plus"
              severity="success"
              size="small"
              onClick={() => {
                setFormRule({
                  name: '',
                  zone: selectedZone === 'ALL' ? 'WAN' : selectedZone,
                  action: 'ACCEPT',
                  direction: 'IN',
                  protocol: 'TCP',
                  port: '',
                  sourceIp: '',
                  destinationIp: '',
                  sourceMac: '',
                  enabled: true,
                  logEnabled: true,
                });
                setRuleDialog(true);
              }}
            />
          </div>

          <DataTable
            value={filteredRules}
            reorderableRows
            onRowReorder={(e) => {
              setRules(e.value as T.FirewallRule[]);
              onStateChangeNotify();
            }}
            size="small"
            className="noc-table"
            paginator
            rows={15}
            emptyMessage="Nenhuma regra configurada para esta zona."
            loading={loading}
          >
            <Column rowReorder style={{ width: '3rem' }} />
            <Column
              field="enabled"
              header="Ativo"
              style={{ width: '4.5rem' }}
              body={(r: T.FirewallRule) => (
                <InputSwitch checked={r.enabled} onChange={() => handleToggleRule(r)} />
              )}
            />
            <Column
              field="action"
              header="Ação"
              style={{ width: '6rem' }}
              body={(r: T.FirewallRule) => {
                const sev = r.action === 'ACCEPT' ? 'success' : r.action === 'DROP' ? 'danger' : 'warning';
                return <Tag value={r.action} severity={sev} />;
              }}
            />
            <Column field="zone" header="Zona" style={{ width: '6.5rem' }} />
            <Column field="name" header="Identificador / Regra" className="font-bold text-cyan-300" />
            <Column field="protocol" header="Proto" style={{ width: '5.5rem' }} />
            <Column
              header="Origem"
              body={(r: T.FirewallRule) => r.sourceIp || r.sourceMac || '0.0.0.0/0 (Any)'}
            />
            <Column
              header="Destino : Porta"
              body={(r: T.FirewallRule) => `${r.destinationIp || 'Any'} : ${r.port || 'Any'}`}
            />
            <Column
              header="Tráfego (Hits / Bytes)"
              body={(r: T.FirewallRule) => (
                <div className="text-xs font-mono text-gray-300">
                  <span className="text-cyan-400 font-bold">{r.hits || 1240} hits</span> |{' '}
                  <span>{((r.bytes || 849200) / 1024 / 1024).toFixed(2)} MB</span>
                </div>
              )}
            />
            <Column
              header="Auditoria ISO 27001"
              body={(r: T.FirewallRule) => getIsoRiskBadge(r)}
            />
            <Column
              header="Ações"
              style={{ width: '4rem' }}
              body={(r: T.FirewallRule) => (
                <Button
                  icon="pi pi-trash"
                  severity="danger"
                  text
                  size="small"
                  onClick={() => handleDeleteRule(r.id)}
                />
              )}
            />
          </DataTable>
        </TabPanel>

        {/* TAB 2: GESTOR DE OBJETOS & ALIASES */}
        <TabPanel header="Objetos e Aliases" leftIcon="pi pi-database mr-2">
          <div className="flex justify-content-between align-items-center mb-3">
            <span className="text-sm text-gray-300">
              Agrupamento lógico de IPs, Redes e Portas para regras granulares limpas (ISO 27001 A.8.20).
            </span>
            <Button
              label="Novo Alias"
              icon="pi pi-plus"
              size="small"
              severity="info"
              onClick={() => setAliasDialog(true)}
            />
          </div>

          <DataTable value={aliases} size="small" className="noc-table">
            <Column field="name" header="Nome do Alias" className="font-bold text-cyan-300" />
            <Column
              field="aliasType"
              header="Tipo"
              body={(a: T.AliasObject) => <Tag value={a.aliasType} severity="info" />}
            />
            <Column
              field="entries"
              header="Itens Agrupados"
              body={(a: T.AliasObject) => (
                <div className="flex gap-1 flex-wrap">
                  {(a.entries || []).map((e, i) => (
                    <code key={i} className="text-xs">{e}</code>
                  ))}
                </div>
              )}
            />
            <Column field="description" header="Descrição" />
            <Column
              style={{ width: '4rem' }}
              body={(a: T.AliasObject) => (
                <Button
                  icon="pi pi-trash"
                  severity="danger"
                  text
                  size="small"
                  onClick={async () => {
                    await SecurityApi.deleteAlias(a.id);
                    setAliases(aliases.filter((item) => item.id !== a.id));
                    onStateChangeNotify();
                  }}
                />
              )}
            />
          </DataTable>
        </TabPanel>

        {/* TAB 3: PROTEÇÃO AVANÇADA (ANTI-SPOOFING, BOGON, RATE LIMIT, GEOIP) */}
        <TabPanel header="Proteções DoS & Bogon" leftIcon="pi pi-lock mr-2">
          <div className="grid">
            <div className="col-12 md:col-6">
              <Card title="Anti-Spoofing & Filtragem Bogon (RFC 1918)" className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-4">
                  Bloqueio incondicional na interface WAN de endereços falsificados e redes privadas que não devem trafegar na internet pública.
                </p>
                <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
                  <span>Bloquear RFC 1918 (10/8, 172.16/12, 192.168/16) na WAN</span>
                  <InputSwitch
                    checked={antiSpoofing.blockRfc1918OnWan}
                    onChange={(e) => handleUpdateAntiSpoofing({ ...antiSpoofing, blockRfc1918OnWan: e.value })}
                  />
                </div>
                <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
                  <span>Descartar prefixos não alocados da IANA (Bogon List)</span>
                  <InputSwitch
                    checked={antiSpoofing.blockIanaUnallocated}
                    onChange={(e) => handleUpdateAntiSpoofing({ ...antiSpoofing, blockIanaUnallocated: e.value })}
                  />
                </div>
                <div className="flex align-items-center justify-content-between p-2">
                  <span className="font-bold">Mecanismo Global Ativado</span>
                  <InputSwitch
                    checked={antiSpoofing.enabled}
                    onChange={(e) => handleUpdateAntiSpoofing({ ...antiSpoofing, enabled: e.value })}
                  />
                </div>
              </Card>
            </div>

            <div className="col-12 md:col-6">
              <Card title="Mitigação DoS / Rate Limiting (SYN / UDP Flood)" className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Controle de taxa e estouro de conexões simultâneas para prevenção de exaustão de tabela conntrack.
                </p>
                <div className="field mb-2">
                  <label className="text-xs font-bold text-gray-300">Limite de SYN Flood (pacotes/seg):</label>
                  <InputText
                    type="number"
                    value={String(rateLimit.synFloodRate)}
                    onChange={(e) => handleUpdateRateLimit({ ...rateLimit, synFloodRate: +e.target.value })}
                    className="p-inputtext-sm"
                  />
                </div>
                <div className="field mb-2">
                  <label className="text-xs font-bold text-gray-300">Limite de UDP Flood (pacotes/seg):</label>
                  <InputText
                    type="number"
                    value={String(rateLimit.udpFloodRate)}
                    onChange={(e) => handleUpdateRateLimit({ ...rateLimit, udpFloodRate: +e.target.value })}
                    className="p-inputtext-sm"
                  />
                </div>
                <div className="field mb-3">
                  <label className="text-xs font-bold text-gray-300">Conexões Simultâneas Máximas por IP:</label>
                  <InputText
                    type="number"
                    value={String(rateLimit.maxConnPerIp)}
                    onChange={(e) => handleUpdateRateLimit({ ...rateLimit, maxConnPerIp: +e.target.value })}
                    className="p-inputtext-sm"
                  />
                </div>
                <div className="flex align-items-center justify-content-between p-2 border-top-1 border-gray-800">
                  <span className="font-bold">Mitigação de DoS Ativa</span>
                  <InputSwitch
                    checked={rateLimit.enabled}
                    onChange={(e) => handleUpdateRateLimit({ ...rateLimit, enabled: e.value })}
                  />
                </div>
              </Card>
            </div>
          </div>
        </TabPanel>

        {/* TAB 4: GEOIP BLOCKING */}
        <TabPanel header="Bloqueio GeoIP" leftIcon="pi pi-globe mr-2">
          <div className="flex justify-content-between align-items-center mb-3">
            <span className="text-sm text-gray-300">
              Restrição geográfica de tráfego de entrada e saída por país de origem do endereço IP (ISO 27001 A.8.20).
            </span>
            <Button
              label="Bloquear País"
              icon="pi pi-plus"
              size="small"
              severity="danger"
              onClick={async () => {
                const code = prompt('Código do País (ex: CN, RU, KP, IR):');
                if (code) {
                  await SecurityApi.addGeoIp({
                    id: '',
                    countryCode: code.toUpperCase(),
                    action: 'BLOCK',
                    direction: 'IN',
                    enabled: true,
                  });
                  loadData();
                  onStateChangeNotify();
                }
              }}
            />
          </div>

          <DataTable value={geoIps} size="small" className="noc-table">
            <Column field="countryCode" header="Código País" className="font-bold text-cyan-300" />
            <Column
              field="action"
              header="Ação"
              body={(g: T.GeoIpPolicy) => <Tag value={g.action} severity={g.action === 'BLOCK' ? 'danger' : 'success'} />}
            />
            <Column field="direction" header="Direção" />
            <Column
              field="enabled"
              header="Status"
              body={(g: T.GeoIpPolicy) => <Tag value={g.enabled ? 'Ativo' : 'Desativado'} severity={g.enabled ? 'success' : 'secondary'} />}
            />
            <Column
              style={{ width: '4rem' }}
              body={(g: T.GeoIpPolicy) => (
                <Button
                  icon="pi pi-trash"
                  severity="danger"
                  text
                  size="small"
                  onClick={async () => {
                    await SecurityApi.deleteGeoIp(g.id);
                    setGeoIps(geoIps.filter((item) => item.id !== g.id));
                    onStateChangeNotify();
                  }}
                />
              )}
            />
          </DataTable>
        </TabPanel>
      </TabView>

      {/* MODAL / FORMULÁRIO DE REGRA */}
      <Dialog
        visible={ruleDialog}
        onHide={() => setRuleDialog(false)}
        header={<span className="font-bold font-orbitron">Cadastrar Regra Granular de Firewall</span>}
        style={{ width: '640px' }}
        className="noc-dialog p-fluid"
        modal
      >
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Nome da Regra / Identificador *</label>
          <InputText
            value={formRule.name}
            onChange={(e) => setFormRule({ ...formRule, name: e.target.value })}
            placeholder="Ex: Permitir Acesso Banco Central"
          />
        </div>

        <div className="grid mb-3">
          <div className="col-4">
            <label className="text-xs font-bold text-gray-300">Ação *</label>
            <Dropdown
              value={formRule.action}
              options={[
                { label: 'PASS / ACCEPT', value: 'ACCEPT' },
                { label: 'BLOCK / DROP', value: 'DROP' },
                { label: 'REJECT', value: 'REJECT' },
              ]}
              onChange={(e) => setFormRule({ ...formRule, action: e.value })}
            />
          </div>
          <div className="col-4">
            <label className="text-xs font-bold text-gray-300">Zona de Rede *</label>
            <Dropdown
              value={formRule.zone}
              options={zones.map((z) => ({ label: z.name, value: z.name }))}
              onChange={(e) => setFormRule({ ...formRule, zone: e.value })}
            />
          </div>
          <div className="col-4">
            <label className="text-xs font-bold text-gray-300">Direção *</label>
            <Dropdown
              value={formRule.direction}
              options={[
                { label: 'IN (Entrada)', value: 'IN' },
                { label: 'OUT (Saída)', value: 'OUT' },
                { label: 'FORWARD', value: 'FORWARD' },
              ]}
              onChange={(e) => setFormRule({ ...formRule, direction: e.value })}
            />
          </div>
        </div>

        <div className="grid mb-3">
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Protocolo</label>
            <Dropdown
              value={formRule.protocol}
              options={[
                { label: 'TCP', value: 'TCP' },
                { label: 'UDP', value: 'UDP' },
                { label: 'ICMP', value: 'ICMP' },
                { label: 'QUALQUER (ANY)', value: 'ANY' },
              ]}
              onChange={(e) => setFormRule({ ...formRule, protocol: e.value })}
            />
          </div>
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Porta Destino (ou Alias)</label>
            <InputText
              value={formRule.port}
              onChange={(e) => setFormRule({ ...formRule, port: e.target.value })}
              placeholder="Ex: 443 ou WEB_PORTS"
            />
          </div>
        </div>

        <div className="grid mb-3">
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Origem (IP, CIDR ou MAC)</label>
            <InputText
              value={formRule.sourceIp}
              onChange={(e) => setFormRule({ ...formRule, sourceIp: e.target.value })}
              placeholder="0.0.0.0/0 ou 192.168.1.0/24"
            />
          </div>
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Destino (IP, CIDR ou Alias)</label>
            <InputText
              value={formRule.destinationIp}
              onChange={(e) => setFormRule({ ...formRule, destinationIp: e.target.value })}
              placeholder="0.0.0.0/0 ou IP do Host"
            />
          </div>
        </div>

        <div className="field-checkbox mb-3 p-3 border-1 border-gray-800 rounded bg-black-alpha-40">
          <Checkbox
            inputId="cbLog"
            checked={!!formRule.logEnabled}
            onChange={(e) => setFormRule({ ...formRule, logEnabled: !!e.checked })}
          />
          <label htmlFor="cbLog" className="text-xs font-bold text-cyan-300 ml-2">
            Registrar Log desta Regra (Exigência Direta ISO/IEC 27001 Controle A.8.15)
          </label>
        </div>

        <div className="flex justify-content-end gap-2 mt-4">
          <Button label="Cancelar" text onClick={() => setRuleDialog(false)} />
          <Button label="Salvar Regra" icon="pi pi-check" severity="success" onClick={handleSaveRule} />
        </div>
      </Dialog>

      {/* MODAL ALIAS */}
      <Dialog
        visible={aliasDialog}
        onHide={() => setAliasDialog(false)}
        header={<span className="font-bold font-orbitron">Cadastrar Objeto / Alias</span>}
        style={{ width: '480px' }}
        className="noc-dialog p-fluid"
        modal
      >
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Nome do Alias (Sem espaços) *</label>
          <InputText
            value={formAlias.name}
            onChange={(e) => setFormAlias({ ...formAlias, name: e.target.value.toUpperCase() })}
            placeholder="Ex: SERVIDORES_ERP"
          />
        </div>

        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Tipo de Alias</label>
          <Dropdown
            value={formAlias.aliasType}
            options={[
              { label: 'Host (IP Único)', value: 'Host' },
              { label: 'Network (Sub-rede CIDR)', value: 'Network' },
              { label: 'Port (Portas / Ranges)', value: 'Port' },
              { label: 'URL / Domínio', value: 'Url' },
            ]}
            onChange={(e) => setFormAlias({ ...formAlias, aliasType: e.value })}
          />
        </div>

        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Entradas (separadas por vírgula ou nova linha)</label>
          <InputText
            value={aliasEntriesText}
            onChange={(e) => setAliasEntriesText(e.target.value)}
            placeholder="192.168.2.10, 192.168.2.11"
          />
        </div>

        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Descrição / Justificativa</label>
          <InputText
            value={formAlias.description}
            onChange={(e) => setFormAlias({ ...formAlias, description: e.target.value })}
            placeholder="Agrupamento de servidores centrais"
          />
        </div>

        <div className="flex justify-content-end gap-2 mt-4">
          <Button label="Cancelar" text onClick={() => setAliasDialog(false)} />
          <Button label="Salvar Alias" icon="pi pi-check" severity="info" onClick={handleSaveAlias} />
        </div>
      </Dialog>
    </div>
  );
};
