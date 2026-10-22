import React, { useState, useEffect } from 'react';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { InputSwitch } from 'primereact/inputswitch';
import { Tag } from 'primereact/tag';
import { Dialog } from 'primereact/dialog';
import { InputText } from 'primereact/inputtext';
import { Dropdown } from 'primereact/dropdown';
import { TabView, TabPanel } from 'primereact/tabview';
import { Card } from 'primereact/card';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const NatModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const [natRules, setNatRules] = useState<T.NatRule[]>([]);
  const [alg, setAlg] = useState<T.AlgConfig>({
    sipEnabled: false,
    ftpEnabled: true,
    pptpEnabled: false,
    tftpEnabled: false,
  });
  const [natReflection, setNatReflection] = useState(true);
  const [dialogVisible, setDialogVisible] = useState(false);
  const [formRule, setFormRule] = useState<Partial<T.NatRule>>({
    name: '',
    natType: 'DnatPortForward',
    originalPort: '80',
    destinationIp: '192.168.2.10',
    destinationPort: '8080',
    interface: 'wan0',
    protocol: 'TCP',
    enabled: true,
  });

  const loadData = async () => {
    try {
      const [r, a] = await Promise.all([SecurityApi.getNatRules(), SecurityApi.getAlg()]);
      setNatRules(r);
      setAlg(a);
    } catch (e) {
      console.error('Error loading NAT:', e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveRule = async () => {
    if (!formRule.name) return;
    const created = await SecurityApi.addNatRule(formRule);
    setNatRules([...natRules, created]);
    setDialogVisible(false);
    onStateChangeNotify();
  };

  const handleDeleteRule = async (id: string) => {
    await SecurityApi.deleteNatRule(id);
    setNatRules(natRules.filter((r) => r.id !== id));
    onStateChangeNotify();
  };

  const handleUpdateAlg = async (updated: T.AlgConfig) => {
    setAlg(updated);
    await SecurityApi.setAlg(updated);
    onStateChangeNotify();
  };

  const portForwards = natRules.filter((r) => r.natType === 'DnatPortForward');
  const outboundNats = natRules.filter((r) => r.natType === 'SnatMasquerade');
  const binatRules = natRules.filter((r) => r.natType === 'BinatOneToOne' || r.natType === 'Nptv6Prefix');

  return (
    <div className="noc-module">
      <TabView className="noc-tabs">
        {/* ABA 1: PORT FORWARDING (DNAT) */}
        <TabPanel header="Port Forwarding (DNAT)" leftIcon="pi pi-arrow-right-arrow-left mr-2">
          <div className="flex justify-content-between align-items-center mb-3">
            <span className="text-sm text-gray-300">
              Redirecionamento de portas WAN para servidores internos na LAN ou DMZ com filtro de origem (ISO 27001 A.8.20).
            </span>
            <Button
              label="Novo Redirecionamento"
              icon="pi pi-plus"
              size="small"
              severity="success"
              onClick={() => {
                setFormRule({
                  name: '',
                  natType: 'DnatPortForward',
                  originalPort: '443',
                  destinationIp: '192.168.2.10',
                  destinationPort: '443',
                  interface: 'wan0',
                  protocol: 'TCP',
                  enabled: true,
                });
                setDialogVisible(true);
              }}
            />
          </div>

          <DataTable value={portForwards} size="small" className="noc-table">
            <Column
              field="enabled"
              header="Ativo"
              style={{ width: '4rem' }}
              body={(r: T.NatRule) => (
                <InputSwitch
                  checked={r.enabled}
                  onChange={async () => {
                    const u = { ...r, enabled: !r.enabled };
                    await SecurityApi.addNatRule(u);
                    setNatRules(natRules.map((x) => (x.id === r.id ? u : x)));
                    onStateChangeNotify();
                  }}
                />
              )}
            />
            <Column field="interface" header="Interface" style={{ width: '6rem' }} />
            <Column field="name" header="Nome da Regra" className="font-bold text-cyan-300" />
            <Column field="protocol" header="Proto" style={{ width: '5rem' }} />
            <Column
              header="Porta Externa WAN"
              body={(r: T.NatRule) => <code className="text-xs">{r.originalPort}</code>}
            />
            <Column
              header="IP e Porta Interna"
              body={(r: T.NatRule) => (
                <div className="font-mono text-xs">
                  <span className="text-green-400">{r.destinationIp}</span> :{' '}
                  <span className="text-cyan-400">{r.destinationPort}</span>
                </div>
              )}
            />
            <Column
              style={{ width: '4rem' }}
              body={(r: T.NatRule) => (
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

        {/* ABA 2: OUTBOUND NAT (SNAT / MASQUERADE) */}
        <TabPanel header="Outbound NAT (SNAT)" leftIcon="pi pi-external-link mr-2">
          <div className="flex justify-content-between align-items-center mb-3">
            <span className="text-sm text-gray-300">
              Tradução dinâmica de IPs privados da LAN para o IP público WAN (Masquerading).
            </span>
            <Button
              label="Nova Regra de Saída"
              icon="pi pi-plus"
              size="small"
              severity="info"
              onClick={() => {
                setFormRule({
                  name: 'Regra Outbound Personalizada',
                  natType: 'SnatMasquerade',
                  originalIp: '192.168.10.0/24',
                  originalPort: 'ANY',
                  destinationIp: '0.0.0.0/0',
                  destinationPort: 'ANY',
                  interface: 'wan0',
                  protocol: 'ALL',
                  enabled: true,
                });
                setDialogVisible(true);
              }}
            />
          </div>

          <DataTable value={outboundNats} size="small" className="noc-table">
            <Column field="interface" header="Interface WAN" style={{ width: '8rem' }} />
            <Column field="name" header="Nome da Regra" className="font-bold text-cyan-300" />
            <Column field="originalIp" header="Rede de Origem (LAN)" />
            <Column field="destinationIp" header="Destino" />
            <Column
              field="natType"
              header="Modo de Tradução"
              body={() => <Tag value="SNAT Masquerade Dinâmico" severity="success" />}
            />
          </DataTable>
        </TabPanel>

        {/* ABA 3: NAT 1:1 (BINAT) & NPTv6 */}
        <TabPanel header="NAT 1:1 & NPTv6" leftIcon="pi pi-link mr-2">
          <div className="flex justify-content-between align-items-center mb-3">
            <span className="text-sm text-gray-300">
              Mapeamento estático bidirecional 1:1 e tradução limpa de prefixos IPv6 (ULA para GUA).
            </span>
            <Button
              label="Novo NAT 1:1 / NPTv6"
              icon="pi pi-plus"
              size="small"
              severity="warning"
              onClick={() => {
                setFormRule({
                  name: 'Mapeamento IP Público Dedicado',
                  natType: 'BinatOneToOne',
                  originalIp: '203.0.113.15',
                  originalPort: 'ANY',
                  destinationIp: '192.168.2.50',
                  destinationPort: 'ANY',
                  interface: 'wan0',
                  protocol: 'ALL',
                  enabled: true,
                });
                setDialogVisible(true);
              }}
            />
          </div>

          <DataTable value={binatRules} size="small" className="noc-table" emptyMessage="Nenhum NAT 1:1 ou NPTv6 cadastrado.">
            <Column field="name" header="Identificador" className="font-bold text-cyan-300" />
            <Column field="originalIp" header="IP Público Exclusivo" />
            <Column field="destinationIp" header="IP Privado Interno" />
            <Column
              field="natType"
              header="Tipo"
              body={(r: T.NatRule) => (
                <Tag value={r.natType === 'BinatOneToOne' ? 'NAT 1:1 (Binat)' : 'NPTv6 Prefix'} severity="info" />
              )}
            />
          </DataTable>
        </TabPanel>

        {/* ABA 4: CONFIGURAÇÕES AVANÇADAS & ALG */}
        <TabPanel header="Avançado & ALGs" leftIcon="pi pi-cog mr-2">
          <div className="grid">
            <div className="col-12 md:col-6">
              <Card title="NAT Reflection (Loopback / Hairpinning)" className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Permite que computadores da rede interna acessem serviços hospedados internamente utilizando o IP público ou domínio externo sem que o pacote se perca.
                </p>
                <div className="flex align-items-center justify-content-between p-2 border-top-1 border-gray-800">
                  <span className="font-bold">NAT Loopback Ativo</span>
                  <InputSwitch
                    checked={natReflection}
                    onChange={(e) => {
                      setNatReflection(e.value);
                      onStateChangeNotify();
                    }}
                  />
                </div>
              </Card>
            </div>

            <div className="col-12 md:col-6">
              <Card title="Application Layer Gateways (ALG Helpers)" className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Controle estrito de helpers do kernel para protocolos com portas negociadas dinamicamente (ISO 27001 A.8.20).
                </p>
                <div className="flex align-items-center justify-content-between mb-2 p-2 border-bottom-1 border-gray-800">
                  <span>SIP Helper (VoIP)</span>
                  <InputSwitch
                    checked={alg.sipEnabled}
                    onChange={(e) => handleUpdateAlg({ ...alg, sipEnabled: e.value })}
                  />
                </div>
                <div className="flex align-items-center justify-content-between mb-2 p-2 border-bottom-1 border-gray-800">
                  <span>FTP Helper (Portas 21 / Passivo)</span>
                  <InputSwitch
                    checked={alg.ftpEnabled}
                    onChange={(e) => handleUpdateAlg({ ...alg, ftpEnabled: e.value })}
                  />
                </div>
                <div className="flex align-items-center justify-content-between mb-2 p-2 border-bottom-1 border-gray-800">
                  <span>PPTP VPN Helper</span>
                  <InputSwitch
                    checked={alg.pptpEnabled}
                    onChange={(e) => handleUpdateAlg({ ...alg, pptpEnabled: e.value })}
                  />
                </div>
                <div className="flex align-items-center justify-content-between p-2">
                  <span>TFTP Helper</span>
                  <InputSwitch
                    checked={alg.tftpEnabled}
                    onChange={(e) => handleUpdateAlg({ ...alg, tftpEnabled: e.value })}
                  />
                </div>
              </Card>
            </div>
          </div>
        </TabPanel>
      </TabView>

      {/* MODAL / FORM NAT */}
      <Dialog
        visible={dialogVisible}
        onHide={() => setDialogVisible(false)}
        header={<span className="font-bold font-orbitron">Cadastrar Regra de Tradução NAT</span>}
        style={{ width: '540px' }}
        className="noc-dialog p-fluid"
        modal
      >
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Nome da Regra *</label>
          <InputText
            value={formRule.name}
            onChange={(e) => setFormRule({ ...formRule, name: e.target.value })}
            placeholder="Ex: Encaminhamento Portal Web"
          />
        </div>

        <div className="grid mb-3">
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Tipo de NAT *</label>
            <Dropdown
              value={formRule.natType}
              options={[
                { label: 'Port Forward (DNAT)', value: 'DnatPortForward' },
                { label: 'Outbound Masquerade (SNAT)', value: 'SnatMasquerade' },
                { label: 'NAT 1:1 Estático (Binat)', value: 'BinatOneToOne' },
                { label: 'NPTv6 IPv6 Prefix', value: 'Nptv6Prefix' },
              ]}
              onChange={(e) => setFormRule({ ...formRule, natType: e.value })}
            />
          </div>
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Interface</label>
            <InputText
              value={formRule.interface}
              onChange={(e) => setFormRule({ ...formRule, interface: e.target.value })}
              placeholder="wan0"
            />
          </div>
        </div>

        <div className="grid mb-3">
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Porta Externa WAN</label>
            <InputText
              value={formRule.originalPort}
              onChange={(e) => setFormRule({ ...formRule, originalPort: e.target.value })}
              placeholder="Ex: 8080"
            />
          </div>
          <div className="col-6">
            <label className="text-xs font-bold text-gray-300">Protocolo</label>
            <Dropdown
              value={formRule.protocol}
              options={[
                { label: 'TCP', value: 'TCP' },
                { label: 'UDP', value: 'UDP' },
                { label: 'TCP/UDP', value: 'ALL' },
              ]}
              onChange={(e) => setFormRule({ ...formRule, protocol: e.value })}
            />
          </div>
        </div>

        <div className="grid mb-3">
          <div className="col-8">
            <label className="text-xs font-bold text-gray-300">IP Interno de Destino *</label>
            <InputText
              value={formRule.destinationIp}
              onChange={(e) => setFormRule({ ...formRule, destinationIp: e.target.value })}
              placeholder="Ex: 192.168.2.10"
            />
          </div>
          <div className="col-4">
            <label className="text-xs font-bold text-gray-300">Porta Interna</label>
            <InputText
              value={formRule.destinationPort}
              onChange={(e) => setFormRule({ ...formRule, destinationPort: e.target.value })}
              placeholder="Ex: 80"
            />
          </div>
        </div>

        <div className="flex justify-content-end gap-2 mt-4">
          <Button label="Cancelar" text onClick={() => setDialogVisible(false)} />
          <Button label="Salvar Regra NAT" icon="pi pi-check" severity="success" onClick={handleSaveRule} />
        </div>
      </Dialog>
    </div>
  );
};
