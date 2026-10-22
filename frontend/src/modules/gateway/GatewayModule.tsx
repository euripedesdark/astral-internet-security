import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Card } from 'primereact/card';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { Tag } from 'primereact/tag';
import { InputSwitch } from 'primereact/inputswitch';
import { InputText } from 'primereact/inputtext';
import { Dropdown } from 'primereact/dropdown';
import { TabView, TabPanel } from 'primereact/tabview';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const GatewayModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const { t } = useTranslation();
  const [wanLinks, setWanLinks] = useState<T.WanLink[]>([]);
  const [multiWan, setMultiWan] = useState<T.MultiWanConfig>({
    mode: 'Failover',
    stickyConnections: true,
    probeTargets: ['1.1.1.1', '8.8.8.8'],
    checkIntervalSecs: 5,
  });
  const [pbrRules, setPbrRules] = useState<T.PbrRule[]>([]);
  const [sinkhole, setSinkhole] = useState<T.DnsSinkholeConfig>({
    rpzEnabled: true,
    blockC2: true,
    blockPhishing: true,
    blockMalware: true,
    totalQueries: 142050,
    blockedQueries: 1842,
  });
  const [qos, setQos] = useState<T.QosConfig>({
    algorithm: 'FQ_CoDel',
    erpPriority: true,
    voipPriority: true,
    downloadBandwidthMbps: 500,
    uploadBandwidthMbps: 100,
    enabled: true,
  });
  const [egress, setEgress] = useState<T.EgressFilterConfig>({
    defaultDenyEgress: true,
    allowedPorts: [80, 443, 53, 123, 853],
    enabled: true,
  });

  const loadData = async () => {
    try {
      const [w, m, p, s, q, e] = await Promise.all([
        SecurityApi.getWanLinks(),
        SecurityApi.getMultiWan(),
        SecurityApi.getPbr(),
        SecurityApi.getSinkhole(),
        SecurityApi.getQos(),
        SecurityApi.getEgress(),
      ]);
      setWanLinks(w);
      setMultiWan(m);
      setPbrRules(p);
      setSinkhole(s);
      setQos(q);
      setEgress(e);
    } catch (err) {
      console.error('Error loading Gateway data:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="noc-module">
      <TabView className="noc-tabs">
        {/* ABA 1: PAINEL MULTI-WAN */}
        <TabPanel header={t('ais.gateway.tabMultiwan')} leftIcon="pi pi-sitemap mr-2">
          <div className="grid mb-4">
            {wanLinks.map((link) => (
              <div key={link.id} className="col-12 md:col-6">
                <Card className="noc-card">
                  <div className="flex justify-content-between align-items-center mb-2">
                    <span className="font-bold text-lg text-cyan-300 font-orbitron">{link.name}</span>
                    <Tag
                      value={link.isActive ? 'LINK ONLINE' : 'OFFLINE'}
                      severity={link.isActive ? 'success' : 'danger'}
                      icon={link.isActive ? 'pi pi-check' : 'pi pi-times'}
                    />
                  </div>
                  <div className="grid text-sm text-gray-300">
                    <div className="col-6">
                      <span className="text-xs text-gray-500 block">INTERFACE</span>
                      <code>{link.interface}</code>
                    </div>
                    <div className="col-6">
                      <span className="text-xs text-gray-500 block">GATEWAY IP</span>
                      <code>{link.gatewayIp}</code>
                    </div>
                    <div className="col-6 mt-2">
                      <span className="text-xs text-gray-500 block">LATÊNCIA MÉDIA</span>
                      <span className="font-bold text-green-400">{link.latencyMs.toFixed(1)} ms</span>
                    </div>
                    <div className="col-6 mt-2">
                      <span className="text-xs text-gray-500 block">PERDA DE PACOTES</span>
                      <span className={`font-bold ${link.packetLossPct > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {link.packetLossPct.toFixed(1)}%
                      </span>
                    </div>
                  </div>
                  <div className="mt-3 flex align-items-center justify-content-between border-top-1 border-gray-800 pt-2">
                    <Tag value={link.isPrimary ? 'Link Primário (Tier 1)' : 'Link Secundário (Tier 2)'} severity="info" />
                    <span className="text-xs text-gray-400">Peso no Balanceamento: {link.weight}%</span>
                  </div>
                </Card>
              </div>
            ))}
          </div>

          <Card title={t('ais.gateway.multiwanPolicyTitle')} className="noc-card">
            <div className="grid">
              <div className="col-12 md:col-6">
                <label className="text-xs font-bold text-gray-300 block mb-1">Modo de Operação WAN</label>
                <Dropdown
                  value={multiWan.mode}
                  options={[
                    { label: 'Failover Automático (Alta Disponibilidade)', value: 'Failover' },
                    { label: 'Balanceamento de Carga Ponderado (Load Balancing)', value: 'LoadBalanceWeighted' },
                    { label: 'Round-Robin com Persistência', value: 'RoundRobin' },
                  ]}
                  onChange={async (e) => {
                    const u = { ...multiWan, mode: e.value };
                    setMultiWan(u);
                    await SecurityApi.setMultiWan(u);
                    onStateChangeNotify();
                  }}
                />
              </div>
              <div className="col-12 md:col-6 flex align-items-center justify-content-between p-3">
                <div>
                  <span className="font-bold block">Sticky Connections (Persistência de Sessão)</span>
                  <small className="text-gray-400">Garante que bancos e HTTPS permaneçam na mesma WAN durante a sessão</small>
                </div>
                <InputSwitch
                  checked={multiWan.stickyConnections}
                  onChange={async (e) => {
                    const u = { ...multiWan, stickyConnections: e.value };
                    setMultiWan(u);
                    await SecurityApi.setMultiWan(u);
                    onStateChangeNotify();
                  }}
                />
              </div>
            </div>
          </Card>
        </TabPanel>

        {/* ABA 2: PBR & QOS */}
        <TabPanel header={t('ais.gateway.tabPbr')} leftIcon="pi pi-sliders-h mr-2">
          <div className="grid">
            <div className="col-12 md:col-6">
              <Card title={t('ais.gateway.qosTitle')} className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Algoritmos modernos de fila FQ_CoDel e Cake para eliminação de latência sob carga pesada e priorização de ERP/VoIP.
                </p>
                <div className="field mb-3">
                  <label className="text-xs font-bold text-gray-300">Algoritmo de Gerenciamento de Fila</label>
                  <Dropdown
                    value={qos.algorithm}
                    options={[
                      { label: 'FQ_CoDel (Fair Queueing CoDel)', value: 'FQ_CoDel' },
                      { label: 'Cake (Common Applications Kept Enhanced)', value: 'Cake' },
                    ]}
                    onChange={async (e) => {
                      const u = { ...qos, algorithm: e.value };
                      setQos(u);
                      await SecurityApi.setQos(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
                <div className="flex align-items-center justify-content-between mb-2 p-2 border-bottom-1 border-gray-800">
                  <span>Prioridade Máxima para Tráfego ERP Astral (DSCP EF)</span>
                  <InputSwitch
                    checked={qos.erpPriority}
                    onChange={async (e) => {
                      const u = { ...qos, erpPriority: e.value };
                      setQos(u);
                      await SecurityApi.setQos(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
                <div className="flex align-items-center justify-content-between p-2">
                  <span>Prioridade para Telefonia VoIP / SIP</span>
                  <InputSwitch
                    checked={qos.voipPriority}
                    onChange={async (e) => {
                      const u = { ...qos, voipPriority: e.value };
                      setQos(u);
                      await SecurityApi.setQos(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
              </Card>
            </div>

            <div className="col-12 md:col-6">
              <Card title={t('ais.gateway.pbrTitle')} className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Force o tráfego de sub-redes ou serviços críticos a sair exclusivamente por determinado link ou túnel seguro.
                </p>
                <DataTable value={pbrRules} size="small" className="noc-table" emptyMessage="Nenhuma rota baseada em política cadastrada.">
                  <Column field="name" header={t('ais.gateway.colPolicy')} className="font-bold text-cyan-300" />
                  <Column field="sourceNetwork" header={t('ais.gateway.colSourceNetwork')} />
                  <Column field="targetGateway" header={t('ais.gateway.colTargetGateway')} />
                  <Column
                    style={{ width: '3rem' }}
                    body={(r: T.PbrRule) => (
                      <Button
                        icon="pi pi-trash"
                        severity="danger"
                        text
                        size="small"
                        onClick={async () => {
                          await SecurityApi.deletePbr(r.id);
                          setPbrRules(pbrRules.filter((x) => x.id !== r.id));
                          onStateChangeNotify();
                        }}
                      />
                    )}
                  />
                </DataTable>
              </Card>
            </div>
          </div>
        </TabPanel>

        {/* ABA 3: EGRESS FILTERING & DNS SINKHOLE */}
        <TabPanel header={t('ais.gateway.tabEgress')} leftIcon="pi pi-filter mr-2">
          <div className="grid">
            <div className="col-12 md:col-6">
              <Card title={t('ais.gateway.egressTitle')} className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Bloqueio por padrão de conexões de saída na LAN, liberando exclusivamente portas de navegação seguras para prevenir vazamento e exfiltração de dados (ISO 27001 A.8.23).
                </p>
                <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
                  <span className="font-bold">Política Default Deny Egress</span>
                  <InputSwitch
                    checked={egress.defaultDenyEgress}
                    onChange={async (e) => {
                      const u = { ...egress, defaultDenyEgress: e.value };
                      setEgress(u);
                      await SecurityApi.setEgress(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
                <label className="text-xs font-bold text-gray-300 block mb-2">Portas de Saída Autorizadas:</label>
                <div className="flex gap-2 flex-wrap mb-3">
                  {egress.allowedPorts.map((p) => (
                    <Tag key={p} value={`TCP/UDP ${p}`} severity="success" />
                  ))}
                </div>
              </Card>
            </div>

            <div className="col-12 md:col-6">
              <Card title={t('ais.gateway.sinkholeTitle')} className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Interceptação de requisições DNS para domínios maliciosos, redes de comando e controle (C2) e phishing (RPZ Response Policy Zones).
                </p>
                <div className="grid text-center mb-3">
                  <div className="col-6">
                    <span className="text-2xl font-bold font-orbitron text-cyan-400">{sinkhole.totalQueries.toLocaleString()}</span>
                    <small className="block text-gray-400">Total Consultas DNS</small>
                  </div>
                  <div className="col-6">
                    <span className="text-2xl font-bold font-orbitron text-red-400">{sinkhole.blockedQueries.toLocaleString()}</span>
                    <small className="block text-gray-400">Ameaças Bloqueadas (Sinkhole)</small>
                  </div>
                </div>
                <div className="flex align-items-center justify-content-between p-2 border-top-1 border-gray-800">
                  <span>Bloquear Domínios C2 e Malware em Tempo Real</span>
                  <InputSwitch
                    checked={sinkhole.blockC2}
                    onChange={async (e) => {
                      const u = { ...sinkhole, blockC2: e.value };
                      setSinkhole(u);
                      await SecurityApi.setSinkhole(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
              </Card>
            </div>
          </div>
        </TabPanel>
      </TabView>
    </div>
  );
};
