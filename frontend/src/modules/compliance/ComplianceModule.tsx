import React, { useState, useEffect } from 'react';
import { Card } from 'primereact/card';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { Tag } from 'primereact/tag';
import { InputSwitch } from 'primereact/inputswitch';
import { InputText } from 'primereact/inputtext';
import { TabView, TabPanel } from 'primereact/tabview';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const ComplianceModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const [logs, setLogs] = useState<T.AuditLogEntry[]>([]);
  const [logFilter, setLogFilter] = useState('');
  const [selectedModule, setSelectedModule] = useState('ALL');
  const [syslog, setSyslog] = useState<T.SyslogRemoteConfig>({
    enabled: true,
    serverHost: 'siem.srvcloud.cloud',
    serverPort: 6514,
    useTls: true,
    rfc5424Format: true,
  });
  const [ntp, setNtp] = useState<T.NtpStatus>({
    synchronized: true,
    ntpServer: 'a.st1.ntp.br',
    stratum: 1,
    offsetMs: 0.12,
    precisionUs: 15.0,
  });
  const [snapshots, setSnapshots] = useState<T.ConfigSnapshot[]>([]);
  const [backup, setBackup] = useState<T.BackupStatus>({
    automated: true,
    encrypted: true,
    lastBackup: new Date().toISOString(),
    targetStorage: '/var/backups/astral/encrypted_vault.bin',
  });
  const [backingUp, setBackingUp] = useState(false);

  const loadData = async () => {
    try {
      const [l, s, n, snaps, b] = await Promise.all([
        SecurityApi.getAuditLogs(),
        SecurityApi.getSyslog(),
        SecurityApi.getNtpStatus(),
        SecurityApi.getSnapshots(),
        SecurityApi.getBackupStatus(),
      ]);
      setLogs(l);
      setSyslog(s);
      setNtp(n);
      setSnapshots(snaps);
      setBackup(b);
    } catch (e) {
      console.error('Error loading Compliance data:', e);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(async () => {
      try {
        const freshLogs = await SecurityApi.getAuditLogs();
        setLogs(freshLogs);
      } catch (_) {}
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleRollback = async (id: string) => {
    if (confirm('Fazer Rollback imediato para esta versão anterior de configuração? Todas as regras serão restauradas ao estado do snapshot.')) {
      await SecurityApi.rollbackSnapshot(id);
      loadData();
      onStateChangeNotify();
    }
  };

  const handleTriggerBackup = async () => {
    setBackingUp(true);
    try {
      const b = await SecurityApi.triggerBackup();
      setBackup(b);
      alert(`Backup criptografado gerado com sucesso em ${b.targetStorage}`);
    } finally {
      setBackingUp(false);
    }
  };

  const filteredLogs = logs.filter((item) => {
    const matchMod = selectedModule === 'ALL' || item.module === selectedModule;
    const matchText =
      !logFilter ||
      item.details.toLowerCase().includes(logFilter.toLowerCase()) ||
      item.operator.toLowerCase().includes(logFilter.toLowerCase()) ||
      item.action.toLowerCase().includes(logFilter.toLowerCase()) ||
      item.clientIp.includes(logFilter);
    return matchMod && matchText;
  });

  return (
    <div className="noc-module">
      <TabView className="noc-tabs">
        {/* ABA 1: LIVE TAIL & AUDITORIA */}
        <TabPanel header="Logs em Tempo Real & SIEM" leftIcon="pi pi-desktop mr-2">
          <div className="flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <div className="flex gap-2 align-items-center">
              <span className="text-xs font-bold text-gray-400">Filtrar Módulo:</span>
              {['ALL', 'FirewallEngine', 'NatEngine', 'VpnEngine', 'ClamAV'].map((m) => (
                <Button
                  key={m}
                  label={m}
                  size="small"
                  outlined={selectedModule !== m}
                  severity={selectedModule === m ? 'info' : 'secondary'}
                  onClick={() => setSelectedModule(m)}
                />
              ))}
            </div>

            <InputText
              value={logFilter}
              onChange={(e) => setLogFilter(e.target.value)}
              placeholder="Pesquisar por IP, Operador, Ação..."
              className="p-inputtext-sm"
              style={{ width: '280px' }}
            />
          </div>

          <DataTable value={filteredLogs} size="small" className="noc-table" paginator rows={15}>
            <Column field="timestamp" header="Data / Hora (UTC)" style={{ width: '13rem' }} />
            <Column field="operator" header="Operador" className="font-bold text-cyan-300" style={{ width: '10rem' }} />
            <Column field="action" header="Ação" style={{ width: '10rem' }} />
            <Column field="module" header="Módulo" style={{ width: '9rem' }} />
            <Column
              field="status"
              header="Status"
              style={{ width: '6rem' }}
              body={(l: T.AuditLogEntry) => {
                const sev = l.status === 'SUCCESS' ? 'success' : l.status === 'BLOCKED' ? 'danger' : 'warning';
                return <Tag value={l.status} severity={sev} />;
              }}
            />
            <Column field="details" header="Detalhes Auditáveis" />
            <Column field="clientIp" header="IP Origem" style={{ width: '8rem' }} />
          </DataTable>
        </TabPanel>

        {/* ABA 2: HISTÓRICO DE MUDANÇAS & ROLLBACK (A.8.32) */}
        <TabPanel header="Gestão de Mudanças & Rollback" leftIcon="pi pi-history mr-2">
          <p className="text-xs text-gray-300 mb-3">
            Histórico imutável de revisões de configuração conforme Controle ISO/IEC 27001 A.8.32. Permite auditoria completa e Rollback com 1 clique.
          </p>

          <DataTable value={snapshots} size="small" className="noc-table" emptyMessage="Nenhum snapshot de mudança gerado até o momento.">
            <Column
              field="version"
              header="Revisão"
              style={{ width: '6rem' }}
              body={(s: T.ConfigSnapshot) => <Tag value={`v${s.version}`} severity="info" className="font-orbitron" />}
            />
            <Column field="timestamp" header="Data / Hora da Aplicação" style={{ width: '14rem' }} />
            <Column field="author" header="Autor da Mudança" className="font-bold text-cyan-300" style={{ width: '14rem' }} />
            <Column field="description" header="Justificativa Técnica da Mudança" />
            <Column
              header="Ação"
              style={{ width: '10rem' }}
              body={(s: T.ConfigSnapshot) => (
                <Button
                  label="Rollback Imediato"
                  icon="pi pi-undo"
                  severity="warning"
                  size="small"
                  onClick={() => handleRollback(s.id)}
                />
              )}
            />
          </DataTable>
        </TabPanel>

        {/* ABA 3: SYSLOG SIEM & NTP (A.8.15 / A.8.17) */}
        <TabPanel header="Syslog SIEM & Sincronismo NTP" leftIcon="pi pi-clock mr-2">
          <div className="grid">
            <div className="col-12 md:col-6">
              <Card title="Exportação Syslog Remoto TLS (RFC 5424)" className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  Transmissão contínua e criptografada de todos os eventos para SIEM corporativo externo (Splunk, Elastic, Sentinel).
                </p>
                <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
                  <span className="font-bold">Encaminhamento SIEM Ativo</span>
                  <InputSwitch
                    checked={syslog.enabled}
                    onChange={async (e) => {
                      const u = { ...syslog, enabled: e.value };
                      setSyslog(u);
                      await SecurityApi.setSyslog(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
                <div className="field mb-2">
                  <label className="text-xs font-bold text-gray-300">Host do Servidor SIEM:</label>
                  <InputText
                    value={syslog.serverHost}
                    onChange={(e) => setSyslog({ ...syslog, serverHost: e.target.value })}
                  />
                </div>
                <div className="field mb-3">
                  <label className="text-xs font-bold text-gray-300">Porta TLS (Padrão 6514):</label>
                  <InputText
                    type="number"
                    value={String(syslog.serverPort)}
                    onChange={(e) => setSyslog({ ...syslog, serverPort: +e.target.value })}
                  />
                </div>
                <Button
                  label="Salvar Parâmetros Syslog"
                  size="small"
                  severity="info"
                  onClick={async () => {
                    await SecurityApi.setSyslog(syslog);
                    onStateChangeNotify();
                  }}
                />
              </Card>
            </div>

            <div className="col-12 md:col-6">
              <Card title="Sincronização de Relógio NTP (Controle A.8.17)" className="noc-card mb-3">
                <p className="text-xs text-gray-300 mb-3">
                  A precisão temporal é requisito inegociável da ISO 27001 para correlação forense de evidências em tribunais.
                </p>
                <div className="p-3 mb-3 border-1 border-gray-800 rounded bg-black-alpha-40">
                  <div className="flex justify-content-between mb-2">
                    <span className="text-xs text-gray-400">Servidor NTP Referência:</span>
                    <span className="font-bold text-cyan-300">{ntp.ntpServer}</span>
                  </div>
                  <div className="flex justify-content-between mb-2">
                    <span className="text-xs text-gray-400">Estrato (Stratum):</span>
                    <span className="font-bold text-green-400">Stratum {ntp.stratum} (Referência Primária)</span>
                  </div>
                  <div className="flex justify-content-between">
                    <span className="text-xs text-gray-400">Desvio Máximo (Clock Offset):</span>
                    <span className="font-bold text-green-400">± {ntp.offsetMs} ms (Excelente)</span>
                  </div>
                </div>
                <Tag
                  value={ntp.synchronized ? 'RELÓGIO SINCRONIZADO E AUTENTICADO' : 'ALERTA: RELÓGIO DESSINCRONIZADO'}
                  severity={ntp.synchronized ? 'success' : 'danger'}
                  className="w-full text-center py-2"
                />
              </Card>
            </div>
          </div>
        </TabPanel>

        {/* ABA 4: BACKUP CRIPTOGRAFADO (A.8.13) */}
        <TabPanel header="Backup Criptografado (A.8.13)" leftIcon="pi pi-database mr-2">
          <Card title="Cofre de Backup Automatizado" className="noc-card">
            <p className="text-xs text-gray-300 mb-4">
              Exportação do estado completo de configurações protegido por AES-256 e assinatura de integridade SHA-512 (ISO 27001 A.8.13).
            </p>
            <div className="grid align-items-center mb-4">
              <div className="col-12 md:col-6">
                <span className="text-xs text-gray-500 block">DESTINO DO ARQUIVO</span>
                <code>{backup.targetStorage}</code>
              </div>
              <div className="col-12 md:col-6">
                <span className="text-xs text-gray-500 block">ÚLTIMO BACKUP EFETUADO</span>
                <span className="font-bold text-green-400">{backup.lastBackup}</span>
              </div>
            </div>
            <Button
              label="Executar Backup Criptografado Imediato"
              icon="pi pi-save"
              severity="success"
              onClick={handleTriggerBackup}
              loading={backingUp}
            />
          </Card>
        </TabPanel>
      </TabView>
    </div>
  );
};
