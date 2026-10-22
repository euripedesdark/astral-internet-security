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

export const AntivirusModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const [status, setStatus] = useState<T.ClamAvStatus>({
    clamdActive: true,
    freshclamLastUpdate: new Date().toISOString(),
    signaturesTotal: 8645210,
    icapBridgeActive: true,
    scannedFilesCount: 53120,
    threatsDetectedCount: 14,
  });
  const [limits, setLimits] = useState<T.DecompressionLimits>({
    maxRecursion: 8,
    maxStreamSizeMb: 100,
    scanTimeoutSeconds: 30,
  });
  const [bypass, setBypass] = useState<T.AntivirusBypass>({
    bypassMediaStreams: true,
    bypassSignedOsUpdates: true,
  });
  const [quarantine, setQuarantine] = useState<T.QuarantineItem[]>([]);
  const [updating, setUpdating] = useState(false);

  const loadData = async () => {
    try {
      const [s, l, b, q] = await Promise.all([
        SecurityApi.getAvStatus(),
        SecurityApi.getAvLimits(),
        SecurityApi.getAvBypass(),
        SecurityApi.getQuarantine(),
      ]);
      setStatus(s);
      setLimits(l);
      setBypass(b);
      setQuarantine(q);
    } catch (e) {
      console.error('Error loading Antivirus data:', e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleForceUpdate = async () => {
    setUpdating(true);
    try {
      const updated = await SecurityApi.triggerAvUpdate();
      setStatus(updated);
      onStateChangeNotify();
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="noc-module">
      {/* STATUS DO MOTOR */}
      <div className="grid mb-4">
        <div className="col-12 md:col-3">
          <Card className="noc-card text-center">
            <span className="text-xs text-gray-500 block">DAEMON CLAMD</span>
            <Tag value={status.clamdActive ? 'OPERACIONAL' : 'PARADO'} severity={status.clamdActive ? 'success' : 'danger'} className="mt-2 text-sm" />
          </Card>
        </div>
        <div className="col-12 md:col-3">
          <Card className="noc-card text-center">
            <span className="text-xs text-gray-500 block">PONTE ICAP / STREAMING</span>
            <Tag value={status.icapBridgeActive ? 'ICAP ATIVO' : 'OFFLINE'} severity={status.icapBridgeActive ? 'info' : 'warning'} className="mt-2 text-sm" />
          </Card>
        </div>
        <div className="col-12 md:col-3">
          <Card className="noc-card text-center">
            <span className="text-xs text-gray-500 block">TOTAL DE ASSINATURAS</span>
            <span className="font-bold font-orbitron text-cyan-400 text-xl block mt-1">
              {status.signaturesTotal.toLocaleString()}
            </span>
          </Card>
        </div>
        <div className="col-12 md:col-3">
          <Card className="noc-card text-center">
            <span className="text-xs text-gray-500 block">AMEAÇAS BLOQUEADAS</span>
            <span className="font-bold font-orbitron text-red-400 text-xl block mt-1">
              {status.threatsDetectedCount}
            </span>
          </Card>
        </div>
      </div>

      <div className="flex justify-content-between align-items-center mb-4 p-3 border-1 border-gray-800 rounded bg-black-alpha-40">
        <div>
          <span className="text-sm font-bold text-gray-300 block">Última Atualização de Assinaturas (freshclam):</span>
          <span className="text-xs text-cyan-400 font-mono">{status.freshclamLastUpdate}</span>
        </div>
        <Button
          label="Forçar Atualização de Assinaturas Agora"
          icon="pi pi-cloud-download"
          severity="success"
          size="small"
          onClick={handleForceUpdate}
          loading={updating}
        />
      </div>

      <TabView className="noc-tabs">
        {/* ABA 1: QUARENTENA CRIPTOGRAFADA */}
        <TabPanel header="Quarentena Forense" leftIcon="pi pi-box mr-2">
          <p className="text-xs text-gray-300 mb-3">
            Arquivos infectados bloqueados no gateway e mantidos em cofre criptografado para inspeção forense (ISO 27001 A.8.7).
          </p>

          <DataTable value={quarantine} size="small" className="noc-table" emptyMessage="Nenhum arquivo em quarentena. Gateway 100% seguro.">
            <Column field="fileName" header="Nome do Arquivo" className="font-bold text-red-300" />
            <Column field="threatName" header="Ameaça Detectada" body={(q: T.QuarantineItem) => <Tag value={q.threatName} severity="danger" />} />
            <Column field="timestamp" header="Data / Hora da Detecção" />
            <Column field="fileSizeBytes" header="Tamanho" body={(q: T.QuarantineItem) => `${(q.fileSizeBytes / 1024).toFixed(1)} KB`} />
            <Column
              header="Ações"
              body={(q: T.QuarantineItem) => (
                <div className="flex gap-2">
                  <Button
                    icon="pi pi-trash"
                    label="Excluir Definitivamente"
                    severity="danger"
                    size="small"
                    onClick={async () => {
                      await SecurityApi.deleteQuarantine(q.id);
                      setQuarantine(quarantine.filter((x) => x.id !== q.id));
                      onStateChangeNotify();
                    }}
                  />
                  <Button
                    icon="pi pi-unlock"
                    label="Liberar Falso Positivo"
                    severity="warning"
                    outlined
                    size="small"
                    onClick={() => {
                      const reason = prompt('Informe a justificativa para liberar falso positivo:');
                      if (reason) {
                        SecurityApi.deleteQuarantine(q.id);
                        setQuarantine(quarantine.filter((x) => x.id !== q.id));
                        onStateChangeNotify();
                      }
                    }}
                  />
                </div>
              )}
            />
          </DataTable>
        </TabPanel>

        {/* ABA 2: LIMITES & PROTEÇÃO CONTRA ZIP BOMBS */}
        <TabPanel header="Limites & Bypass Inteligente" leftIcon="pi pi-sliders-v mr-2">
          <div className="grid">
            <div className="col-12 md:col-6">
              <Card title="Proteção contra Bombas de Descompactação (Zip Bombs)" className="noc-card mb-3">
                <div className="field mb-3">
                  <label className="text-xs font-bold text-gray-300">Recursão Máxima de Arquivos Compactados (.zip, .rar, .tar.gz):</label>
                  <InputText
                    type="number"
                    value={String(limits.maxRecursion)}
                    onChange={(e) => setLimits({ ...limits, maxRecursion: +e.target.value })}
                  />
                </div>
                <div className="field mb-3">
                  <label className="text-xs font-bold text-gray-300">Tamanho Máximo de Stream por Arquivo (MB):</label>
                  <InputText
                    type="number"
                    value={String(limits.maxStreamSizeMb)}
                    onChange={(e) => setLimits({ ...limits, maxStreamSizeMb: +e.target.value })}
                  />
                </div>
                <div className="field mb-3">
                  <label className="text-xs font-bold text-gray-300">Timeout Limite de Varredura (segundos):</label>
                  <InputText
                    type="number"
                    value={String(limits.scanTimeoutSeconds)}
                    onChange={(e) => setLimits({ ...limits, scanTimeoutSeconds: +e.target.value })}
                  />
                </div>
                <Button
                  label="Salvar Parâmetros de Varredura"
                  severity="info"
                  size="small"
                  onClick={async () => {
                    await SecurityApi.setAvLimits(limits);
                    onStateChangeNotify();
                  }}
                />
              </Card>
            </div>

            <div className="col-12 md:col-6">
              <Card title="Bypass Inteligente de Performance" className="noc-card mb-3">
                <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
                  <div>
                    <span className="font-bold block">Ignorar Fluxos de Streaming de Mídia Contínuos</span>
                    <small className="text-gray-400">Preserva CPU evitando varredura desnecessária de streams de vídeo/áudio</small>
                  </div>
                  <InputSwitch
                    checked={bypass.bypassMediaStreams}
                    onChange={(e) => {
                      const u = { ...bypass, bypassMediaStreams: e.value };
                      setBypass(u);
                      SecurityApi.setAvBypass(u);
                      onStateChangeNotify();
                    }}
                  />
                </div>
                <div className="flex align-items-center justify-content-between p-2">
                  <div>
                    <span className="font-bold block">Bypass de Atualizações Assinadas do Sistema Operacional</span>
                    <small className="text-gray-400">Microsoft Update, Canonical, RedHat com certificados digitais válidos</small>
                  </div>
                  <InputSwitch
                    checked={bypass.bypassSignedOsUpdates}
                    onChange={(e) => {
                      const u = { ...bypass, bypassSignedOsUpdates: e.value };
                      setBypass(u);
                      SecurityApi.setAvBypass(u);
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
