import React, { useState, useEffect } from 'react';
import { Card } from 'primereact/card';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { Tag } from 'primereact/tag';
import { InputSwitch } from 'primereact/inputswitch';
import { InputText } from 'primereact/inputtext';
import { Dialog } from 'primereact/dialog';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const ZeroTrustModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const [tunnel, setTunnel] = useState<T.CloudflareTunnelConfig>({
    tunnelId: 'astral-argo-tunnel-01',
    tunnelName: 'astral-enterprise-edge',
    status: 'Connected',
    activeConnectors: 2,
    ingressRulesCount: 5,
  });
  const [apps, setApps] = useState<T.ZtnaAppPublish[]>([]);
  const [jwt, setJwt] = useState<T.EdgeJwtValidator>({
    enabled: true,
    teamDomain: 'astral-sec.cloudflareaccess.com',
    audienceTag: 'cf-access-aud-astral-erp',
  });
  const [doh, setDoh] = useState<T.DohConfig>({
    dohUrl: 'https://cloudflare-dns.com/dns-query',
    dotFallback: true,
    enabled: true,
  });
  const [appDialog, setAppDialog] = useState(false);
  const [formApp, setFormApp] = useState<Partial<T.ZtnaAppPublish>>({
    hostname: '',
    internalServiceUrl: 'http://192.168.2.10:8080',
    requireMfa: true,
  });

  const loadData = async () => {
    try {
      const [t, a, j, d] = await Promise.all([
        SecurityApi.getTunnelStatus(),
        SecurityApi.getZtnaApps(),
        SecurityApi.getJwtValidator(),
        SecurityApi.getDoh(),
      ]);
      setTunnel(t);
      setApps(a);
      setJwt(j);
      setDoh(d);
    } catch (e) {
      console.error('Error loading Zero Trust:', e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handlePublishApp = async () => {
    if (!formApp.hostname) return;
    const res = await SecurityApi.publishZtnaApp({
      id: '',
      hostname: formApp.hostname,
      internalServiceUrl: formApp.internalServiceUrl || '',
      requireMfa: !!formApp.requireMfa,
    });
    setApps([...apps, res]);
    setAppDialog(false);
    onStateChangeNotify();
  };

  return (
    <div className="noc-module">
      {/* CARD CONECTOR CLOUDFLARED */}
      <Card title="Daemon Conector Nativo Cloudflared (Argo Tunnel)" className="noc-card mb-4">
        <div className="grid align-items-center">
          <div className="col-12 md:col-4">
            <span className="text-xs text-gray-500 block">STATUS DO TÚNEL</span>
            <div className="flex align-items-center gap-2 mt-1">
              <span className="pulsing-dot bg-green-500" />
              <span className="font-bold font-orbitron text-green-400 text-lg">{tunnel.status}</span>
            </div>
            <small className="text-gray-400">Sem portas de entrada abertas no Firewall (Zero Inbound)</small>
          </div>
          <div className="col-12 md:col-4">
            <span className="text-xs text-gray-500 block">CONECTORES ATIVOS</span>
            <span className="font-bold text-xl text-cyan-300">{tunnel.activeConnectors} instâncias redundantes</span>
          </div>
          <div className="col-12 md:col-4 text-right">
            <Button
              label="Reiniciar Conector cloudflared"
              icon="pi pi-refresh"
              severity="secondary"
              size="small"
              onClick={() => alert('Sinal de reinicialização enviado ao daemon cloudflared')}
            />
          </div>
        </div>
      </Card>

      {/* PUBLICAÇÃO DE APLICAÇÕES INTERNAS */}
      <Card
        title={
          <div className="flex justify-content-between align-items-center">
            <span>Publicação de Aplicações via ZTNA (Cloudflare Access)</span>
            <Button
              label="Publicar Novo Subdomínio"
              icon="pi pi-plus"
              size="small"
              severity="success"
              onClick={() => setAppDialog(true)}
            />
          </div>
        }
        className="noc-card mb-4"
      >
        <p className="text-xs text-gray-300 mb-3">
          Sistemas internos roteados diretamente para subdomínios protegidos na nuvem com autenticação MFA obrigatória antes que o pacote atinja a rede local (ISO 27001 A.5.15).
        </p>

        <DataTable value={apps} size="small" className="noc-table">
          <Column field="hostname" header="Domínio Público Externo" className="font-bold text-cyan-300" />
          <Column field="internalServiceUrl" header="Endereço do Serviço Interno" body={(a: T.ZtnaAppPublish) => <code>{a.internalServiceUrl}</code>} />
          <Column
            field="requireMfa"
            header="Autenticação Nuvem"
            body={(a: T.ZtnaAppPublish) => (
              <Tag value={a.requireMfa ? 'MFA / SSO Obrigatório' : 'Acesso Público'} severity={a.requireMfa ? 'success' : 'warning'} />
            )}
          />
          <Column
            style={{ width: '4rem' }}
            body={(a: T.ZtnaAppPublish) => (
              <Button
                icon="pi pi-trash"
                severity="danger"
                text
                size="small"
                onClick={async () => {
                  await SecurityApi.deleteZtnaApp(a.id);
                  setApps(apps.filter((x) => x.id !== a.id));
                  onStateChangeNotify();
                }}
              />
            )}
          />
        </DataTable>
      </Card>

      {/* POLÍTICAS DE BORDA & DoH */}
      <div className="grid">
        <div className="col-12 md:col-6">
          <Card title="Validação de JWT de Borda (Cf-Access-Jwt-Assertion)" className="noc-card">
            <p className="text-xs text-gray-300 mb-3">
              Garante que nenhuma requisição passe sem autenticação prévia validada pelo header criptográfico da Cloudflare.
            </p>
            <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
              <span className="font-bold">Exigir Asserção JWT</span>
              <InputSwitch
                checked={jwt.enabled}
                onChange={async (e) => {
                  const u = { ...jwt, enabled: e.value };
                  setJwt(u);
                  await SecurityApi.setJwtValidator(u);
                  onStateChangeNotify();
                }}
              />
            </div>
            <div className="field">
              <label className="text-xs text-gray-400">Team Domain Cloudflare Access:</label>
              <code>{jwt.teamDomain}</code>
            </div>
          </Card>
        </div>

        <div className="col-12 md:col-6">
          <Card title="DNS over HTTPS (DoH) / DNS over TLS" className="noc-card">
            <p className="text-xs text-gray-300 mb-3">
              Encaminhamento criptografado de consultas DNS para o Cloudflare Gateway filtrado.
            </p>
            <div className="flex align-items-center justify-content-between mb-3 p-2 border-bottom-1 border-gray-800">
              <span className="font-bold">Resolução DoH Ativa</span>
              <InputSwitch
                checked={doh.enabled}
                onChange={async (e) => {
                  const u = { ...doh, enabled: e.value };
                  setDoh(u);
                  await SecurityApi.setDoh(u);
                  onStateChangeNotify();
                }}
              />
            </div>
            <div className="field">
              <label className="text-xs text-gray-400">Endpoint DoH Gateway:</label>
              <code>{doh.dohUrl}</code>
            </div>
          </Card>
        </div>
      </div>

      {/* MODAL NOVO APP */}
      <Dialog
        visible={appDialog}
        onHide={() => setAppDialog(false)}
        header={<span className="font-bold font-orbitron">Publicar Aplicação Interna no ZTNA</span>}
        style={{ width: '500px' }}
        className="noc-dialog p-fluid"
        modal
      >
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Hostname Público Externo *</label>
          <InputText
            value={formApp.hostname}
            onChange={(e) => setFormApp({ ...formApp, hostname: e.target.value })}
            placeholder="Ex: erp.empresa.com.br"
          />
        </div>
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Endereço do Serviço Interno Local *</label>
          <InputText
            value={formApp.internalServiceUrl}
            onChange={(e) => setFormApp({ ...formApp, internalServiceUrl: e.target.value })}
            placeholder="http://192.168.2.10:8080"
          />
        </div>
        <div className="flex align-items-center justify-content-between p-2 border-1 border-gray-800 rounded">
          <span>Exigir Autenticação Multifator (MFA/SSO)</span>
          <InputSwitch
            checked={!!formApp.requireMfa}
            onChange={(e) => setFormApp({ ...formApp, requireMfa: e.value })}
          />
        </div>
        <div className="flex justify-content-end gap-2 mt-4">
          <Button label="Cancelar" text onClick={() => setAppDialog(false)} />
          <Button label="Publicar Rota" icon="pi pi-check" severity="success" onClick={handlePublishApp} />
        </div>
      </Dialog>
    </div>
  );
};
