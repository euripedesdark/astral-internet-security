import React, { useState, useEffect } from 'react';
import { Card } from 'primereact/card';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { Tag } from 'primereact/tag';
import { InputSwitch } from 'primereact/inputswitch';
import { InputText } from 'primereact/inputtext';
import { Dropdown } from 'primereact/dropdown';
import { TabView, TabPanel } from 'primereact/tabview';
import { Dialog } from 'primereact/dialog';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const VpnModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const [vpnConfig, setVpnConfig] = useState<T.OpenVpnConfig>({
    mode: 'RoadWarrior',
    port: 1194,
    protocol: 'UDP',
    cipher: 'AES-256-GCM',
    tlsVersion: '1.3',
    dcoEnabled: true,
    splitTunnel: true,
    subnet: '10.8.0.0/24',
    mfaRequired: true,
  });
  const [certs, setCerts] = useState<T.PkiCert[]>([]);
  const [overrides, setOverrides] = useState<T.ClientSpecificOverride[]>([]);
  const [certDialog, setCertDialog] = useState(false);
  const [formCert, setFormCert] = useState({ commonName: '', certType: 'Client' });

  const loadData = async () => {
    try {
      const [c, pki, ccd] = await Promise.all([
        SecurityApi.getVpnConfig(),
        SecurityApi.getCerts(),
        SecurityApi.getCcdOverrides(),
      ]);
      setVpnConfig(c);
      setCerts(pki);
      setOverrides(ccd);
    } catch (e) {
      console.error('Error loading VPN data:', e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleIssueCert = async () => {
    if (!formCert.commonName) return;
    const res = await SecurityApi.issueCert(formCert.commonName, formCert.certType);
    setCerts([...certs, res]);
    setCertDialog(false);
    onStateChangeNotify();
  };

  const handleRevokeCert = async (id: string) => {
    if (confirm('Revogar este certificado imediatamente? O acesso do usuário será encerrado na mesma hora (CRL ativa).')) {
      await SecurityApi.revokeCert(id);
      setCerts(certs.map((c) => (c.id === id ? { ...c, revoked: true } : c)));
      onStateChangeNotify();
    }
  };

  const handleDownloadOvpn = async (clientName: string) => {
    const profile = await SecurityApi.exportOvpnProfile(clientName);
    const blob = new Blob([profile.inlineProfile], { type: 'application/x-openvpn-profile' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${clientName}.ovpn`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="noc-module">
      <TabView className="noc-tabs">
        {/* ABA 1: PKI & CERTIFICADOS */}
        <TabPanel header="Infraestrutura de Chaves (PKI)" leftIcon="pi pi-key mr-2">
          <div className="flex justify-content-between align-items-center mb-3">
            <span className="text-sm text-gray-300">
              Gerenciador de Autoridade Certificadora local com revogação instantânea via CRL (ISO 27001 A.8.24 / A.6.7).
            </span>
            <Button
              label="Emitir Novo Certificado"
              icon="pi pi-plus"
              size="small"
              severity="success"
              onClick={() => setCertDialog(true)}
            />
          </div>

          <DataTable value={certs} size="small" className="noc-table">
            <Column field="commonName" header="Nome Comum (CN / Usuário)" className="font-bold text-cyan-300" />
            <Column
              field="certType"
              header="Tipo"
              body={(c: T.PkiCert) => <Tag value={c.certType} severity={c.certType === 'CA' ? 'danger' : c.certType === 'Server' ? 'info' : 'success'} />}
            />
            <Column field="serial" header="Serial Hex" body={(c: T.PkiCert) => <code>{c.serial}</code>} />
            <Column
              field="revoked"
              header="Status da Validade"
              body={(c: T.PkiCert) => (
                <Tag
                  value={c.revoked ? 'REVOGADO (CRL)' : 'VÁLIDO / ATIVO'}
                  severity={c.revoked ? 'danger' : 'success'}
                  icon={c.revoked ? 'pi pi-ban' : 'pi pi-check'}
                />
              )}
            />
            <Column
              header="Exportar .ovpn"
              body={(c: T.PkiCert) =>
                c.certType === 'Client' && !c.revoked ? (
                  <Button
                    label="Baixar .ovpn"
                    icon="pi pi-download"
                    size="small"
                    outlined
                    severity="info"
                    onClick={() => handleDownloadOvpn(c.commonName)}
                  />
                ) : null
              }
            />
            <Column
              style={{ width: '6rem' }}
              body={(c: T.PkiCert) =>
                !c.revoked && c.certType !== 'CA' ? (
                  <Button
                    label="Revogar"
                    icon="pi pi-ban"
                    severity="danger"
                    size="small"
                    onClick={() => handleRevokeCert(c.id)}
                  />
                ) : null
              }
            />
          </DataTable>
        </TabPanel>

        {/* ABA 2: SERVIDOR OPENVPN & CRIPTOGRAFIA */}
        <TabPanel header="Servidor OpenVPN & Criptografia" leftIcon="pi pi-lock mr-2">
          <Card title="Criptografia de Alto Padrão (Data Channel Offload)" className="noc-card mb-4">
            <div className="grid">
              <div className="col-12 md:col-4">
                <label className="text-xs font-bold text-gray-400 block mb-1">Cifra de Criptografia Obrigatória</label>
                <Dropdown
                  value={vpnConfig.cipher}
                  options={[
                    { label: 'AES-256-GCM (Recomendado ISO 27001)', value: 'AES-256-GCM' },
                    { label: 'CHACHA20-POLY1305 (Alta Performance Mobile)', value: 'CHACHA20-POLY1305' },
                  ]}
                  onChange={async (e) => {
                    const u = { ...vpnConfig, cipher: e.value };
                    setVpnConfig(u);
                    await SecurityApi.setVpnConfig(u);
                    onStateChangeNotify();
                  }}
                />
              </div>
              <div className="col-12 md:col-4">
                <label className="text-xs font-bold text-gray-400 block mb-1">Porta e Protocolo</label>
                <div className="flex gap-2">
                  <InputText value={String(vpnConfig.port)} className="p-inputtext-sm" readOnly />
                  <Tag value={vpnConfig.protocol} severity="info" />
                </div>
              </div>
              <div className="col-12 md:col-4">
                <label className="text-xs font-bold text-gray-400 block mb-1">Sub-rede Virtual VPN</label>
                <InputText value={vpnConfig.subnet} className="p-inputtext-sm" readOnly />
              </div>
            </div>

            <div className="grid mt-3">
              <div className="col-12 md:col-4 flex align-items-center justify-content-between p-2 border-top-1 border-gray-800">
                <span>Data Channel Offload (DCO no Kernel)</span>
                <InputSwitch
                  checked={vpnConfig.dcoEnabled}
                  onChange={async (e) => {
                    const u = { ...vpnConfig, dcoEnabled: e.value };
                    setVpnConfig(u);
                    await SecurityApi.setVpnConfig(u);
                    onStateChangeNotify();
                  }}
                />
              </div>
              <div className="col-12 md:col-4 flex align-items-center justify-content-between p-2 border-top-1 border-gray-800">
                <span>Autenticação Multifator (TOTP Obrigatório)</span>
                <InputSwitch
                  checked={vpnConfig.mfaRequired}
                  onChange={async (e) => {
                    const u = { ...vpnConfig, mfaRequired: e.value };
                    setVpnConfig(u);
                    await SecurityApi.setVpnConfig(u);
                    onStateChangeNotify();
                  }}
                />
              </div>
              <div className="col-12 md:col-4 flex align-items-center justify-content-between p-2 border-top-1 border-gray-800">
                <span>Split-Tunneling (Apenas tráfego corporativo)</span>
                <InputSwitch
                  checked={vpnConfig.splitTunnel}
                  onChange={async (e) => {
                    const u = { ...vpnConfig, splitTunnel: e.value };
                    setVpnConfig(u);
                    await SecurityApi.setVpnConfig(u);
                    onStateChangeNotify();
                  }}
                />
              </div>
            </div>
          </Card>
        </TabPanel>
      </TabView>

      {/* MODAL EMITIR CERTIFICADO */}
      <Dialog
        visible={certDialog}
        onHide={() => setCertDialog(false)}
        header={<span className="font-bold font-orbitron">Emitir Certificado Digital X.509</span>}
        style={{ width: '480px' }}
        className="noc-dialog p-fluid"
        modal
      >
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Common Name (CN / Usuário ou Host) *</label>
          <InputText
            value={formCert.commonName}
            onChange={(e) => setFormCert({ ...formCert, commonName: e.target.value })}
            placeholder="Ex: joao.silva@empresa.com.br"
          />
        </div>
        <div className="field mb-3">
          <label className="text-xs font-bold text-gray-300">Tipo de Certificado</label>
          <Dropdown
            value={formCert.certType}
            options={[
              { label: 'Cliente (Usuário Road Warrior)', value: 'Client' },
              { label: 'Servidor (Gateway Endpoint)', value: 'Server' },
            ]}
            onChange={(e) => setFormCert({ ...formCert, certType: e.value })}
          />
        </div>
        <div className="flex justify-content-end gap-2 mt-4">
          <Button label="Cancelar" text onClick={() => setCertDialog(false)} />
          <Button label="Emitir Certificado" icon="pi pi-check" severity="success" onClick={handleIssueCert} />
        </div>
      </Dialog>
    </div>
  );
};
