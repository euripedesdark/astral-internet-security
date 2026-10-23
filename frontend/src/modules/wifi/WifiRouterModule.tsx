import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Card } from 'primereact/card';
import { Button } from 'primereact/button';
import { InputText } from 'primereact/inputtext';
import { Dropdown } from 'primereact/dropdown';
import { InputSwitch } from 'primereact/inputswitch';
import { Tag } from 'primereact/tag';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onStateChangeNotify: () => void;
}

export const WifiRouterModule: React.FC<Props> = ({ onStateChangeNotify }) => {
  const { t } = useTranslation();
  const [wifiStatus, setWifiStatus] = useState<T.WifiRouterStatus | null>(null);
  const [interfaces, setInterfaces] = useState<T.NetworkInterfaceInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState<T.WifiHotspotConfig>({
    interfaceName: 'wlp2s0',
    ssid: 'Astral-Secure-WiFi',
    password: 'astral_secure_wifi',
    band: 'bg',
    channel: 6,
    ipGateway: '10.42.0.1/24',
    enableNatRouting: true,
    wanInterface: 'enp0s20u2',
  });

  const loadData = async () => {
    try {
      const [w, ifaces] = await Promise.all([
        SecurityApi.getWifiStatus(),
        SecurityApi.getInterfaces(),
      ]);
      setWifiStatus(w);
      setInterfaces(ifaces);
      if (w.interfaceName) {
        setForm((prev) => ({
          ...prev,
          interfaceName: w.interfaceName || 'wlp2s0',
          ssid: w.ssid || prev.ssid,
          ipGateway: w.ipGateway || prev.ipGateway,
        }));
      }
    } catch (err) {
      console.error('Error loading Wi-Fi router data:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleStartHotspot = async () => {
    setLoading(true);
    try {
      const res = await SecurityApi.startWifiHotspot(form);
      if (res.success) {
        setWifiStatus(res.wifi);
        onStateChangeNotify();
      }
    } catch (e: any) {
      alert('Erro ao ativar Roteador Wi-Fi: ' + (e.message || e));
    } finally {
      setLoading(false);
    }
  };

  const handleStopHotspot = async () => {
    setLoading(true);
    try {
      const res = await SecurityApi.stopWifiHotspot();
      if (res.success) {
        setWifiStatus(res.wifi);
        onStateChangeNotify();
      }
    } catch (e: any) {
      alert('Erro ao desativar Roteador Wi-Fi: ' + (e.message || e));
    } finally {
      setLoading(false);
    }
  };

  if (!wifiStatus?.hasWifi) {
    return (
      <div className="noc-module p-4">
        <Card className="noc-card text-center">
          <i className="pi pi-exclamation-circle text-4xl text-amber-400 mb-3 block" />
          <h3 className="text-xl font-bold font-orbitron text-gray-200">
            Nenhuma Placa Wi-Fi Detectada no Sistema
          </h3>
          <p className="text-gray-400 max-w-28rem mx-auto mt-2 text-sm">
            O firewall examinou os dispositivos de rede (sysfs/iw) e não encontrou uma interface sem fio conectada.
            Para ativar a função de roteador Wi-Fi, conecte uma placa Wi-Fi compatível com modo Ponto de Acesso (AP).
          </p>
        </Card>
      </div>
    );
  }

  const wanOptions = interfaces
    .filter((i) => !i.isWireless)
    .map((i) => ({
      label: `${i.name} ${i.ip ? `(${i.ip})` : ''} - ${i.suggestedRole}`,
      value: i.name,
    }));

  return (
    <div className="noc-module">
      <div className="grid">
        {/* CARD DE STATUS DO ROTEADOR WI-FI */}
        <div className="col-12 md:col-5">
          <Card className="noc-card mb-4" title={<span className="font-orbitron text-cyan-300">Status do Roteador Wi-Fi</span>}>
            <div className="flex justify-content-between align-items-center mb-4 p-3 bg-gray-900 border-round border-1 border-gray-800">
              <div>
                <span className="text-xs text-gray-500 block">ESTADO OPERACIONAL</span>
                <span className="text-lg font-bold font-orbitron">
                  {wifiStatus.isActive ? 'PONTO DE ACESSO ATIVO' : 'ROTEADOR DESLIGADO'}
                </span>
              </div>
              <Tag
                value={wifiStatus.isActive ? 'ONLINE (AP)' : 'DESATIVADO'}
                severity={wifiStatus.isActive ? 'success' : 'danger'}
                icon={wifiStatus.isActive ? 'pi pi-wifi' : 'pi pi-power-off'}
              />
            </div>

            <div className="grid text-sm text-gray-300">
              <div className="col-6 mb-2">
                <span className="text-xs text-gray-500 block">INTERFACE WIRELESS</span>
                <code>{wifiStatus.interfaceName || 'wlp2s0'}</code>
              </div>
              <div className="col-6 mb-2">
                <span className="text-xs text-gray-500 block">REDE (SSID)</span>
                <code className="text-cyan-400">{wifiStatus.ssid || form.ssid}</code>
              </div>
              <div className="col-6 mb-2">
                <span className="text-xs text-gray-500 block">GATEWAY WI-FI (DHCP)</span>
                <code>{wifiStatus.ipGateway || '10.42.0.1'}</code>
              </div>
              <div className="col-6 mb-2">
                <span className="text-xs text-gray-500 block">DISPOSITIVOS CONECTADOS</span>
                <span className="font-bold text-green-400 font-orbitron text-base">
                  {wifiStatus.clientsCount} clientes
                </span>
              </div>
              <div className="col-12 mt-2">
                <span className="text-xs text-gray-500 block mb-1">MODOS DE HARDWARE SUPORTADOS</span>
                <div className="flex gap-1 flex-wrap">
                  {(wifiStatus.modeSupported || []).map((m, idx) => (
                    <Tag key={idx} value={m} severity="info" />
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-top-1 border-gray-800 flex justify-content-between">
              <Button
                label="Atualizar Status"
                icon="pi pi-refresh"
                size="small"
                text
                onClick={loadData}
              />
              {wifiStatus.isActive ? (
                <Button
                  label="Desativar Roteador Wi-Fi"
                  icon="pi pi-power-off"
                  severity="danger"
                  size="small"
                  loading={loading}
                  onClick={handleStopHotspot}
                />
              ) : (
                <Button
                  label="Ativar Roteador Wi-Fi"
                  icon="pi pi-wifi"
                  severity="success"
                  size="small"
                  loading={loading}
                  onClick={handleStartHotspot}
                />
              )}
            </div>
          </Card>
        </div>

        {/* CARD DE CONFIGURAÇÃO DO ROTEADOR WI-FI */}
        <div className="col-12 md:col-7">
          <Card className="noc-card mb-4" title={<span className="font-orbitron text-cyan-300">Configuração de Ponto de Acesso (AP)</span>}>
            <p className="text-xs text-gray-400 mb-4">
              Configure o SSID, credenciais WPA2/WPA3 e o roteamento NAT integrado para transformar o firewall em um Ponto de Acesso Wi-Fi de alta performance.
            </p>

            <div className="grid p-fluid">
              <div className="col-12 md:col-6 field mb-3">
                <label className="text-xs font-bold text-gray-300">Nome da Rede Wi-Fi (SSID) *</label>
                <InputText
                  value={form.ssid}
                  onChange={(e) => setForm({ ...form, ssid: e.target.value })}
                  placeholder="Ex: Astral-WiFi"
                />
              </div>

              <div className="col-12 md:col-6 field mb-3">
                <label className="text-xs font-bold text-gray-300">Senha WPA2-PSK (Mínimo 8 dígitos) *</label>
                <InputText
                  type="password"
                  value={form.password || ''}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="Chave de segurança..."
                />
              </div>

              <div className="col-12 md:col-6 field mb-3">
                <label className="text-xs font-bold text-gray-300">Banda de Transmissão</label>
                <Dropdown
                  value={form.band}
                  options={[
                    { label: '2.4 GHz (bg) - Maior Alcance', value: 'bg' },
                    { label: '5 GHz (a) - Maior Velocidade', value: 'a' },
                  ]}
                  onChange={(e) => setForm({ ...form, band: e.value })}
                />
              </div>

              <div className="col-12 md:col-6 field mb-3">
                <label className="text-xs font-bold text-gray-300">Canal de Transmissão</label>
                <Dropdown
                  value={form.channel}
                  options={[
                    { label: 'Canal 6 (Padrão Recomendado)', value: 6 },
                    { label: 'Canal 1', value: 1 },
                    { label: 'Canal 11', value: 11 },
                    { label: 'Automático', value: 0 },
                  ]}
                  onChange={(e) => setForm({ ...form, channel: e.value })}
                />
              </div>

              <div className="col-12 md:col-6 field mb-3">
                <label className="text-xs font-bold text-gray-300">Interface WAN de Saída (Internet)</label>
                <Dropdown
                  value={form.wanInterface}
                  options={wanOptions}
                  onChange={(e) => setForm({ ...form, wanInterface: e.value })}
                />
              </div>

              <div className="col-12 md:col-6 field mb-3">
                <label className="text-xs font-bold text-gray-300">Faixa de IP do Gateway Wi-Fi</label>
                <InputText
                  value={form.ipGateway}
                  onChange={(e) => setForm({ ...form, ipGateway: e.target.value })}
                  placeholder="10.42.0.1/24"
                />
              </div>

              <div className="col-12 mt-2">
                <div className="flex align-items-center justify-content-between p-3 bg-gray-900 border-round border-1 border-gray-800">
                  <div>
                    <span className="font-bold text-sm text-gray-200 block">Roteamento NAT & Masquerade Automático</span>
                    <small className="text-gray-400">
                      Permite que os dispositivos conectados à rede Wi-Fi naveguem pela Internet através da interface WAN ({form.wanInterface}).
                    </small>
                  </div>
                  <InputSwitch
                    checked={form.enableNatRouting}
                    onChange={(e) => setForm({ ...form, enableNatRouting: e.value })}
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-content-end gap-2 mt-4 pt-3 border-top-1 border-gray-800">
              <Button
                label="Salvar e Iniciar Ponto de Acesso"
                icon="pi pi-check"
                severity="success"
                loading={loading}
                onClick={handleStartHotspot}
              />
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
