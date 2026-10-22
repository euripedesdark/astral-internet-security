import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Card } from 'primereact/card';
import { Tag } from 'primereact/tag';
import { Button } from 'primereact/button';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { SecurityApi } from '../../shared/services/securityApi';
import * as T from '../../shared/types/security';

interface Props {
  onNavigate: (module: string) => void;
  onStateChangeNotify: () => void;
}

export const OverviewModule: React.FC<Props> = ({ onNavigate, onStateChangeNotify }) => {
  const { t } = useTranslation();
  const [fwState, setFwState] = useState<T.FirewallState | null>(null);
  const [stats, setStats] = useState<T.InterfaceStat[]>([]);
  const [panicConfirm, setPanicConfirm] = useState(false);

  const loadData = async () => {
    try {
      const [st, ifaces] = await Promise.all([
        SecurityApi.getFirewallState(),
        SecurityApi.getStats(),
      ]);
      setFwState(st);
      setStats(ifaces.interfaces || []);
    } catch (e) {
      console.error('Error loading overview:', e);
    }
  };

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 5000);
    return () => clearInterval(id);
  }, []);

  const handleTogglePanic = async () => {
    if (!fwState) return;
    const next = !fwState.panicMode;
    await SecurityApi.setPanicMode(next);
    setFwState({ ...fwState, panicMode: next });
    setPanicConfirm(false);
    onStateChangeNotify();
  };

  return (
    <div className="noc-module">
      {/* PANIC MODE BANNER SE ATIVO */}
      {fwState?.panicMode && (
        <div className="panic-alert-box mb-4">
          <i className="pi pi-exclamation-triangle text-3xl mr-3" />
          <div className="flex-1">
            <h3 className="m-0 font-orbitron">{t('ais.overview.panicTitle')}</h3>
            <p className="m-0 text-xs">{t('ais.overview.panicDesc')}</p>
          </div>
          <Button label={t('ais.overview.deactivatePanic')} severity="contrast" onClick={handleTogglePanic} />
        </div>
      )}

      {/* METRIC CARDS */}
      <div className="grid mb-4">
        <div className="col-12 sm:col-6 lg:col-3">
          <Card className="noc-metric-card">
            <span className="noc-metric-label">{t('ais.overview.firewallState')}</span>
            <div className="flex align-items-center justify-content-between mt-2">
              <span className="font-bold text-2xl font-orbitron text-green-400">{t('ais.overview.spiActive')}</span>
              <Tag value="ISO 27001" severity="success" />
            </div>
            <small className="text-gray-400">{t('ais.overview.defaultPolicy')}: {fwState?.defaultPolicy || 'DROP'}</small>
          </Card>
        </div>

        <div className="col-12 sm:col-6 lg:col-3">
          <Card className="noc-metric-card">
            <span className="noc-metric-label">{t('ais.overview.activeConnections')}</span>
            <div className="flex align-items-center justify-content-between mt-2">
              <span className="font-bold text-2xl font-orbitron text-cyan-400">
                {(fwState?.activeConnections || 1240).toLocaleString()}
              </span>
              <i className="pi pi-share-alt text-cyan-400 text-xl" />
            </div>
            <small className="text-gray-400">{t('ais.overview.statefulTable')}</small>
          </Card>
        </div>

        <div className="col-12 sm:col-6 lg:col-3">
          <Card className="noc-metric-card">
            <span className="noc-metric-label">{t('ais.overview.activeRules')}</span>
            <div className="flex align-items-center justify-content-between mt-2">
              <span className="font-bold text-2xl font-orbitron text-cyan-300">
                {fwState?.rulesCount || 16}
              </span>
              <i className="pi pi-shield text-cyan-400 text-xl" />
            </div>
            <small className="text-gray-400">{t('ais.overview.zonesSub')}</small>
          </Card>
        </div>

        <div className="col-12 sm:col-6 lg:col-3">
          <Card className="noc-metric-card">
            <span className="noc-metric-label">{t('ais.overview.panicButton')}</span>
            {!panicConfirm ? (
              <Button
                label={t('ais.overview.triggerPanic')}
                icon="pi pi-power-off"
                severity="danger"
                className="mt-2 w-full font-orbitron"
                size="small"
                onClick={() => setPanicConfirm(true)}
              />
            ) : (
              <div className="flex gap-2 mt-2">
                <Button label={t('ais.overview.confirmDrop')} severity="danger" size="small" onClick={handleTogglePanic} />
                <Button label="X" text severity="secondary" size="small" onClick={() => setPanicConfirm(false)} />
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* QUICK LAUNCH GRID DOS 6 MÓDULOS */}
      <h3 className="font-orbitron text-sm text-gray-400 mb-3 tracking-widest">{t('ais.overview.operationalModules')}</h3>
      <div className="grid mb-4">
        {[
          { id: 'firewall', title: t('ais.modules.firewall.title'), desc: t('ais.modules.firewall.desc'), icon: 'pi pi-shield', color: '#00d2ff' },
          { id: 'nat', title: t('ais.modules.nat.title'), desc: t('ais.modules.nat.desc'), icon: 'pi pi-arrow-right-arrow-left', color: '#00e5ff' },
          { id: 'gateway', title: t('ais.modules.gateway.title'), desc: t('ais.modules.gateway.desc'), icon: 'pi pi-sitemap', color: '#57e389' },
          { id: 'zero_trust', title: t('ais.modules.zero_trust.title'), desc: t('ais.modules.zero_trust.desc'), icon: 'pi pi-cloud', color: '#f59e0b' },
          { id: 'vpn', title: t('ais.modules.vpn.title'), desc: t('ais.modules.vpn.desc'), icon: 'pi pi-lock', color: '#a855f7' },
          { id: 'antivirus', title: t('ais.modules.antivirus.title'), desc: t('ais.modules.antivirus.desc'), icon: 'pi pi-shield', color: '#ef4444' },
        ].map((m) => (
          <div key={m.id} className="col-12 md:col-4">
            <Card
              className="noc-card noc-module-launcher"
              onClick={() => onNavigate(m.id)}
            >
              <div className="flex align-items-center gap-3">
                <i className={`${m.icon} text-2xl`} style={{ color: m.color }} />
                <div>
                  <span className="font-bold block text-sm font-orbitron text-gray-100">{m.title}</span>
                  <p className="text-xs text-gray-400 m-0 mt-1">{m.desc}</p>
                </div>
              </div>
            </Card>
          </div>
        ))}
      </div>

      {/* INTERFACES NETWORK METRICS TABLE */}
      <Card title={t('ais.overview.interfaceTrafficTitle')} className="noc-card">
        <DataTable value={stats} size="small" className="noc-table" emptyMessage={t('ais.overview.collectingKernelStats')}>
          <Column field="name" header={t('ais.overview.colInterface')} className="font-bold text-cyan-300 font-mono" />
          <Column
            field="rxBytes"
            header={t('ais.overview.colRxBytes')}
            body={(s: T.InterfaceStat) => (
              <span className="text-green-400 font-mono">{(s.rxBytes / 1024 / 1024).toFixed(2)} MB</span>
            )}
          />
          <Column
            field="txBytes"
            header={t('ais.overview.colTxBytes')}
            body={(s: T.InterfaceStat) => (
              <span className="text-cyan-400 font-mono">{(s.txBytes / 1024 / 1024).toFixed(2)} MB</span>
            )}
          />
        </DataTable>
      </Card>
    </div>
  );
};
