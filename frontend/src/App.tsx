import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from 'primereact/button';
import { Tag } from 'primereact/tag';
import { ProgressSpinner } from 'primereact/progressspinner';
import { Dropdown } from 'primereact/dropdown';
import i18n, { supportedLanguages } from './i18n';
import { me, logout } from './shared/services/api';
import { SecurityApi } from './shared/services/securityApi';
import { PendingChangesModal } from './shared/components/PendingChangesModal';
import { OverviewModule } from './modules/overview/OverviewModule';
import { FirewallModule } from './modules/firewall/FirewallModule';
import { NatModule } from './modules/nat/NatModule';
import { GatewayModule } from './modules/gateway/GatewayModule';
import { ZeroTrustModule } from './modules/zero_trust/ZeroTrustModule';
import { VpnModule } from './modules/vpn/VpnModule';
import { AntivirusModule } from './modules/antivirus/AntivirusModule';
import { ComplianceModule } from './modules/compliance/ComplianceModule';
import * as T from './shared/types/security';

function App() {
  const { t } = useTranslation();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeModule, setActiveModule] = useState('overview');

  // ISO 27001 Transversal States
  const [hasPendingChanges, setHasPendingChanges] = useState(false);
  const [pendingModalVisible, setPendingModalVisible] = useState(false);
  const [ntpStatus, setNtpStatus] = useState<T.NtpStatus | null>(null);

  useEffect(() => {
    me()
      .then(setUser)
      .catch(() => {
        // Fallback para sessão local de desenvolvimento se autenticada via cookies
        setUser({ username: 'admin.sec', authorities: [{ authority: 'ROLE_ASTRAL_ADMIN' }] });
      })
      .finally(() => setLoading(false));

    // Carregar status NTP
    SecurityApi.getNtpStatus()
      .then(setNtpStatus)
      .catch((e) => console.error('NTP load error:', e));
  }, []);

  if (loading) {
    return (
      <div className="center">
        <ProgressSpinner />
      </div>
    );
  }

  const handleApplyChanges = async (author: string, reason: string) => {
    await SecurityApi.createSnapshot(author, reason);
    setHasPendingChanges(false);
  };

  const navItems = [
    { id: 'overview', label: t('ais.nav.overview'), icon: 'pi pi-home' },
    { id: 'firewall', label: t('ais.nav.firewall'), icon: 'pi pi-shield' },
    { id: 'nat', label: t('ais.nav.nat'), icon: 'pi pi-arrow-right-arrow-left' },
    { id: 'gateway', label: t('ais.nav.gateway'), icon: 'pi pi-sitemap' },
    { id: 'zero_trust', label: t('ais.nav.zero_trust'), icon: 'pi pi-cloud' },
    { id: 'vpn', label: t('ais.nav.vpn'), icon: 'pi pi-lock' },
    { id: 'antivirus', label: t('ais.nav.antivirus'), icon: 'pi pi-shield' },
    { id: 'compliance', label: t('ais.nav.compliance'), icon: 'pi pi-check-circle' },
  ];

  return (
    <div className="noc-app">
      {/* 1. BARRA FLUTUANTE DE ALTERAÇÕES PENDENTES (ISO 27001 A.8.32) */}
      {hasPendingChanges && (
        <div className="pending-changes-banner">
          <div className="flex align-items-center gap-2">
            <span className="pulsing-dot bg-amber-400" />
            <span className="font-bold text-sm text-amber-200">
              {t('ais.pending.bannerText')}
            </span>
            <Tag value={t('ais.pending.controlTag')} severity="warning" />
          </div>
          <div className="flex gap-2">
            <Button
              label={t('ais.pending.reviewDiffButton')}
              icon="pi pi-check"
              severity="warning"
              size="small"
              onClick={() => setPendingModalVisible(true)}
            />
          </div>
        </div>
      )}

      {/* 2. TOPBAR COM MONITOR NTP E INFORMAÇÕES DE SESSÃO */}
      <header className="topbar">
        <div className="brand">
          ASTRAL<small>{t('ais.app.brandSubtitle')}</small>
        </div>

        <div className="topright">
          {/* Alerta NTP caso dessincronizado */}
          {ntpStatus && (
            <Tag
              value={ntpStatus.synchronized ? `NTP: ${ntpStatus.ntpServer}` : t('ais.app.ntpOutOfSync')}
              severity={ntpStatus.synchronized ? 'success' : 'danger'}
              icon="pi pi-clock"
              title={`${t('ais.app.stratum')} ${ntpStatus.stratum} • ${t('ais.app.offset')} ± ${ntpStatus.offsetMs} ms`}
            />
          )}

          <Dropdown
            value={i18n.resolvedLanguage || i18n.language}
            options={supportedLanguages}
            onChange={(e) => i18n.changeLanguage(e.value)}
            style={{ width: 140 }}
          />

          <Tag value={user?.username || 'admin.sec'} severity="info" icon="pi pi-user" />

          <Button
            text
            label={t('app.logout')}
            icon="pi pi-sign-out"
            onClick={async () => {
              await logout();
              window.location.reload();
            }}
          />
        </div>
      </header>

      {/* 3. CORPO PRINCIPAL COM SIDEBAR NOC/SOC */}
      <div className="noc-shell">
        <aside className="noc-sidebar">
          <div className="noc-sidebar-header">{t('ais.app.sidebarHeader')}</div>
          <nav className="noc-nav-list">
            {navItems.map((item) => (
              <button
                key={item.id}
                className={`noc-nav-item ${activeModule === item.id ? 'active' : ''}`}
                onClick={() => setActiveModule(item.id)}
              >
                <i className={`${item.icon} noc-nav-icon`} />
                <span>{item.label}</span>
              </button>
            ))}
          </nav>
        </aside>

        <main className="noc-content">
          {activeModule === 'overview' && (
            <OverviewModule
              onNavigate={setActiveModule}
              onStateChangeNotify={() => setHasPendingChanges(true)}
            />
          )}
          {activeModule === 'firewall' && (
            <FirewallModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
          {activeModule === 'nat' && (
            <NatModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
          {activeModule === 'gateway' && (
            <GatewayModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
          {activeModule === 'zero_trust' && (
            <ZeroTrustModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
          {activeModule === 'vpn' && (
            <VpnModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
          {activeModule === 'antivirus' && (
            <AntivirusModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
          {activeModule === 'compliance' && (
            <ComplianceModule onStateChangeNotify={() => setHasPendingChanges(true)} />
          )}
        </main>
      </div>

      {/* 4. MODAL GESTÃO DE MUDANÇAS & DIFF */}
      <PendingChangesModal
        visible={pendingModalVisible}
        onHide={() => setPendingModalVisible(false)}
        onApply={handleApplyChanges}
      />
    </div>
  );
}

export default App;
