import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Dialog } from 'primereact/dialog';
import { Button } from 'primereact/button';
import { InputTextarea } from 'primereact/inputtextarea';
import { InputText } from 'primereact/inputtext';
import { Tag } from 'primereact/tag';

interface Props {
  visible: boolean;
  onHide: () => void;
  onApply: (author: string, reason: string) => Promise<void>;
  diffBefore?: string;
  diffAfter?: string;
}

export const PendingChangesModal: React.FC<Props> = ({
  visible,
  onHide,
  onApply,
  diffBefore,
  diffAfter,
}) => {
  const { t } = useTranslation();
  const [author, setAuthor] = useState('admin.sec@astral.corp');
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const defaultBefore = diffBefore || `// Configuração Ativa (Revisão Anterior)
firewall.policy.default = "DROP"
rules.count = 8
nat.masquerade.wan0 = true
alg.sip = false
`;

  const defaultAfter = diffAfter || `// Alterações Pendentes a serem Aplicadas
firewall.policy.default = "DROP"
rules.count = 9
+ rule: "Permitir HTTPS Interno" (TCP 443 LAN->DMZ, Log: ON)
+ bogon.filter.wan0 = true (Anti-Spoofing RFC 1918)
nat.masquerade.wan0 = true
alg.sip = false
`;

  const handleConfirm = async () => {
    if (!reason.trim()) {
      setError(t('ais.modal.reasonRequired'));
      return;
    }
    setError('');
    setLoading(true);
    try {
      await onApply(author, reason);
      onHide();
    } catch (e: any) {
      setError(e.message || 'Error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog
      visible={visible}
      onHide={onHide}
      header={
        <div className="flex align-items-center gap-2">
          <i className="pi pi-shield text-cyan-400 text-xl" />
          <span className="font-bold text-lg font-orbitron">
            {t('ais.modal.title')}
          </span>
          <Tag value={t('ais.modal.traceabilityActive')} severity="warning" />
        </div>
      }
      style={{ width: '820px' }}
      className="p-fluid noc-dialog"
      modal
    >
      <div className="p-2">
        <p className="text-sm text-gray-300 mb-3">
          {t('ais.modal.desc')}
        </p>

        <div className="grid mb-3">
          <div className="col-6">
            <label className="text-xs font-bold text-gray-400 block mb-1">
              {t('ais.modal.currentState')}
            </label>
            <pre className="diff-view diff-before">{defaultBefore}</pre>
          </div>
          <div className="col-6">
            <label className="text-xs font-bold text-cyan-400 block mb-1">
              {t('ais.modal.proposedState')}
            </label>
            <pre className="diff-view diff-after">{defaultAfter}</pre>
          </div>
        </div>

        <div className="field mb-3">
          <label className="font-bold text-sm text-gray-300">
            {t('ais.modal.operatorField')} *
          </label>
          <InputText
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            placeholder={t('ais.modal.operatorPlaceholder')}
            className="p-inputtext-sm"
          />
        </div>

        <div className="field mb-3">
          <label className="font-bold text-sm text-gray-300">
            {t('ais.modal.reasonField')} *
          </label>
          <InputTextarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            placeholder={t('ais.modal.reasonPlaceholder')}
            className="p-inputtext-sm"
          />
        </div>

        {error && <div className="p-message p-message-error mb-3">{error}</div>}

        <div className="flex justify-content-end gap-2 mt-4">
          <Button label={t('common.cancel')} icon="pi pi-times" text onClick={onHide} disabled={loading} />
          <Button
            label={loading ? t('ais.modal.applying') : t('ais.modal.confirmButton')}
            icon="pi pi-check"
            severity="success"
            onClick={handleConfirm}
            loading={loading}
          />
        </div>
      </div>
    </Dialog>
  );
};
