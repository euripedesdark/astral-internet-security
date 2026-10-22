import React, { useState } from 'react';
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
      setError('O motivo da alteração é obrigatório conforme Controle ISO/IEC 27001 A.8.32');
      return;
    }
    setError('');
    setLoading(true);
    try {
      await onApply(author, reason);
      onHide();
    } catch (e: any) {
      setError(e.message || 'Falha ao aplicar alterações');
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
            Gestão de Mudanças ISO 27001 (A.8.32) - Aplicar Alterações
          </span>
          <Tag value="Rastreabilidade Ativa" severity="warning" />
        </div>
      }
      style={{ width: '820px' }}
      className="p-fluid noc-dialog"
      modal
    >
      <div className="p-2">
        <p className="text-sm text-gray-300 mb-3">
          Nenhuma alteração de segurança é publicada em produção sem registro auditável. Revise as diferenças (Diff) antes de efetivar e informe a justificativa técnica.
        </p>

        <div className="grid mb-3">
          <div className="col-6">
            <label className="text-xs font-bold text-gray-400 block mb-1">
              ESTADO ATUAL (EM EXECUÇÃO)
            </label>
            <pre className="diff-view diff-before">{defaultBefore}</pre>
          </div>
          <div className="col-6">
            <label className="text-xs font-bold text-cyan-400 block mb-1">
              NOVO ESTADO PROPOSTO (DIFF APÓS APLICAÇÃO)
            </label>
            <pre className="diff-view diff-after">{defaultAfter}</pre>
          </div>
        </div>

        <div className="field mb-3">
          <label className="font-bold text-sm text-gray-300">
            Operador / Autor da Mudança (Controle A.8.2) *
          </label>
          <InputText
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            placeholder="Nome ou e-mail corporativo do administrador"
            className="p-inputtext-sm"
          />
        </div>

        <div className="field mb-3">
          <label className="font-bold text-sm text-gray-300">
            Motivo / Justificativa Técnica da Mudança (Controle A.8.32) *
          </label>
          <InputTextarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            placeholder="Ex: Liberação de tráfego HTTPS seguro para novo servidor ERP da DMZ conforme chamado TIK-8492"
            className="p-inputtext-sm"
          />
        </div>

        {error && <div className="p-message p-message-error mb-3">{error}</div>}

        <div className="flex justify-content-end gap-2 mt-4">
          <Button label="Cancelar" icon="pi pi-times" text onClick={onHide} disabled={loading} />
          <Button
            label={loading ? 'Aplicando e Gravando Trilha...' : 'Confirmar e Publicar Regras'}
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
