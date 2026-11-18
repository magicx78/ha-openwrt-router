/**
 * ConfigAccessPanel — what the router lets the backup module do:
 * capabilities (config.*), the SSH host key pin (confirm / forget, R19) and
 * the ACL offer for the tier `config_backup_read` (R18). Each of these runs
 * request → explicit tick → approve (R15) → execute (R20); nothing starts
 * without an admin's clicks.
 */

import React, { useState } from 'react';
import type { AclOffer, Approval, ConfigApi, RouterDetail } from './configTypes';
import {
  APPROVAL_STATUS_LABEL,
  CAP_LABEL,
  CAP_REASON_TEXT,
  SSH_PIN_LABEL,
  formatTime,
  isExpired,
  label,
} from './configLogic.ts';
import { Badge, ErrorBox, Notice, Spinner } from './configUi';

type Step = 'idle' | 'requesting' | 'requested' | 'approving' | 'approved' | 'executing' | 'done' | 'failed';

/** Request → tick → approve → execute, for acl_deploy and ssh_pin_*. */
function ApprovalAction({ api, startLabel, confirmText, executeLabel, start, resume, readOnly, onDone }: {
  api: ConfigApi;
  startLabel: string;
  confirmText: string;
  executeLabel: string;
  start: () => Promise<{ approval: Approval; offer?: AclOffer }>;
  resume?: Approval | null;
  readOnly: boolean;
  onDone: () => void;
}) {
  const initial: Step = resume ? (resume.status === 'approved' ? 'approved' : 'requested') : 'idle';
  const [step, setStep] = useState<Step>(initial);
  const [approval, setApproval] = useState<Approval | null>(resume ?? null);
  const [offer, setOffer] = useState<AclOffer | null>(null);
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const expired = isExpired(approval, Date.now());

  const guard = async (busy: Step, fn: () => Promise<void>) => {
    setStep(busy);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e);
      setStep('failed');
    }
  };

  const request = () => guard('requesting', async () => {
    const r = await start();
    setApproval(r.approval);
    setOffer(r.offer ?? null);
    setAck(false);
    setStep('requested');
  });
  const approve = () => approval && ack && guard('approving', async () => {
    const a = await api.approve(approval.approvalId);
    setApproval(a);
    setStep(a.status === 'approved' ? 'approved' : 'requested');
  });
  const execute = () => approval && ack && approval.status === 'approved' && guard('executing', async () => {
    await api.execute(approval.approvalId);
    setStep('done');
    onDone();
  });
  const reject = () => approval && guard('idle', async () => {
    await api.reject(approval.approvalId);
    setApproval(null);
    setStep('idle');
  });

  if (step === 'idle' || step === 'failed') {
    return (
      <div className="cfg-stack">
        <ErrorBox error={error} />
        <div className="diag-actions">
          <button type="button" className="diag-btn cfg-btn" disabled={readOnly} onClick={() => void request()}>{startLabel}</button>
        </div>
      </div>
    );
  }
  if (step === 'requesting' || step === 'approving' || step === 'executing') {
    return <Spinner text={step === 'executing' ? 'Wird ausgeführt …' : 'Bitte warten …'} />;
  }
  if (step === 'done') return <Notice tone="ok">Erledigt.</Notice>;

  return (
    <div className="cfg-stack">
      {offer && (
        <div className="cfg-offer">
          {offer.added.length > 0 && (
            <><div className="cfg-subtitle">Neue Rechte</div>
              <ul className="cfg-list">{offer.added.map(x => <li key={x} className="diag-mono">{x}</li>)}</ul></>
          )}
          {offer.removed.length > 0 && (
            <><div className="cfg-subtitle">Entfallende Rechte</div>
              <ul className="cfg-list">{offer.removed.map(x => <li key={x} className="diag-mono">{x}</li>)}</ul></>
          )}
          {offer.risks.length > 0 && (
            <><div className="cfg-subtitle">Risiken</div>
              <ul className="cfg-list cfg-list--warn">{offer.risks.map(x => <li key={x}>{x}</li>)}</ul></>
          )}
        </div>
      )}
      {approval && (
        <div className="diag-kv">
          <span>{label(APPROVAL_STATUS_LABEL, approval.status)}</span>
          <span className={expired ? 'cfg-text-critical' : ''}>{expired ? 'abgelaufen' : `gültig bis ${formatTime(approval.expiresAt)}`}</span>
        </div>
      )}
      <label className="diag-check cfg-confirm">
        <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />
        {confirmText}
      </label>
      <div className="diag-actions">
        {step === 'requested' && (
          <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={!ack || expired || readOnly}
            onClick={() => void approve()}>
            Freigeben
          </button>
        )}
        {step === 'approved' && (
          <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={!ack || expired || readOnly}
            onClick={() => void execute()}>
            {executeLabel}
          </button>
        )}
        <button type="button" className="diag-btn cfg-btn" onClick={() => void reject()}>Verwerfen</button>
        {expired && <button type="button" className="diag-btn cfg-btn" onClick={() => void request()}>Neu beantragen</button>}
      </div>
    </div>
  );
}

export function ConfigAccessPanel({ api, detail, approvals, readOnly, onChanged }: {
  api: ConfigApi;
  detail: RouterDetail;
  approvals: readonly Approval[];
  readOnly: boolean;
  onChanged: () => void;
}) {
  const pin = detail.sshPin;
  const pending = (action: string) =>
    approvals.find(a => a.action === action && (a.status === 'pending' || a.status === 'approved')) ?? null;
  const caps = Object.entries(detail.capabilities).filter(([name]) => name.startsWith('config.'));

  return (
    <div className="cfg-stack">
      {caps.length > 0 && (
        <ul className="cfg-caps">
          {caps.map(([name, c]) => (
            <li key={name} className={`cfg-caps__item cfg-caps__item--${c.state}`}>
              <span className="cfg-caps__name">{label(CAP_LABEL, name)}</span>
              <Badge tone={c.state === 'available' ? 'ok' : c.state === 'unavailable' ? 'critical' : 'muted'}>
                {c.state === 'available' ? 'verfügbar' : c.state === 'unavailable' ? 'nicht verfügbar' : 'unbekannt'}
              </Badge>
              {c.reason && c.reason !== 'ok' && <span className="diag-table__meta">{label(CAP_REASON_TEXT, c.reason)}</span>}
              {c.missing.length > 0 && <span className="diag-table__meta diag-mono">fehlt: {c.missing.join(', ')}</span>}
            </li>
          ))}
        </ul>
      )}

      {pin && (
        <div className="cfg-stack">
          <div className="cfg-subtitle">SSH-Host-Key</div>
          {pin.state === 'mismatch' && (
            <Notice tone="error">
              <strong>Der Host-Key des Routers weicht vom gespeicherten ab.</strong> SSH-Zugriffe werden abgelehnt. Nur wenn der
              Router neu installiert wurde, den gespeicherten Key vergessen und den neuen prüfen; sonst kann ein fremdes Gerät
              antworten.
            </Notice>
          )}
          <div className="diag-kv">
            <span>Zustand <Badge tone={pin.state === 'mismatch' ? 'critical' : pin.state === 'pending' ? 'warn' : 'muted'}>
              {label(SSH_PIN_LABEL, pin.state)}</Badge></span>
          </div>
          {pin.fingerprint && <div className="cfg-fingerprint diag-mono">{pin.fingerprint}</div>}
          {pin.state === 'pending' && (
            <ApprovalAction api={api} readOnly={readOnly} resume={pending('ssh_pin_confirm')} onDone={onChanged}
              startLabel="Host-Key bestätigen …" executeLabel="Host-Key übernehmen"
              confirmText="Ich habe den Fingerprint mit dem Router verglichen (z. B. an der Konsole) und er stimmt überein."
              start={async () => ({ approval: await api.sshPin(detail.routerId, 'confirm') })} />
          )}
          {(pin.state === 'mismatch' || pin.state === 'confirmed' || pin.state === 'pinned') && (
            <ApprovalAction api={api} readOnly={readOnly} resume={pending('ssh_pin_reset')} onDone={onChanged}
              startLabel="Gespeicherten Key vergessen …" executeLabel="Key vergessen"
              confirmText="Der Router wurde neu installiert. Beim nächsten Kontakt muss der neue Key wieder bestätigt werden."
              start={async () => ({ approval: await api.sshPin(detail.routerId, 'reset') })} />
          )}
        </div>
      )}

      {detail.acl && detail.acl.offerable.length > 0 && (
        <div className="cfg-stack">
          <div className="cfg-subtitle">rpcd-ACL</div>
          <div className="cfg-hint">
            Für das Backup fehlen dem Router Leserechte (Stufe <span className="diag-mono">{detail.acl.offerable.join(', ')}</span>
            {detail.acl.deployedVersion !== null && <>; verteilt ist Version {detail.acl.deployedVersion}</>}).
            Das Angebot zeigt die Änderung; nach der Freigabe schreibt Home Assistant die ACL auf den Router und startet rpcd einmal neu.
          </div>
          <ApprovalAction api={api} readOnly={readOnly} resume={pending('acl_deploy')} onDone={onChanged}
            startLabel="ACL-Angebot anfordern" executeLabel="ACL auf den Router schreiben"
            confirmText="Ich habe neue Rechte und Risiken geprüft. Die ACL wird auf den Router geschrieben und rpcd startet einmal neu."
            start={async () => api.aclOffer(detail.routerId)} />
        </div>
      )}
    </div>
  );
}
