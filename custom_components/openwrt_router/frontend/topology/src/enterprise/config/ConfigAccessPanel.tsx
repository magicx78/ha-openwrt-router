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

/** Rights as a list; "n weitere Zeilen" only as a count. */
function RightsList({ title, rights, empty }: { title: string; rights: readonly string[]; empty: string }) {
  return (
    <>
      <div className="cfg-subtitle">{title}</div>
      {rights.length > 0
        ? <ul className="cfg-list">{rights.map(x => <li key={x} className="diag-mono">{x}</li>)}</ul>
        : <div className="cfg-hint">{empty}</div>}
    </>
  );
}

/** A command template as plain, selectable text (never run from here). */
function CommandText({ title, text }: { title: string; text: string }) {
  return (
    <>
      <div className="cfg-subtitle">{title}</div>
      <pre className="cfg-code diag-mono"><code>{text}</code></pre>
    </>
  );
}

/** R18's fixed core texts: what is written, the risk and the way back. */
function AclOfferDetails({ offer }: { offer: AclOffer }) {
  return (
    <div className="cfg-offer">
      <div className="cfg-subtitle">Was auf den Router geschrieben wird</div>
      <div className="diag-kv"><span>Zieldatei <span className="diag-mono">{offer.targetFile ?? '–'}</span></span></div>
      <RightsList title="Hinzugefügte Rechte" rights={offer.rightsAdded} empty="keine" />
      <RightsList title="Entfernte Rechte" rights={offer.rightsRemoved} empty="keine" />
      {offer.rightsUnlisted > 0 && (
        <div className="cfg-hint">{offer.rightsUnlisted} weitere Zeilen (nicht einzeln aufgeführt).</div>
      )}
      {offer.riskText && (
        <Notice tone="error"><strong>Risiko:</strong> <span lang="en">{offer.riskText}</span></Notice>
      )}
      {offer.rollbackText && (
        <>
          <div className="cfg-subtitle">Rückweg</div>
          <p className="cfg-hint" lang="en">{offer.rollbackText}</p>
        </>
      )}
      {offer.rollbackTemplate && <CommandText title="Befehl mit gesicherter Vorgängerdatei" text={offer.rollbackTemplate} />}
      {offer.rollbackTemplateNoPrevious && <CommandText title="Befehl ohne Vorgängerdatei" text={offer.rollbackTemplateNoPrevious} />}
      <div className="cfg-hint">Die Befehle sind nur zum Kopieren gedacht; das Panel führt sie nicht aus.</div>
    </div>
  );
}

type Step = 'idle' | 'requesting' | 'requested' | 'approving' | 'approved' | 'executing' | 'done' | 'failed';

/** Request → tick → approve → execute, for acl_deploy and ssh_pin_*. */
function ApprovalAction({ api, startLabel, confirmText, executeLabel, start, resume, readOnly, offerRequired, onDone }: {
  api: ConfigApi;
  startLabel: string;
  confirmText: string;
  executeLabel: string;
  start: () => Promise<{ approval: Approval; offer?: AclOffer }>;
  resume?: Approval | null;
  readOnly: boolean;
  /** ACL deploy: approve / execute only with a complete offer shown above. */
  offerRequired?: boolean;
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
  const offerComplete = offer?.complete === true;
  const allowed = ack && !expired && !readOnly && (!offerRequired || offerComplete);
  // R15 without acknowledge_plaintext: that field belongs to export approvals only.
  const approve = () => approval && allowed && guard('approving', async () => {
    const a = await api.approve(approval.approvalId);
    setApproval(a);
    setStep(a.status === 'approved' ? 'approved' : 'requested');
  });
  const execute = () => approval && allowed && approval.status === 'approved' && guard('executing', async () => {
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
      {offer && <AclOfferDetails offer={offer} />}
      {offerRequired && !offerComplete && (
        <Notice tone="warn">
          Die Antwort des Servers enthält nicht alle Angaben zum ACL-Angebot (Zieldatei, Rechte, Risiko, Rückweg).
          Die Freigabe ist deshalb gesperrt. Bitte die Integration aktualisieren und das Angebot neu anfordern.
        </Notice>
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
          <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={!allowed}
            onClick={() => void approve()}>
            Freigeben
          </button>
        )}
        {step === 'approved' && (
          <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={!allowed}
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

export function ConfigAccessPanel({ api, detail, approvals, readOnly, enabled, onChanged }: {
  api: ConfigApi;
  detail: RouterDetail;
  approvals: readonly Approval[];
  readOnly: boolean;
  /** Backup function switched on; the ACL deploy is offered only then. */
  enabled: boolean;
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

      {enabled && detail.acl && detail.acl.offerable.length > 0 && (
        <div className="cfg-stack">
          <div className="cfg-subtitle">rpcd-ACL</div>
          <div className="cfg-hint">
            Für das Backup fehlen dem Router Leserechte (Stufe <span className="diag-mono">{detail.acl.offerable.join(', ')}</span>
            {detail.acl.deployedVersion !== null && <>; verteilt ist Version {detail.acl.deployedVersion}</>}).
            Das Angebot zeigt die Änderung; nach der Freigabe schreibt Home Assistant die ACL auf den Router und startet rpcd einmal neu.
          </div>
          <ApprovalAction api={api} readOnly={readOnly} offerRequired onDone={onChanged}
            startLabel="ACL-Angebot anfordern" executeLabel="ACL auf den Router schreiben"
            confirmText="Ich habe Zieldatei, Rechte, Risiko und Rückweg gelesen und verstanden. Die ACL wird auf den Router geschrieben und rpcd startet einmal neu."
            start={async () => api.aclOffer(detail.routerId)} />
        </div>
      )}
    </div>
  );
}
