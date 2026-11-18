/**
 * ConfigApprovalDialog — export of a stored version in explicit steps
 * (plan 7.6): request (R13) → tick "contains all secrets in plain text" →
 * approve (R15) → download (R17). The state machine lives in configLogic
 * (exportReduce); without the tick neither approve nor download is possible.
 * The expiry time of the approval is shown; an expired one is requested anew.
 */

import React, { useEffect, useReducer, useRef } from 'react';
import type { Approval, ConfigApi, ExportArtifact, Version } from './configTypes';
import {
  APPROVAL_STATUS_LABEL,
  REASON_LABEL,
  canApprove,
  canDownload,
  exportInit,
  exportReduce,
  formatRelative,
  formatTime,
  isExpired,
  label,
  shortHash,
} from './configLogic.ts';
import { ErrorBox, Notice, Spinner, useClock } from './configUi';

const ARTIFACT_LABEL: Record<ExportArtifact, string> = {
  archive: 'Vollarchiv (sysupgrade-Format, .tar.gz)',
  uci: 'UCI-Snapshot (JSON)',
  inventory: 'Bestandsaufnahme (JSON, Pakete und Hardware)',
};

export const PLAINTEXT_WARNING =
  'Das Archiv enthält alle Passwörter und Schlüssel des Routers im Klartext – unter anderem /etc/shadow '
  + '(Passwort-Hashes), SSH-Host-Keys, WLAN-, VPN- und TLS-Schlüssel. Die Datei sicher aufbewahren und nicht weitergeben.';

export function ConfigExportFlow({ api, version, resume, readOnly, onFinished }: {
  api: ConfigApi;
  version: Version;
  resume?: Approval | null;
  readOnly?: boolean;
  onFinished?: () => void;
}) {
  const [state, dispatch] = useReducer(exportReduce, undefined, () =>
    resume ? exportReduce(exportInit(), { type: 'resume', approval: resume }) : exportInit());
  const kinds = version.artifacts.map(a => a.kind).filter((k): k is ExportArtifact => k in ARTIFACT_LABEL);
  const [artifact, setArtifact] = React.useState<ExportArtifact>(kinds.includes('archive') ? 'archive' : kinds[0] ?? 'uci');
  const now = useClock(15_000);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  const run = async <T,>(fn: () => Promise<T>, done: (v: T) => void) => {
    try {
      const v = await fn();
      if (alive.current) done(v);
    } catch (error) {
      if (alive.current) dispatch({ type: 'failed', error });
    }
  };

  const request = () => {
    dispatch({ type: 'request' });
    void run(() => api.requestExport(version.backupId, artifact), approval => dispatch({ type: 'requested', approval }));
  };
  const approve = () => {
    if (!state.approval || !canApprove(state, Date.now())) return;
    const id = state.approval.approvalId;
    dispatch({ type: 'approve' });
    void run(() => api.approve(id), approval => dispatch({ type: 'approved', approval }));
  };
  const download = () => {
    if (!state.approval || !canDownload(state, Date.now())) return;
    const id = state.approval.approvalId;
    dispatch({ type: 'download' });
    void run(() => api.download(id), r => { dispatch({ type: 'downloaded', filename: r.filename }); onFinished?.(); });
  };
  const reject = () => {
    if (!state.approval) return;
    const id = state.approval.approvalId;
    void run(() => api.reject(id), () => dispatch({ type: 'reset' }));
  };

  const a = state.approval;
  const expired = isExpired(a, now);

  return (
    <div className="cfg-stack">
      <div className="diag-kv">
        <span>Version <b>{formatTime(version.createdAt)}</b></span>
        <span>{label(REASON_LABEL, version.reason)}</span>
        <span className="diag-mono">{shortHash(version.sha256)}</span>
      </div>
      <Notice tone="error"><strong>Achtung: Klartext.</strong> {PLAINTEXT_WARNING}</Notice>

      {(state.step === 'idle' || (state.step === 'failed' && state.renew)) && (
        <>
          {kinds.length > 1 && (
            <fieldset className="diag-fieldset">
              <legend>Inhalt</legend>
              {kinds.map(k => (
                <label key={k} className="diag-check cfg-radio">
                  <input type="radio" name="cfg-artifact" checked={artifact === k} onChange={() => setArtifact(k)} />
                  {ARTIFACT_LABEL[k]}
                </label>
              ))}
            </fieldset>
          )}
          <div className="cfg-steps-note">Schritt 1 von 3: Export beantragen. Danach folgen Bestätigung und Download.</div>
          <div className="diag-actions">
            <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={readOnly} onClick={request}>
              {state.renew ? 'Neu beantragen' : 'Export beantragen'}
            </button>
          </div>
        </>
      )}

      {state.step === 'requesting' && <Spinner text="Antrag wird angelegt …" />}
      {state.step === 'approving' && <Spinner text="Wird freigegeben …" />}
      {state.step === 'downloading' && <Spinner text="Datei wird geladen …" />}

      {a && (state.step === 'requested' || state.step === 'approved') && (
        <>
          <div className="diag-kv">
            <span>Antrag <span className="diag-mono">{shortHash(a.approvalId)}</span></span>
            <span>{label(APPROVAL_STATUS_LABEL, a.status)}</span>
            <span className={expired ? 'cfg-text-critical' : ''}>
              {expired ? 'abgelaufen' : `gültig bis ${formatTime(a.expiresAt)} (${formatRelative(a.expiresAt, now)})`}
            </span>
          </div>
          <div className="cfg-steps-note">
            {state.step === 'requested' ? 'Schritt 2 von 3: bestätigen und freigeben.' : 'Schritt 3 von 3: herunterladen.'}
          </div>
          <label className="diag-check cfg-confirm">
            <input type="checkbox" checked={state.acknowledged}
              onChange={e => dispatch({ type: 'acknowledge', value: e.target.checked })} />
            Ich habe verstanden, dass die Datei alle Passwörter und Schlüssel im Klartext enthält, und bewahre sie sicher auf.
          </label>
          <div className="diag-actions">
            {state.step === 'requested' && (
              <button type="button" className="diag-btn diag-btn--primary cfg-btn"
                disabled={readOnly || !canApprove(state, now)} onClick={approve}>
                Freigeben
              </button>
            )}
            {state.step === 'approved' && (
              <button type="button" className="diag-btn diag-btn--primary cfg-btn"
                disabled={!canDownload(state, now)} onClick={download}>
                Herunterladen
              </button>
            )}
            <button type="button" className="diag-btn cfg-btn" onClick={reject}>Antrag verwerfen</button>
            {expired && (
              <button type="button" className="diag-btn cfg-btn" onClick={() => { dispatch({ type: 'reset' }); }}>
                Neu beantragen
              </button>
            )}
          </div>
        </>
      )}

      {state.step === 'done' && (
        <Notice tone="ok">
          Download gestartet: <span className="diag-mono">{state.filename}</span>. Die Freigabe ist damit eingelöst.
        </Notice>
      )}

      {state.step === 'failed' && (
        <>
          <ErrorBox error={state.error} />
          {!state.renew && (
            <div className="diag-actions">
              <button type="button" className="diag-btn cfg-btn" onClick={() => dispatch({ type: 'reset' })}>Von vorn</button>
            </div>
          )}
        </>
      )}
      {state.step === 'approved' && state.error !== null && <ErrorBox error={state.error} />}
    </div>
  );
}

/** Modal wrapper around ConfigExportFlow. */
export function ConfigApprovalDialog(props: {
  api: ConfigApi;
  version: Version;
  resume?: Approval | null;
  readOnly?: boolean;
  onClose: () => void;
}) {
  return (
    <ConfigModal title="Version exportieren" onClose={props.onClose}>
      <ConfigExportFlow api={props.api} version={props.version} resume={props.resume} readOnly={props.readOnly} />
    </ConfigModal>
  );
}

export function ConfigModal({ title, onClose, children }: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <div className="cfg-modal" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="cfg-modal__box" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}
        onKeyDown={e => { if (e.key === 'Escape') onClose(); }}>
        <div className="cfg-modal__head">
          <span className="view-title">{title}</span>
          <button type="button" className="diag-btn cfg-btn" onClick={onClose} aria-label="Schließen">Schließen</button>
        </div>
        <div className="cfg-modal__body">{children}</div>
      </div>
    </div>
  );
}
