/**
 * ConfigDriftPanel — drift report of one router (R9): counts, comparison,
 * baseline; "Drift jetzt prüfen" (R10), "Bestätigen" / "Als bekannt
 * markieren" (R11) and "Unterschiede ansehen" (opens the diff baseline →
 * live). Loaded with the detail; no background polling.
 */

import React, { useState } from 'react';
import type { ConfigApi, DriftAckChoice, DriftState } from './configTypes';
import {
  COMPARISON_LABEL,
  DRIFT_STATE_LABEL,
  formatTime,
  isDriftOpen,
  label,
  sanitizeNote,
} from './configLogic.ts';
import { Badge, ErrorBox, Spinner } from './configUi';

export function ConfigDriftPanel({ api, routerId, drift, enabled, readOnly, onChanged, onShowDiff }: {
  api: ConfigApi;
  routerId: string;
  drift: DriftState | null;
  enabled: boolean;
  readOnly: boolean;
  onChanged: (d: DriftState) => void;
  onShowDiff: (baselineBackupId: string) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState('');
  const report = drift?.report ?? null;
  const open = isDriftOpen(drift);

  const run = async (what: string, fn: () => Promise<DriftState>) => {
    setBusy(what);
    setError(null);
    try {
      onChanged(await fn());
      setNote('');
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  const ack = (state: DriftAckChoice) => {
    if (!report?.driftId) return;
    const id = report.driftId;
    void run(state, () => api.driftAck(routerId, id, state, sanitizeNote(note) || undefined));
  };

  return (
    <div className="cfg-stack">
      <div className="diag-kv">
        <span>Zustand <Badge tone={open ? 'critical' : 'muted'}>{label(DRIFT_STATE_LABEL, drift?.state ?? 'unknown')}</Badge></span>
        {report && (
          <>
            <span className={report.criticalCount ? 'cfg-text-critical' : ''}><b>{report.criticalCount}</b> kritisch</span>
            <span className={report.unknownCount ? 'cfg-text-warn' : ''}><b>{report.unknownCount}</b> nicht einstufbar</span>
            <span>Vergleich {label(COMPARISON_LABEL, report.comparison)}</span>
            <span>geprüft {formatTime(report.checkedAt)}</span>
          </>
        )}
      </div>
      {!report && <div className="cfg-empty">Noch keine Drift-Prüfung für diesen Router.</div>}
      {report && report.comparison !== 'complete' && (
        <div className="cfg-hint">Nicht alle Konfigurationen ließen sich vergleichen; das Ergebnis ist kein vollständiger Befund.</div>
      )}
      {open && (
        <label className="diag-field diag-field--block">
          <span className="diag-field__label">Notiz zur Bestätigung (optional, höchstens 200 Zeichen)</span>
          <input value={note} maxLength={200} onChange={e => setNote(e.target.value)} spellCheck={false} />
        </label>
      )}
      <div className="diag-actions">
        <button type="button" className="diag-btn cfg-btn" disabled={busy !== null || readOnly || !enabled}
          onClick={() => void run('check', () => api.driftCheck(routerId))}>
          Drift jetzt prüfen
        </button>
        {report?.baselineBackupId && (
          <button type="button" className="diag-btn cfg-btn" onClick={() => onShowDiff(report.baselineBackupId as string)}>
            Unterschiede ansehen
          </button>
        )}
        {open && report?.driftId && (
          <>
            <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={busy !== null || readOnly}
              onClick={() => ack('acknowledged')}>
              Bestätigen
            </button>
            <button type="button" className="diag-btn cfg-btn" disabled={busy !== null || readOnly}
              title="Der aktuelle Stand wird zur neuen Bezugsbasis"
              onClick={() => ack('known')}>
              Als bekannt markieren
            </button>
          </>
        )}
      </div>
      {busy === 'check' && <Spinner text="Konfiguration wird vom Router gelesen und verglichen …" />}
      <ErrorBox error={error} />
      {drift && drift.acks.length > 0 && (
        <ul className="cfg-list">
          {drift.acks.map((a, i) => (
            <li key={`${a.driftId}-${i}`}>
              {label(DRIFT_STATE_LABEL, a.state)} {formatTime(a.at)}{a.mine ? ' (von dir)' : ''}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
