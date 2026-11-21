/**
 * ConfigRestoreCheck — restore assistant (plan 7.7). Version → compatibility
 * (R12) → preview → explicit confirmation → export + manual instructions +
 * checklist. It never executes anything on a router: there is no restore
 * route, and this view has no button that would call one.
 */

import React, { useEffect, useReducer, useState } from 'react';
import type { ConfigApi, Version } from './configTypes';
import {
  FINDING_TEXT,
  REASON_LABEL,
  VERIFY_CHECKLIST,
  WARNING_TEXT,
  formatTime,
  label,
  restoreCanProceed,
  restoreImpact,
  restoreInit,
  restoreKeyText,
  restoreReduce,
  restorableVersions,
  stepText,
  type RestoreWizardStep,
} from './configLogic.ts';
import { ConfigDiffList } from './ConfigDiffView';
import { ConfigExportFlow, ConfigModal } from './ConfigApprovalDialog';
import { Badge, ErrorBox, Notice, RiskBadge, Skeleton } from './configUi';

const STEPS: Array<{ id: RestoreWizardStep | 'select'; title: string }> = [
  { id: 'select', title: 'Version' },
  { id: 'compat', title: 'Kompatibilität' },
  { id: 'preview', title: 'Vorschau' },
  { id: 'confirm', title: 'Bestätigung' },
  { id: 'guide', title: 'Export & Anleitung' },
];

export function ConfigRestoreCheck({ api, versions, initialBackupId, routerName, readOnly, onClose }: {
  api: ConfigApi;
  versions: readonly Version[];
  initialBackupId: string;
  routerName: string;
  readOnly?: boolean;
  onClose: () => void;
}) {
  const candidates = restorableVersions(versions);
  const [s, dispatch] = useReducer(restoreReduce, initialBackupId, restoreInit);
  const [checked, setChecked] = useState<Record<number, boolean>>({});
  const [attempt, setAttempt] = useState(0);
  const version = versions.find(v => v.backupId === s.backupId) ?? null;

  useEffect(() => {
    let alive = true;
    api.restoreCheck(s.backupId).then(
      plan => { if (alive) dispatch({ type: 'checked', plan }); },
      error => { if (alive) dispatch({ type: 'failed', error }); },
    );
    return () => { alive = false; };
  }, [api, s.backupId, attempt]);

  const current = STEPS.findIndex(x => x.id === s.step);
  const impact = s.plan ? restoreImpact(s.plan) : null;

  return (
    <ConfigModal title={`Wiederherstellung vorbereiten – ${routerName}`} onClose={onClose}>
      <div className="cfg-stack">
        <Notice tone="error">
          <strong>Nicht automatisch reversibel.</strong> Diese Ansicht führt nichts auf dem Router aus. Sie prüft die
          Version, zeigt die Folgen und liefert das Archiv mit einer Anleitung; einspielen musst du es selbst.
        </Notice>
        <ol className="cfg-stepper" aria-label="Schritte">
          {STEPS.map((x, i) => (
            <li key={x.id} className={`cfg-stepper__item${i === current ? ' active' : ''}${i < current ? ' done' : ''}`}
              aria-current={i === current ? 'step' : undefined}>
              <span className="cfg-stepper__num">{i + 1}</span>
              <span className="cfg-stepper__label">{x.title}</span>
            </li>
          ))}
        </ol>

        {s.step === 'compat' && (
          <>
            <label className="diag-field diag-field--block">
              <span className="diag-field__label">Version</span>
              <select value={s.backupId} onChange={e => dispatch({ type: 'select', backupId: e.target.value })}>
                {candidates.map(v => (
                  <option key={v.backupId} value={v.backupId}>
                    {formatTime(v.createdAt)} · {label(REASON_LABEL, v.reason)}{v.openwrtVersion ? ` · OpenWrt ${v.openwrtVersion}` : ''}
                  </option>
                ))}
                {!candidates.some(v => v.backupId === s.backupId) && <option value={s.backupId}>{formatTime(version?.createdAt ?? null)}</option>}
              </select>
            </label>
            {s.loading && <Skeleton rows={3} />}
            <ErrorBox error={s.error} onRetry={() => { dispatch({ type: 'select', backupId: s.backupId }); setAttempt(n => n + 1); }} />
            {s.plan && impact && (
              <>
                {s.plan.compatible
                  ? <Notice tone="ok">Die Version passt grundsätzlich zu diesem Router.</Notice>
                  : <Notice tone="error"><strong>Nicht kompatibel.</strong> Die Wiederherstellung ist blockiert; bitte abbrechen.</Notice>}
                <FindingList title="Blockierend" tone="critical" codes={impact.blocking.map(f => f.code)} />
                <FindingList title="Hinweise" tone="warn" codes={impact.warnings.map(f => f.code)} />
              </>
            )}
          </>
        )}

        {s.step === 'preview' && s.plan && impact && (
          <>
            <div className="diag-facts">
              <Fact label="Neustart nötig" value={impact.reboot ? 'Ja' : 'Nein'} tone={impact.reboot ? 'warn' : undefined} />
              <Fact label="Verbindungsabbruch möglich" value={impact.connectionRisk ? 'Ja' : 'Unwahrscheinlich'}
                tone={impact.connectionRisk ? 'critical' : undefined} />
              <Fact label="Betroffene Bereiche" value={String(impact.areas.length)} />
              <Fact label="Kritische Änderungen" value={String(impact.critical.length)}
                tone={impact.critical.length ? 'critical' : undefined} />
            </div>
            {impact.areas.length > 0 && (
              <ul className="cfg-areas">
                {impact.areas.map(a => (
                  <li key={a.area} className={a.critical ? 'cfg-areas__item--critical' : ''}>
                    <span>{a.label}</span>
                    <span className="diag-muted">{a.count}</span>
                    <RiskBadge risk={a.maxRisk} />
                    {a.critical && <Badge tone="critical">kritisch</Badge>}
                  </li>
                ))}
              </ul>
            )}
            {s.plan.warnings.length > 0 && (
              <ul className="cfg-list cfg-list--warn">
                {s.plan.warnings.map(w => <li key={w}>{WARNING_TEXT[w] ?? restoreKeyText(w)}</li>)}
              </ul>
            )}
            <div className="cfg-subtitle">Geplante Schritte</div>
            <ol className="cfg-list">
              {s.plan.steps.map(st => <li key={`${st.order}-${st.action}`}>{stepText(st)}</li>)}
            </ol>
            <div className="cfg-subtitle">Geplante Änderungen gegenüber dem aktuellen Stand</div>
            <ConfigDiffList changes={s.plan.changes} />
          </>
        )}

        {s.step === 'confirm' && impact && (
          <>
            <ul className="cfg-list cfg-list--warn">
              <li>Die Wiederherstellung ist <strong>nicht automatisch reversibel</strong>.</li>
              {impact.reboot && <li>Der Router startet neu; WLAN und Netzwerk fallen kurz aus.</li>}
              {impact.connectionRisk && (
                <li>Die Verbindung zu Home Assistant kann abbrechen. Konsole oder Failsafe-Modus bereithalten.</li>
              )}
              <li>Passwörter, SSH-Schlüssel und Zertifikate werden auf den Stand der Version zurückgesetzt.</li>
            </ul>
            <label className="diag-check cfg-confirm">
              <input type="checkbox" checked={s.understood}
                onChange={e => dispatch({ type: 'understood', value: e.target.checked })} />
              Ich habe verstanden: Die Wiederherstellung ist nicht automatisch reversibel, kann die Verbindung
              unterbrechen und wird von mir selbst von Hand ausgeführt.
            </label>
          </>
        )}

        {s.step === 'guide' && s.plan && version && (
          <>
            <div className="cfg-subtitle">1. Archiv exportieren</div>
            <ConfigExportFlow api={api} version={version} readOnly={readOnly} />
            <div className="cfg-subtitle">2. Von Hand wiederherstellen</div>
            <ol className="cfg-list">
              {s.plan.steps.map(st => <li key={`${st.order}-${st.action}`}>{stepText(st)}</li>)}
              {s.plan.instructions.map(k => <li key={k}>{restoreKeyText(k)}</li>)}
            </ol>
            <div className="cfg-subtitle">3. Danach prüfen</div>
            <ul className="cfg-checklist">
              {VERIFY_CHECKLIST.map((item, i) => (
                <li key={item}>
                  <label className="diag-check">
                    <input type="checkbox" checked={checked[i] === true}
                      onChange={e => setChecked(prev => ({ ...prev, [i]: e.target.checked }))} />
                    {item}
                  </label>
                </li>
              ))}
            </ul>
          </>
        )}

        <div className="diag-actions cfg-wizard__nav">
          {current > 1 && (
            <button type="button" className="diag-btn cfg-btn" onClick={() => dispatch({ type: 'back' })}>Zurück</button>
          )}
          {s.step !== 'guide' && (
            <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={!restoreCanProceed(s)}
              onClick={() => dispatch({ type: 'next' })}>
              Weiter
            </button>
          )}
          <button type="button" className="diag-btn cfg-btn" onClick={onClose}>
            {s.step === 'guide' ? 'Fertig' : 'Abbrechen'}
          </button>
        </div>
      </div>
    </ConfigModal>
  );
}

function FindingList({ title, tone, codes }: { title: string; tone: 'critical' | 'warn'; codes: string[] }) {
  if (codes.length === 0) return null;
  return (
    <div>
      <div className="cfg-subtitle">{title}</div>
      <ul className={`cfg-list cfg-list--${tone}`}>
        {codes.map(c => <li key={c}>{FINDING_TEXT[c] ?? `Befund ${c}`}</li>)}
      </ul>
    </div>
  );
}

function Fact({ label: name, value, tone }: { label: string; value: string; tone?: 'warn' | 'critical' }) {
  return (
    <div className="diag-fact">
      <span className="diag-fact__label">{name}</span>
      <span className={`diag-fact__value${tone ? ` cfg-text-${tone}` : ''}`}>{value}</span>
    </div>
  );
}
