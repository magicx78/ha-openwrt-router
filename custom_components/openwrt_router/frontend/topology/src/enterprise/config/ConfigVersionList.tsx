/**
 * ConfigVersionList — backup timeline (last 30 days) and version history:
 * time, type, size, short checksum, reason, validation, note, protection.
 * Per version: validate (R6), protect / unprotect (R7), export, restore
 * check, compare with the live state. Table on wide screens, cards below
 * 600 px (config.css).
 */

import React, { useState } from 'react';
import type { ConfigApi, Version } from './configTypes';
import {
  ACTOR_LABEL,
  REASON_LABEL,
  TYPE_LABEL,
  VALIDATION_LABEL,
  VERSION_STATUS_LABEL,
  VERSION_WARNING_TEXT,
  formatBytes,
  formatTime,
  label,
  shortHash,
  restorableVersions,
  timelinePoints,
} from './configLogic.ts';
import { Badge, ErrorBox } from './configUi';

const VALIDATION_TONE: Record<string, string> = {
  ok: 'ok', valid: 'ok', unverified: 'muted', invalid: 'critical', corrupt: 'critical', missing: 'critical',
};

function Timeline({ versions, now }: { versions: readonly Version[]; now: number }) {
  const points = timelinePoints(versions, now, 30);
  return (
    <div className="cfg-timeline" aria-label="Backups der letzten 30 Tage">
      <div className="cfg-timeline__track">
        {points.map(p => (
          <span key={p.backupId} className={`cfg-timeline__dot cfg-timeline__dot--${p.status}${p.reason === 'manual' ? ' cfg-timeline__dot--manual' : ''}`}
            style={{ left: `${(p.pos * 100).toFixed(2)}%` }}
            title={`${formatTime(p.createdAt)} · ${label(REASON_LABEL, p.reason)} · ${label(VERSION_STATUS_LABEL, p.status)}`} />
        ))}
      </div>
      <div className="stab-axis"><span>vor 30 Tagen</span><span>heute</span></div>
    </div>
  );
}

export function ConfigVersionList({ api, versions, now, readOnly, enabled, onChanged, onExport, onRestore, onCompare }: {
  api: ConfigApi;
  versions: readonly Version[];
  now: number;
  readOnly: boolean;
  enabled: boolean;
  onChanged: (v: Version) => void;
  onExport: (v: Version) => void;
  onRestore: (v: Version) => void;
  onCompare: (from: string, to: string) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ id: string; error: unknown } | null>(null);
  const restorable = new Set(restorableVersions(versions).map(v => v.backupId));

  const act = async (v: Version, fn: () => Promise<Version>) => {
    setBusy(v.backupId);
    setError(null);
    try {
      onChanged(await fn());
    } catch (e) {
      setError({ id: v.backupId, error: e });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="cfg-stack">
      <Timeline versions={versions} now={now} />
      <div className="cfg-versions" role="table" aria-label="Versionen">
        <div className="cfg-vrow cfg-vrow--head" role="row">
          <span role="columnheader">Zeit</span>
          <span role="columnheader">Typ / Grund</span>
          <span role="columnheader">Größe</span>
          <span role="columnheader">Prüfsumme</span>
          <span role="columnheader">Prüfung</span>
          <span role="columnheader">Beschreibung</span>
          <span role="columnheader">Aktionen</span>
        </div>
        {versions.map(v => {
          const working = busy === v.backupId;
          return (
            <div key={v.backupId} className={`cfg-vrow cfg-vrow--${v.status}`} role="row">
              <span role="cell" className="cfg-vrow__time">
                <b>{formatTime(v.createdAt)}</b>
                {v.lastSeenAt && v.lastSeenAt !== v.createdAt && (
                  <span className="diag-table__meta">zuletzt gleich: {formatTime(v.lastSeenAt)}</span>
                )}
                {v.status !== 'ok' && <Badge tone={v.status === 'failed' ? 'critical' : 'warn'}>{label(VERSION_STATUS_LABEL, v.status)}</Badge>}
              </span>
              <span role="cell">
                {label(TYPE_LABEL, v.backupType)}
                <span className="diag-table__meta">
                  {label(REASON_LABEL, v.reason)}
                  {v.createdBy && ` · ${v.createdBy.mine ? 'von dir' : label(ACTOR_LABEL, v.createdBy.kind)}`}
                  {v.openwrtVersion && ` · OpenWrt ${v.openwrtVersion}`}
                </span>
              </span>
              <span role="cell" className="cfg-vrow__num">{formatBytes(v.sizeBytes)}</span>
              <span role="cell" className="diag-mono" title={v.sha256 ?? undefined}>{shortHash(v.sha256)}</span>
              <span role="cell">
                <Badge tone={VALIDATION_TONE[v.validation.state] ?? 'muted'}>{label(VALIDATION_LABEL, v.validation.state)}</Badge>
                {v.validation.checkedAt && <span className="diag-table__meta">{formatTime(v.validation.checkedAt)}</span>}
              </span>
              <span role="cell" className="cfg-vrow__note">
                {v.protected && <Badge tone="info">Geschützt</Badge>}
                {v.note ? <span>{v.note}</span> : <span className="diag-muted">–</span>}
                {v.warnings.map(w => <span key={w} className="diag-table__meta cfg-text-warn">{VERSION_WARNING_TEXT[w] ?? w}</span>)}
              </span>
              <span role="cell" className="cfg-vrow__actions">
                <button type="button" className="diag-btn cfg-btn" disabled={working || readOnly || v.status === 'failed'}
                  onClick={() => void act(v, () => api.validate(v.backupId))}>
                  Prüfen
                </button>
                <button type="button" className="diag-btn cfg-btn" disabled={working || readOnly}
                  aria-pressed={v.protected}
                  onClick={() => void act(v, () => api.protect(v.backupId, !v.protected))}>
                  {v.protected ? 'Schutz aufheben' : 'Schützen'}
                </button>
                <button type="button" className="diag-btn cfg-btn" disabled={working || v.status === 'failed' || v.artifacts.length === 0}
                  onClick={() => onExport(v)}>
                  Export
                </button>
                <button type="button" className="diag-btn cfg-btn" disabled={working || !restorable.has(v.backupId) || !enabled}
                  title={restorable.has(v.backupId) ? undefined : 'Nur Versionen mit Archiv lassen sich wiederherstellen'}
                  onClick={() => onRestore(v)}>
                  Wiederherstellen …
                </button>
                <button type="button" className="diag-btn cfg-btn" disabled={working || v.status === 'failed'}
                  onClick={() => onCompare(v.backupId, 'live')}>
                  Mit aktuell vergleichen
                </button>
              </span>
              {error?.id === v.backupId && <div className="cfg-vrow__error"><ErrorBox error={error.error} /></div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
