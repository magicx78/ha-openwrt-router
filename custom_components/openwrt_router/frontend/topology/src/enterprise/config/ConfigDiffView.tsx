/**
 * ConfigDiffView — compare two versions, or a version with the live router
 * (R8). Grouped by area, highest risk first; critical areas (Management-IP,
 * VLAN, Firewall, SSH, Uplink) are marked. Secrets only say "geändert".
 * Loads on demand only (a live comparison reads the router).
 */

import React, { useEffect, useState } from 'react';
import type { Change, ConfigApi, Diff, Version } from './configTypes';
import {
  OP_LABEL,
  changeValueText,
  formatTime,
  groupChangesByArea,
  isCriticalChange,
  label,
  REASON_LABEL,
} from './configLogic.ts';
import { Badge, ErrorBox, RiskBadge, Skeleton } from './configUi';

function changePath(c: Change): string {
  return [c.config, c.section, c.option].filter(Boolean).join('.');
}

function ChangeRow({ c }: { c: Change }) {
  return (
    <li className={`cfg-change cfg-change--${c.op}${isCriticalChange(c) ? ' cfg-change--critical' : ''}`}>
      <div className="cfg-change__head">
        <span className={`cfg-op cfg-op--${c.op}`}>{OP_LABEL[c.op]}</span>
        <span className="cfg-change__path diag-mono">{changePath(c)}</span>
        <RiskBadge risk={c.risk} />
      </div>
      {c.op !== 'reordered' && c.op !== 'not_comparable' && (
        <div className="cfg-change__values">
          {c.secret ? (
            <span className="cfg-change__secret">Geheimer Wert geändert (Inhalt wird nicht angezeigt)</span>
          ) : (
            <>
              {c.op !== 'added' && <span className="cfg-change__old">{changeValueText(c, 'old')}</span>}
              {c.op === 'changed' && <span className="cfg-change__arrow" aria-label="wird zu">→</span>}
              {c.op !== 'removed' && <span className="cfg-change__new">{changeValueText(c, 'new')}</span>}
            </>
          )}
        </div>
      )}
    </li>
  );
}

/** Rendered change list (also used by the restore preview). */
export function ConfigDiffList({ changes, complete = true, truncated = false }: {
  changes: readonly Change[];
  complete?: boolean;
  truncated?: boolean;
}) {
  const groups = groupChangesByArea(changes);
  if (changes.length === 0) {
    return <div className="cfg-empty">Keine Unterschiede.</div>;
  }
  const critical = changes.filter(isCriticalChange).length;
  return (
    <div className="cfg-diff">
      <div className="diag-kv">
        <span><b>{changes.length}</b> Änderungen</span>
        {critical > 0 && <span className="cfg-text-critical"><b>{critical}</b> in kritischen Bereichen</span>}
        {!complete && <span className="cfg-text-warn">Vergleich unvollständig</span>}
        {truncated && <span className="cfg-text-warn">Liste gekürzt</span>}
      </div>
      {groups.map(g => (
        <details key={g.area} className={`cfg-group${g.critical ? ' cfg-group--critical' : ''}`} open={g.critical || groups.length <= 3}>
          <summary className="cfg-group__head">
            <span className="cfg-group__title">{g.label}</span>
            {g.critical && <Badge tone="critical">Kritischer Bereich</Badge>}
            <RiskBadge risk={g.maxRisk} />
            <span className="cfg-group__counts">
              {g.counts.added > 0 && <span className="cfg-op--added">+{g.counts.added}</span>}
              {g.counts.removed > 0 && <span className="cfg-op--removed">−{g.counts.removed}</span>}
              {g.counts.changed > 0 && <span className="cfg-op--changed">~{g.counts.changed}</span>}
              {g.counts.other > 0 && <span>·{g.counts.other}</span>}
            </span>
          </summary>
          <ul className="cfg-changes">
            {g.changes.map((c, i) => <ChangeRow key={`${changePath(c)}-${c.op}-${i}`} c={c} />)}
          </ul>
        </details>
      ))}
    </div>
  );
}

export interface DiffRequest {
  from: string;
  to: string;
  /** Changes on every new request so the same pair can be loaded again. */
  seq: number;
}

function versionOption(v: Version) {
  return `${formatTime(v.createdAt)} · ${label(REASON_LABEL, v.reason)}`;
}

export function ConfigDiffView({ api, routerId, versions, request }: {
  api: ConfigApi;
  routerId: string;
  versions: readonly Version[];
  request: DiffRequest | null;
}) {
  const usable = versions.filter(v => v.status !== 'failed');
  const [from, setFrom] = useState<string>(usable[0]?.backupId ?? '');
  const [to, setTo] = useState<string>('live');
  const [diff, setDiff] = useState<Diff | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  const load = async (a: string, b: string) => {
    if (!a || !b || a === b) return;
    setLoading(true);
    setError(null);
    try {
      setDiff(await api.diff(routerId, a, b));
    } catch (e) {
      setDiff(null);
      setError(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!request) return;
    setFrom(request.from);
    setTo(request.to);
    void load(request.from, request.to);
    // only a new request (seq) triggers a load
  }, [request?.seq]);

  useEffect(() => {
    if (!from && usable[0]) setFrom(usable[0].backupId);
  }, [usable[0]?.backupId]);

  if (usable.length === 0) {
    return <div className="cfg-empty">Für einen Vergleich wird mindestens eine Version gebraucht.</div>;
  }

  return (
    <div className="cfg-stack">
      <div className="diag-filters cfg-diff__pick">
        <label>
          Von
          <select value={from} onChange={e => setFrom(e.target.value)}>
            {usable.map(v => <option key={v.backupId} value={v.backupId}>{versionOption(v)}</option>)}
          </select>
        </label>
        <label>
          Nach
          <select value={to} onChange={e => setTo(e.target.value)}>
            <option value="live">Aktueller Stand (Router)</option>
            {usable.map(v => <option key={v.backupId} value={v.backupId}>{versionOption(v)}</option>)}
          </select>
        </label>
        <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={loading || !from || from === to}
          onClick={() => void load(from, to)}>
          Vergleichen
        </button>
      </div>
      {to === 'live' && <div className="cfg-hint">Der Vergleich mit dem aktuellen Stand liest die Konfiguration einmal vom Router.</div>}
      {loading && <Skeleton rows={4} />}
      <ErrorBox error={error} onRetry={() => void load(from, to)} />
      {diff && !loading && <ConfigDiffList changes={diff.changes} complete={diff.complete} truncated={diff.truncated} />}
    </div>
  );
}
