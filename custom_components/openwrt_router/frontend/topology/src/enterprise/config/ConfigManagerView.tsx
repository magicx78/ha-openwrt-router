/**
 * ConfigManagerView — Enterprise sub-tab "Konfiguration" (Configuration
 * Manager, plan 8). Router overview → router detail (versions, timeline,
 * drift, comparison, access, approvals) with export and restore assistant.
 *
 * Data is loaded when the tab opens, after every action and on
 * "Aktualisieren". The only repeated request is the bounded re-read while a
 * backup runs (every 5 s, at most 5 min). Nothing is stored in the browser.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import configCSS from './config.css?inline';
import type { Approval, ConfigApi, DriftState, Overview, RouterDetail, RouterSummary, Version } from './configTypes';
import {
  APPROVAL_ACTION_LABEL,
  APPROVAL_STATUS_LABEL,
  CAP_REASON_TEXT,
  DRIFT_STATE_LABEL,
  OPTION_HINT,
  ROUTER_STATE_LABEL,
  SCHEDULE_LABEL,
  archivePath,
  errorInfo,
  failureText,
  isAccessFailure,
  formatRelative,
  formatTime,
  isDriftOpen,
  label,
  routerRisk,
  routerViewState,
  sanitizeNote,
} from './configLogic.ts';
import { ConfigVersionList } from './ConfigVersionList';
import { ConfigDiffView, type DiffRequest } from './ConfigDiffView';
import { ConfigDriftPanel } from './ConfigDriftPanel';
import { ConfigRestoreCheck } from './ConfigRestoreCheck';
import { ConfigApprovalDialog } from './ConfigApprovalDialog';
import { ConfigAccessPanel } from './ConfigAccessPanel';
import { Badge, ErrorBox, Notice, RiskBadge, Skeleton, Spinner, useBoundedPoll } from './configUi';

const STATE_TONE: Record<string, string> = {
  ok: 'ok', drift: 'critical', failed: 'critical', blocked: 'warn', partial: 'warn',
  never: 'muted', disabled: 'muted', running: 'info',
};

// ── Global states (403 / 410 / 503 / conflict) ───────────────────────────

function GlobalError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const info = errorInfo(error);
  if (info.kind === 'forbidden') {
    return <Notice tone="warn"><strong>Nur für Administratoren.</strong> Der Configuration Manager ist auf Administratoren beschränkt.</Notice>;
  }
  if (info.kind === 'gone' || info.kind === 'unavailable' || info.kind === 'network') {
    return (
      <Notice tone="warn">
        {info.kind === 'gone' ? 'Die Integration ist nicht geladen.' : info.message}
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      </Notice>
    );
  }
  return <ErrorBox error={error} onRetry={onRetry} />;
}

// ── Overview ─────────────────────────────────────────────────────────────

function RouterList({ routers, now, onOpen }: { routers: RouterSummary[]; now: number; onOpen: (id: string) => void }) {
  return (
    <div className="cfg-routers" role="table" aria-label="Router">
      <div className="cfg-rrow cfg-rrow--head" role="row">
        <span role="columnheader">Router</span>
        <span role="columnheader">Backup-Status</span>
        <span role="columnheader">Letztes Backup</span>
        <span role="columnheader">Versionen</span>
        <span role="columnheader">Änderungen / Drift</span>
        <span role="columnheader">OpenWrt</span>
        <span role="columnheader">Risiko</span>
      </div>
      {routers.map(r => {
        const st = routerViewState(r);
        const risk = routerRisk(r, now);
        return (
          <button key={r.routerId} type="button" role="row" className={`cfg-rrow cfg-rrow--${st}`} onClick={() => onOpen(r.routerId)}>
            <span role="cell" className="cfg-rrow__name">{r.name}</span>
            <span role="cell">
              {st === 'running' ? <Spinner text="Backup läuft" /> : <Badge tone={STATE_TONE[st]}>{ROUTER_STATE_LABEL[st]}</Badge>}
              {st === 'blocked' && r.capability.reason && (
                <span className="diag-table__meta">{label(CAP_REASON_TEXT, r.capability.reason)}</span>
              )}
            </span>
            <span role="cell">
              <span className="cfg-cell-label">Letztes Backup: </span>
              {r.lastBackupAt ? formatRelative(r.lastBackupAt, now) : '–'}
            </span>
            <span role="cell"><span className="cfg-cell-label">Versionen: </span>{r.versions}</span>
            <span role="cell">
              <span className="cfg-cell-label">Drift: </span>
              {r.drift ? (
                <span className={isDriftOpen(r.drift) ? 'cfg-text-critical' : ''}>
                  {label(DRIFT_STATE_LABEL, r.drift.state)}
                  {isDriftOpen(r.drift) && ` · ${r.drift.criticalCount} kritisch`}
                </span>
              ) : '–'}
            </span>
            <span role="cell"><span className="cfg-cell-label">OpenWrt: </span>{r.openwrtVersion ?? '–'}</span>
            <span role="cell"><RiskBadge risk={risk === 'none' ? null : risk} /></span>
          </button>
        );
      })}
    </div>
  );
}

// ── Detail ───────────────────────────────────────────────────────────────

type Modal = { kind: 'export'; version: Version; resume?: Approval } | { kind: 'restore'; version: Version } | null;

function RouterDetailView({ api, summary, fleetBusy, now, readOnly, onBack, reloadOverview }: {
  api: ConfigApi;
  summary: RouterSummary;
  /** Some router of the fleet is backing up (the core runs one at a time). */
  fleetBusy: boolean;
  now: number;
  readOnly: boolean;
  onBack: () => void;
  reloadOverview: () => Promise<void>;
}) {
  const rid = summary.routerId;
  const [detail, setDetail] = useState<RouterDetail | null>(null);
  const [versions, setVersions] = useState<Version[] | null>(null);
  const [drift, setDrift] = useState<DriftState | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [errors, setErrors] = useState<Record<string, unknown>>({});
  const [note, setNote] = useState('');
  const [backupBusy, setBackupBusy] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [modal, setModal] = useState<Modal>(null);
  const [diffReq, setDiffReq] = useState<DiffRequest | null>(null);

  const load = useCallback(async () => {
    const [d, v, dr, ap] = await Promise.allSettled([
      api.router(rid), api.versions(rid, { limit: 50 }), api.drift(rid), api.approvals(rid),
    ]);
    const err: Record<string, unknown> = {};
    if (d.status === 'fulfilled') setDetail(d.value); else err.detail = d.reason;
    if (v.status === 'fulfilled') setVersions(v.value); else err.versions = v.reason;
    if (dr.status === 'fulfilled') setDrift(dr.value); else err.drift = dr.reason;
    if (ap.status === 'fulfilled') setApprovals(ap.value); else err.approvals = ap.reason;
    setErrors(err);
  }, [api, rid]);

  useEffect(() => { void load(); }, [load]);

  // A running backup (or our own one waiting in the queue): bounded re-read.
  const running = summary.running || waiting;
  useBoundedPoll(running, () => { void reloadOverview(); });
  const prevRunning = useRef(summary.running);
  useEffect(() => {
    if (prevRunning.current && !summary.running) void load();
    prevRunning.current = summary.running;
  }, [summary.running, load]);
  // Our request waited for another router's backup: done once the fleet is idle.
  useEffect(() => {
    if (waiting && !fleetBusy) setWaiting(false);
  }, [waiting, fleetBusy, now]);

  const [cooldownUntil, setCooldownUntil] = useState<number | null>(null);
  useEffect(() => {
    if (cooldownUntil === null) return undefined;
    const t = window.setTimeout(() => setCooldownUntil(null), Math.max(0, cooldownUntil - Date.now()));
    return () => window.clearTimeout(t);
  }, [cooldownUntil]);
  const coolingDown = cooldownUntil !== null;

  const backupNow = async () => {
    setBackupBusy(true);
    setActionError(null);
    try {
      await api.backup(rid, sanitizeNote(note) || undefined);
      setNote('');
      await Promise.all([load(), reloadOverview()]);
    } catch (e) {
      const info = errorInfo(e);
      if (info.kind === 'busy') setWaiting(true);
      // Too soon: lock the button until Retry-After has passed (no automatic retry).
      if (info.kind === 'rate_limited' && info.retryAfter !== null) setCooldownUntil(Date.now() + info.retryAfter * 1000);
      setActionError(e);
    } finally {
      setBackupBusy(false);
    }
  };

  const path = detail ? archivePath(detail) : 'unknown';
  const enabled = summary.enabled && (detail?.enabled ?? true);
  const exportPending = approvals.filter(a => a.action === 'export' && (a.status === 'pending' || a.status === 'approved'));
  const accessNeeded = detail !== null && (
    summary.capability.state !== 'available'
    || detail.sshPin?.state === 'pending' || detail.sshPin?.state === 'mismatch'
    || (detail.acl?.offerable.length ?? 0) > 0
    || isAccessFailure(summary.errorClass));
  const st = routerViewState(summary);

  return (
    <div className="cfg-stack">
      <div className="diag-detail__bar">
        <button type="button" className="diag-btn cfg-btn" onClick={onBack}>← Alle Router</button>
        <button type="button" className="diag-btn cfg-btn" onClick={() => { void load(); void reloadOverview(); }}>Aktualisieren</button>
      </div>
      <div className="diag-detail__head">
        <span className="diag-detail__title">{summary.name}</span>
        {st === 'running' ? <Spinner text="Backup läuft …" /> : <Badge tone={STATE_TONE[st]}>{ROUTER_STATE_LABEL[st]}</Badge>}
        <RiskBadge risk={routerRisk(summary, now) === 'none' ? null : routerRisk(summary, now)} />
      </div>

      {!enabled && <Notice tone="info">{OPTION_HINT}</Notice>}
      {path === 'uci_only' && (
        <Notice tone="warn">
          <strong>Nur UCI-Snapshot.</strong> Dieser Router liefert kein Vollarchiv (weder cgi-io noch SSH). Gesichert wird
          nur die UCI-Konfiguration; eine Wiederherstellung über LuCI oder sysupgrade ist damit nicht möglich.
        </Notice>
      )}
      {st === 'failed' && (
        <Notice tone="error">
          {failureText(summary.errorClass)}
          <button type="button" className="diag-btn cfg-btn" disabled={backupBusy || coolingDown || readOnly || !enabled} onClick={() => void backupNow()}>
            Erneut versuchen
          </button>
        </Notice>
      )}

      <div className="diag-facts">
        <Fact name="Letztes Backup" value={summary.lastBackupAt ? `${formatTime(summary.lastBackupAt)} (${formatRelative(summary.lastBackupAt, now)})` : 'noch keins'} />
        <Fact name="Versionen" value={String(summary.versions)} />
        <Fact name="OpenWrt" value={summary.openwrtVersion ?? '–'} />
        <Fact name="Zeitplan" value={summary.schedule
          ? `${label(SCHEDULE_LABEL, summary.schedule.mode)}${summary.schedule.time ? ` ab ${summary.schedule.time}` : ''}` : '–'} />
        <Fact name="Nächster Lauf" value={formatTime(summary.schedule?.nextRunAt ?? null)} />
        <Fact name="Archivweg" value={path === 'archive' ? 'Vollarchiv' : path === 'uci_only' ? 'nur UCI-Snapshot' : path === 'none' ? 'keiner' : 'unbekannt'} />
      </div>

      <section className="cfg-section">
        <h3 className="cfg-section__title">Backup jetzt</h3>
        <div className="cfg-backup">
          <label className="diag-field diag-field--block cfg-backup__note">
            <span className="diag-field__label">Beschreibung (optional, höchstens 200 Zeichen)</span>
            <input value={note} maxLength={200} onChange={e => setNote(e.target.value)} placeholder="z. B. vor dem Firmware-Update" />
          </label>
          <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={backupBusy || running || coolingDown || readOnly || !enabled}
            onClick={() => void backupNow()}>
            Jetzt sichern
          </button>
        </div>
        {backupBusy && <Spinner text="Backup wird erstellt …" />}
        {waiting && <Spinner text="Auf dem Router läuft gerade ein anderer Vorgang; die Ansicht fragt alle 5 s nach (höchstens 5 min). Danach erneut sichern." />}
        <ErrorBox error={actionError} />
      </section>

      {(accessNeeded || errors.detail !== undefined) && (
        <section className="cfg-section">
          <h3 className="cfg-section__title">Zugang</h3>
          <ErrorBox error={errors.detail} onRetry={() => void load()} />
          {detail && <ConfigAccessPanel api={api} detail={detail} approvals={approvals} readOnly={readOnly} enabled={enabled}
            onChanged={() => { void load(); void reloadOverview(); }} />}
        </section>
      )}

      <section className="cfg-section">
        <h3 className="cfg-section__title">Drift</h3>
        <ErrorBox error={errors.drift} onRetry={() => void load()} />
        {drift === null && errors.drift === undefined ? <Skeleton rows={2} /> : (
          <ConfigDriftPanel api={api} routerId={rid} drift={drift} enabled={enabled} readOnly={readOnly}
            onChanged={d => { setDrift(d); void reloadOverview(); }}
            onShowDiff={from => setDiffReq({ from, to: 'live', seq: Date.now() })} />
        )}
      </section>

      {(exportPending.length > 0 || errors.approvals !== undefined) && (
        <section className="cfg-section">
          <h3 className="cfg-section__title">Offene Freigaben</h3>
          <ErrorBox error={errors.approvals} onRetry={() => void load()} />
          <ul className="cfg-list">
            {exportPending.map(a => {
              const v = versions?.find(x => x.backupId === a.subjectId);
              return (
                <li key={a.approvalId} className="cfg-approval">
                  <span>{label(APPROVAL_ACTION_LABEL, a.action)} · {label(APPROVAL_STATUS_LABEL, a.status)} · bis {formatTime(a.expiresAt)}</span>
                  {v && <button type="button" className="diag-btn cfg-btn" onClick={() => setModal({ kind: 'export', version: v, resume: a })}>Fortsetzen</button>}
                </li>
              );
            })}
          </ul>
        </section>
      )}

      <section className="cfg-section">
        <h3 className="cfg-section__title">Versionen</h3>
        <ErrorBox error={errors.versions} onRetry={() => void load()} />
        {versions === null && errors.versions === undefined && <Skeleton rows={4} />}
        {versions !== null && versions.length === 0 && (
          <div className="cfg-empty">
            Noch keine Versionen gespeichert.
            {enabled && !readOnly && (
              <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={backupBusy || running}
                onClick={() => void backupNow()}>
                Jetzt sichern
              </button>
            )}
          </div>
        )}
        {versions !== null && versions.length > 0 && (
          <ConfigVersionList api={api} versions={versions} now={now} readOnly={readOnly} enabled={enabled}
            onChanged={nv => setVersions(prev => (prev ?? []).map(x => (x.backupId === nv.backupId ? nv : x)))}
            onExport={v => setModal({ kind: 'export', version: v })}
            onRestore={v => setModal({ kind: 'restore', version: v })}
            onCompare={(from, to) => setDiffReq({ from, to, seq: Date.now() })} />
        )}
      </section>

      {versions !== null && versions.length > 0 && (
        <section className="cfg-section" id="cfg-diff">
          <h3 className="cfg-section__title">Vergleich</h3>
          <ConfigDiffView api={api} routerId={rid} versions={versions} request={diffReq} />
        </section>
      )}

      {modal?.kind === 'export' && (
        <ConfigApprovalDialog api={api} version={modal.version} resume={modal.resume ?? null} readOnly={readOnly}
          onClose={() => { setModal(null); void load(); }} />
      )}
      {modal?.kind === 'restore' && versions && (
        <ConfigRestoreCheck api={api} versions={versions} initialBackupId={modal.version.backupId}
          routerName={summary.name} readOnly={readOnly} onClose={() => { setModal(null); void load(); }} />
      )}
    </div>
  );
}

function Fact({ name, value }: { name: string; value: string }) {
  return (
    <div className="diag-fact">
      <span className="diag-fact__label">{name}</span>
      <span className="diag-fact__value">{value}</span>
    </div>
  );
}

// ── Tab root ─────────────────────────────────────────────────────────────

export function ConfigManagerView({ api }: { api: ConfigApi }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const o = await api.overview();
      setOverview(o);
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setNow(Date.now());
      setLoading(false);
    }
  }, [api]);

  useEffect(() => { void load(); }, [load]);

  const anyRunning = overview?.routers.some(r => r.running) ?? false;
  // In the detail the detail view polls itself; the list polls only while shown.
  useBoundedPoll(anyRunning && selected === null, () => { void load(); });

  const readOnly = overview !== null && overview.provider !== null && overview.provider !== 'config_manager';
  const conflict = errorInfo(error).kind === 'conflict';
  const summary = overview?.routers.find(r => r.routerId === selected) ?? null;

  return (
    <div className="cfg">
      <style>{configCSS}</style>
      <div className="cfg-header">
        <span className="view-title">Configuration Manager</span>
        {overview && overview.pendingApprovals > 0 && (
          <Badge tone="warn">{overview.pendingApprovals} offene Freigabe{overview.pendingApprovals === 1 ? '' : 'n'}</Badge>
        )}
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={loading}
          onClick={() => { setLoading(true); void load(); }}>
          Aktualisieren
        </button>
      </div>

      {(readOnly || conflict) && (
        <Notice tone="warn">
          <strong>Fremdes Backup-Modul.</strong> Ein anderes Modul ist beim Enterprise Core angemeldet. Diese Ansicht ist nur
          lesbar; Aktionen sind gesperrt.
        </Notice>
      )}
      {error !== null && !conflict && (overview === null
        ? <GlobalError error={error} onRetry={() => { setLoading(true); void load(); }} />
        : <ErrorBox error={error} onRetry={() => void load()} />)}

      {loading && overview === null && <Skeleton rows={5} />}

      {overview && overview.routers.length === 0 && (
        <div className="cfg-empty">Keine Router eingerichtet. Router werden über die OpenWrt-Router-Integration hinzugefügt.</div>
      )}

      {overview && summary && (
        <RouterDetailView key={summary.routerId} api={api} summary={summary} fleetBusy={anyRunning} now={now} readOnly={readOnly}
          onBack={() => setSelected(null)} reloadOverview={load} />
      )}
      {overview && !summary && overview.routers.length > 0 && (
        <>
          <div className="cfg-hint">
            Gesichert wird die Router-Konfiguration in Home Assistant. Ein Archiv enthält alle Router-Geheimnisse im Klartext;
            Export und Wiederherstellung brauchen eine ausdrückliche Bestätigung.
          </div>
          <RouterList routers={overview.routers} now={now} onOpen={setSelected} />
        </>
      )}
    </div>
  );
}
