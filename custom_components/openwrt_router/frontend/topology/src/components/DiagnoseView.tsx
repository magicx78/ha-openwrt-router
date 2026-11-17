/**
 * DiagnoseView — network intelligence tab (P7).
 *
 * Overview, incidents (roots with expandable follow-up incidents), timeline
 * with filters, WLAN, client stability, infrastructure, incident detail and
 * settings. All data comes from /api/openwrt_topology/intelligence/* (engine
 * memory, no router calls). Refresh: whenever the panel's snapshot refreshes
 * (`refreshKey`, every 30 s; the stability tab at most every 60 s) — no own
 * timer.
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type { IntelApi } from '../api';
import type {
  IntelEvent,
  IntelIncident,
  IntelIncidentDetail,
  IntelSummary,
  IncidentCounts,
  Severity,
} from '../types';
import {
  AREA_LABEL,
  CATEGORY_LABEL,
  CAUSE_LEVEL_LABEL,
  SCOPE_LABEL,
  errorMessage,
  SEVERITY_LABEL,
  STATUS_LABEL,
  causeLabel,
  formatDuration,
  formatTs,
  isWifiIncident,
  kindLabel,
  logLabel,
  recommendation,
  typeLabel,
} from '../utils/intel';
import { IntelSettingsView } from './IntelSettingsView';
import { StabilityView } from './StabilityView';

type SubTab = 'overview' | 'incidents' | 'timeline' | 'wifi' | 'stability' | 'infra' | 'settings';

const SUB_TABS: Array<{ id: SubTab; label: string }> = [
  { id: 'overview', label: 'Übersicht' },
  { id: 'incidents', label: 'Incidents' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'wifi', label: 'WLAN' },
  { id: 'stability', label: 'Stabilität' },
  { id: 'infra', label: 'Infrastruktur' },
  { id: 'settings', label: 'Einstellungen' },
];

const PERIODS: Array<{ id: string; label: string; seconds: number | null }> = [
  { id: '1h', label: '1 Stunde', seconds: 3600 },
  { id: '24h', label: '24 Stunden', seconds: 86400 },
  { id: '7d', label: '7 Tage', seconds: 7 * 86400 },
  { id: '30d', label: '30 Tage', seconds: 30 * 86400 },
  { id: 'all', label: 'Alles', seconds: null },
];

const PAGE = 100;

interface Props {
  api?: IntelApi;
  /** Changes on every snapshot refresh; triggers a reload of the open view. */
  refreshKey: string;
  /** Router (config entry id) preselected from a warning symbol, or null. */
  routerFilter: string | null;
  onRouterFilterChange: (router: string | null) => void;
  onBack: () => void;
}

function SeverityDot({ severity }: { severity: Severity }) {
  return <span className={`diag-dot diag-dot--${severity}`} title={SEVERITY_LABEL[severity]} />;
}

function CountPills({ counts }: { counts: IncidentCounts }) {
  return (
    <span className="diag-pills">
      {(['critical', 'warning', 'info'] as const).map(s => (
        <span key={s} className={`diag-pill diag-pill--${s}${counts[s] ? '' : ' diag-pill--zero'}`}>
          {counts[s]} {SEVERITY_LABEL[s]}
        </span>
      ))}
    </span>
  );
}

/** "bestätigt" or "Hypothese · 60 % (möglich)" — cause status, confidence, level. */
export function CauseBadge({ inc }: { inc: IntelIncident }) {
  const pct = `${Math.round(inc.confidence * 100)} %`;
  if (inc.cause_status === 'confirmed') {
    return <span className="diag-cause diag-cause--confirmed" title={`Konfidenz ${pct}`}>bestätigt</span>;
  }
  if (inc.cause_status === 'hypothesis') {
    return (
      <span className={`diag-cause diag-cause--${inc.cause_level}`} title="Ursache aus Indizien abgeleitet">
        Hypothese · {pct} ({CAUSE_LEVEL_LABEL[inc.cause_level]})
      </span>
    );
  }
  return <span className="diag-cause diag-cause--unknown">{CAUSE_LEVEL_LABEL.unknown}</span>;
}

function ScoreValue({ score }: { score: number | null }) {
  if (score == null) return <span className="diag-score diag-score--unknown" title="Zu wenig Daten">–</span>;
  const cls = score >= 80 ? 'good' : score >= 50 ? 'fair' : 'poor';
  return <span className={`diag-score diag-score--${cls}`}>{score}</span>;
}

// ── Incident list with expandable follow-ups ─────────────────────────────

function IncidentRow({
  inc,
  childCount,
  expanded,
  onToggle,
  onOpen,
  nested,
}: {
  inc: IntelIncident;
  childCount: number;
  expanded: boolean;
  onToggle?: () => void;
  onOpen: () => void;
  nested?: boolean;
}) {
  return (
    <div className={`diag-inc diag-inc--${inc.severity} diag-inc--st-${inc.status}${nested ? ' diag-inc--nested' : ''}`}>
      <button type="button" className="diag-inc__main" onClick={onOpen}>
        <SeverityDot severity={inc.severity} />
        <span className="diag-inc__text">
          <span className="diag-inc__title">{typeLabel(inc.type)}</span>
          <span className="diag-inc__sub">
            {inc.router_names.join(', ') || SCOPE_LABEL[inc.scope] || inc.scope}
            {inc.scope === 'client' || inc.scope === 'port' || inc.scope === 'radio'
              ? ` · ${SCOPE_LABEL[inc.scope]} ${inc.scope_key.split(':').pop()}`
              : ''}
            {' · '}
            {formatDuration(inc.duration_s)}
            {inc.occurrences > 1 ? ` · ${inc.occurrences}×` : ''}
          </span>
          <span className="diag-inc__cause">
            Ursache: {causeLabel(inc.cause)} <CauseBadge inc={inc} />
          </span>
        </span>
        <span className={`diag-status diag-status--${inc.status}`}>{STATUS_LABEL[inc.status]}</span>
      </button>
      {childCount > 0 && onToggle && (
        <button type="button" className="diag-inc__children" onClick={onToggle} aria-expanded={expanded}>
          {expanded ? '▾' : '▸'} {childCount} Folgeproblem{childCount === 1 ? '' : 'e'}
        </button>
      )}
    </div>
  );
}

function IncidentTree({
  incidents,
  onOpen,
  empty,
}: {
  incidents: IntelIncident[];
  onOpen: (id: string) => void;
  empty: string;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const { roots, children } = useMemo(() => {
    const ids = new Set(incidents.map(i => i.id));
    const kids = new Map<string, IntelIncident[]>();
    const top: IntelIncident[] = [];
    for (const inc of incidents) {
      // indented only while it is a silent child; a child that counts on
      // its own again (E8/E12) is a root of the list, parent_id is history
      if (inc.child && inc.parent_id && ids.has(inc.parent_id)) {
        const list = kids.get(inc.parent_id) ?? [];
        list.push(inc);
        kids.set(inc.parent_id, list);
      } else {
        top.push(inc);
      }
    }
    return { roots: top, children: kids };
  }, [incidents]);

  if (roots.length === 0) return <div className="view-empty">{empty}</div>;
  const toggle = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  return (
    <div className="diag-list">
      {roots.map(inc => {
        const kids = children.get(inc.id) ?? [];
        const open = expanded.has(inc.id);
        return (
          <React.Fragment key={inc.id}>
            <IncidentRow
              inc={inc}
              childCount={kids.length}
              expanded={open}
              onToggle={() => toggle(inc.id)}
              onOpen={() => onOpen(inc.id)}
            />
            {open && kids.map(kid => (
              <IncidentRow key={kid.id} inc={kid} childCount={0} expanded={false} onOpen={() => onOpen(kid.id)} nested />
            ))}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ── Event rows ────────────────────────────────────────────────────────────

function EventRow({ ev, onOpenIncident }: { ev: IntelEvent; onOpenIncident?: (id: string) => void }) {
  const mac = typeof ev.subject?.mac === 'string' ? (ev.subject.mac as string) : null;
  const port = typeof ev.subject?.port === 'string' ? (ev.subject.port as string) : null;
  return (
    <div className={`diag-ev diag-ev--${ev.severity}`}>
      <span className="diag-ev__time">{formatTs(ev.ts)}</span>
      <SeverityDot severity={ev.severity} />
      <span className="diag-ev__body">
        <span className="diag-ev__kind">
          {CATEGORY_LABEL[ev.category] ?? ev.category} · {kindLabel(ev.kind)}
          {ev.count > 1 ? ` ×${ev.count}` : ''}
        </span>
        <span className="diag-ev__sub">
          {ev.router_name}
          {mac ? ` · ${mac}` : ''}
          {port ? ` · ${port}` : ''}
          {ev.origin === 'inferred' ? ' · abgeleitet' : ''}
          {ev.maintenance ? ' · Wartung' : ''}
          {ev.role === 'follow_up' ? ' · Folge' : ev.role === 'evidence' ? ' · Beleg' : ''}
        </span>
      </span>
      {ev.parent_id && onOpenIncident && (
        <button type="button" className="diag-link" onClick={() => onOpenIncident(ev.parent_id!)}>
          Incident
        </button>
      )}
    </div>
  );
}

// ── Incident detail ───────────────────────────────────────────────────────

function IncidentDetailView({
  api,
  id,
  refreshKey,
  onOpen,
  onClose,
  onChanged,
}: {
  api: IntelApi;
  id: string;
  refreshKey: string;
  onOpen: (id: string) => void;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<IntelIncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api.incident(id).then(
      d => { if (alive) { setDetail(d); setError(null); } },
      e => { if (alive) setError(errorMessage(e)); },
    );
    return () => { alive = false; };
  }, [api, id, refreshKey]);

  const act = async (status: 'acknowledged' | 'ignored' | 'active', days?: number) => {
    setBusy(true);
    try {
      setDetail(await api.setIncidentStatus(id, status, days));
      setError(null);
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const inc = detail?.incident;
  const rec = inc ? recommendation(inc.type, inc.recommendation_key) : undefined;
  const admin = api.isAdmin();
  return (
    <div className="diag-detail">
      <div className="diag-detail__bar">
        <button type="button" className="diag-btn" onClick={onClose}>← Zurück</button>
        {inc && <span className={`diag-status diag-status--${inc.status}`}>{STATUS_LABEL[inc.status]}</span>}
      </div>
      {error && <div className="diag-error">{error}</div>}
      {!inc && !error && <div className="view-empty">Lade Incident…</div>}
      {inc && (
        <>
          <div className="diag-detail__head">
            <SeverityDot severity={inc.severity} />
            <span className="diag-detail__title">{typeLabel(inc.type)}</span>
            <span className={`diag-pill diag-pill--${inc.severity}`}>{SEVERITY_LABEL[inc.severity]}</span>
          </div>

          <div className="diag-facts">
            <Fact label="Betrifft" value={`${SCOPE_LABEL[inc.scope] ?? inc.scope} ${inc.scope === 'router' || inc.scope === 'fleet' ? '' : inc.scope_key.split(':').pop()}`} />
            <Fact label="Router" value={inc.router_names.join(', ') || '–'} />
            <Fact label="Seit" value={formatTs(inc.reopened_at ?? inc.first_seen)} />
            <Fact label="Zuletzt" value={formatTs(inc.last_seen)} />
            <Fact label="Dauer" value={formatDuration(inc.duration_s)} />
            {inc.resolved_at != null && <Fact label="Behoben" value={formatTs(inc.resolved_at)} />}
            {inc.ignore_until != null && <Fact label="Ignoriert bis" value={formatTs(inc.ignore_until)} />}
            <Fact label="Vorkommen" value={String(inc.occurrences)} />
            {inc.reopen_count > 0 && <Fact label="Wieder geöffnet" value={`${inc.reopen_count}×`} />}
            {inc.affected > 0 && <Fact label="Betroffen" value={String(inc.affected)} />}
            {inc.area && <Fact label="Bereich" value={AREA_LABEL[inc.area] ?? inc.area} />}
            <Fact label="Herkunft" value={inc.origin === 'inferred' ? 'abgeleitet' : 'gemessen'} />
          </div>

          <div className="settings-card">
            <div className="settings-card__heading">Ursache</div>
            <div className="diag-cause-line">
              {causeLabel(inc.cause)} <CauseBadge inc={inc} />
            </div>
            <div className="settings-info">
              Einstufung: {CAUSE_LEVEL_LABEL[inc.cause_level]} – „bestätigt“ nur mit Messdaten,
              „wahrscheinlich“ nur mit mindestens zwei unabhängigen Quellen, sonst „möglich“.
            </div>
          </div>

          {rec && (
            <div className="settings-card">
              <div className="settings-card__heading">Empfehlung</div>
              <div className="diag-rec">{rec}</div>
            </div>
          )}

          {admin ? (
            <div className="diag-actions">
              {inc.status === 'active' && (
                <button type="button" className="diag-btn" disabled={busy} onClick={() => act('acknowledged')}>
                  Als gesehen markieren
                </button>
              )}
              {inc.status !== 'resolved' && inc.status !== 'ignored' && (
                <>
                  <button type="button" className="diag-btn" disabled={busy} onClick={() => act('ignored', 1)}>Ignorieren 1 Tag</button>
                  <button type="button" className="diag-btn" disabled={busy} onClick={() => act('ignored', 7)}>Ignorieren 7 Tage</button>
                </>
              )}
              {(inc.status === 'acknowledged' || inc.status === 'ignored') && (
                <button type="button" className="diag-btn" disabled={busy} onClick={() => act('active')}>
                  Wieder aktivieren
                </button>
              )}
            </div>
          ) : (
            <div className="settings-info">Bestätigen und Ignorieren nur als Administrator.</div>
          )}

          {detail.parent && (
            <div className="settings-card">
              <div className="settings-card__heading">Folge von</div>
              <IncidentRow inc={detail.parent} childCount={0} expanded={false} onOpen={() => onOpen(detail.parent!.id)} />
            </div>
          )}

          {detail.children.length > 0 && (
            <div className="settings-card">
              <div className="settings-card__heading">Folgeprobleme ({detail.children.length})</div>
              <div className="diag-list">
                {detail.children.map(c => (
                  <IncidentRow key={c.id} inc={c} childCount={0} expanded={false} onOpen={() => onOpen(c.id)} nested />
                ))}
              </div>
            </div>
          )}

          <div className="settings-card">
            <div className="settings-card__heading">Ereigniskette ({detail.chain.length})</div>
            {detail.chain.length === 0 ? (
              <div className="settings-info">Keine gespeicherten Ereignisse (älter als die Aufbewahrung oder nur Messwerte).</div>
            ) : (
              <div className="diag-list">
                {detail.chain.map(ev => <EventRow key={ev.id} ev={ev} />)}
              </div>
            )}
          </div>

          <div className="settings-card">
            <div className="settings-card__heading">Belege ({inc.evidence_count})</div>
            <div className="diag-list">
              {(inc.evidence ?? []).slice().reverse().map((e, i) => (
                <div key={`${e.id ?? 'm'}-${i}`} className="diag-ev">
                  <span className="diag-ev__time">{formatTs(e.ts)}</span>
                  <span className="diag-ev__body">
                    <span className="diag-ev__kind">{kindLabel(e.kind)}</span>
                    <span className="diag-ev__sub">{e.event ? 'gespeichertes Ereignis' : 'Messwert'}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="diag-fact">
      <span className="diag-fact__label">{label}</span>
      <span className="diag-fact__value">{value}</span>
    </div>
  );
}

// ── Timeline ──────────────────────────────────────────────────────────────

function Timeline({
  api,
  summary,
  refreshKey,
  routerFilter,
  onRouterFilterChange,
  onOpenIncident,
}: {
  api: IntelApi;
  summary: IntelSummary | null;
  refreshKey: string;
  routerFilter: string | null;
  onRouterFilterChange: (r: string | null) => void;
  onOpenIncident: (id: string) => void;
}) {
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [period, setPeriod] = useState('24h');
  const [mac, setMac] = useState('');
  const [events, setEvents] = useState<IntelEvent[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const query = useMemo(() => {
    const seconds = PERIODS.find(p => p.id === period)?.seconds ?? null;
    const now = summary?.generated_at ?? Date.now() / 1000;
    return {
      router: routerFilter ?? undefined,
      category: category || undefined,
      severity: severity || undefined,
      since: seconds != null ? Math.floor(now - seconds) : undefined,
      mac: mac.trim() || undefined,
      limit: PAGE,
    };
    // summary.generated_at moves with every refresh; the window follows it
  }, [routerFilter, category, severity, period, mac, summary?.generated_at]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api.events(query).then(
      page => { if (alive) { setEvents(page.events); setNext(page.next_before); setError(null); } },
      e => { if (alive) setError(errorMessage(e)); },
    ).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [api, query, refreshKey]);

  const more = async () => {
    if (!next) return;
    try {
      const page = await api.events({ ...query, before: next });
      setEvents(prev => [...prev, ...page.events]);
      setNext(page.next_before);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <>
      <div className="diag-filters">
        <label>
          Router
          <select value={routerFilter ?? ''} onChange={e => onRouterFilterChange(e.target.value || null)}>
            <option value="">Alle</option>
            {(summary?.routers ?? []).map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </label>
        <label>
          Kategorie
          <select value={category} onChange={e => setCategory(e.target.value)}>
            <option value="">Alle</option>
            {Object.entries(CATEGORY_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
        <label>
          Schweregrad
          <select value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="">Alle</option>
            {(['critical', 'warning', 'info'] as const).map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </select>
        </label>
        <label>
          Zeitraum
          <select value={period} onChange={e => setPeriod(e.target.value)}>
            {PERIODS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
          </select>
        </label>
        <label>
          MAC
          <input value={mac} onChange={e => setMac(e.target.value)} placeholder="optional" spellCheck={false} />
        </label>
      </div>
      {error && <div className="diag-error">{error}</div>}
      {!error && events.length === 0 && !loading && <div className="view-empty">Keine Ereignisse für diese Filter.</div>}
      <div className="diag-list">
        {events.map(ev => <EventRow key={ev.id} ev={ev} onOpenIncident={onOpenIncident} />)}
      </div>
      {next && (
        <button type="button" className="diag-btn diag-btn--wide" onClick={more}>Ältere laden</button>
      )}
    </>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────

export function DiagnoseView({ api, refreshKey, routerFilter, onRouterFilterChange, onBack }: Props) {
  const [tab, setTab] = useState<SubTab>('overview');
  const [summary, setSummary] = useState<IntelSummary | null>(null);
  const [incidents, setIncidents] = useState<IntelIncident[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [showResolved, setShowResolved] = useState(false);
  const [bump, setBump] = useState(0);

  const reload = useCallback(() => setBump(b => b + 1), []);

  useEffect(() => {
    if (!api) return;
    let alive = true;
    Promise.all([api.summary(), api.incidents({ limit: 200 })]).then(
      ([s, list]) => {
        if (!alive) return;
        setSummary(s);
        setIncidents(list.incidents);
        setError(null);
      },
      e => { if (alive) setError(errorMessage(e)); },
    );
    return () => { alive = false; };
  }, [api, refreshKey, bump]);

  const header = (
    <div className="view-header">
      <span className="diag-header-left">
        <button type="button" className="diag-btn diag-btn--back" onClick={onBack} title="Zur Topologie">←</button>
        <span className="view-title">Diagnose</span>
      </span>
      {summary && (
        <span className="view-count">
          Flotte <ScoreValue score={summary.fleet.score} /> · Abdeckung {Math.round(summary.fleet.coverage * 100)} %
        </span>
      )}
    </div>
  );

  if (!api) {
    return (
      <div className="topo-view diag">
        {header}
        <div className="view-empty">Die Diagnose ist nur in Home Assistant verfügbar.</div>
      </div>
    );
  }

  const routerName = summary?.routers.find(r => r.id === routerFilter)?.name;
  const filtered = incidents.filter(i =>
    (showResolved || i.status !== 'resolved') && (!routerFilter || i.routers.includes(routerFilter)),
  );
  const wifi = filtered.filter(i => isWifiIncident(i.type, i.area));
  const infra = filtered.filter(i => !isWifiIncident(i.type, i.area));
  const open = (id: string) => setOpenId(id);

  return (
    <div className="topo-view diag">
      {header}
      <div className="diag-tabs" role="tablist">
        {SUB_TABS.map(t => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={`diag-tab${tab === t.id ? ' active' : ''}`}
            onClick={() => { setTab(t.id); setOpenId(null); }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {routerFilter && tab !== 'settings' && tab !== 'stability' && (
        <div className="diag-filterchip">
          Router: {routerName ?? routerFilter}
          <button type="button" className="diag-link" onClick={() => onRouterFilterChange(null)}>× alle Router</button>
        </div>
      )}

      {error && <div className="diag-error">{error}</div>}
      {summary?.load_failed && (
        <div className="diag-error">Der gespeicherte Verlauf konnte nicht gelesen werden; es wird neu gesammelt.</div>
      )}

      {openId ? (
        <IncidentDetailView
          api={api}
          id={openId}
          refreshKey={refreshKey}
          onOpen={open}
          onClose={() => setOpenId(null)}
          onChanged={reload}
        />
      ) : (
        <>
          {tab === 'overview' && summary && (
            <Overview summary={summary} incidents={filtered} routerFilter={routerFilter} onOpen={open} onPickRouter={onRouterFilterChange} />
          )}
          {(tab === 'incidents' || tab === 'wifi' || tab === 'infra') && (
            <label className="diag-check">
              <input type="checkbox" checked={showResolved} onChange={e => setShowResolved(e.target.checked)} />
              Behobene anzeigen
            </label>
          )}
          {tab === 'incidents' && (
            <IncidentTree incidents={filtered} onOpen={open} empty="Keine offenen Incidents." />
          )}
          {tab === 'timeline' && (
            <Timeline
              api={api}
              summary={summary}
              refreshKey={refreshKey}
              routerFilter={routerFilter}
              onRouterFilterChange={onRouterFilterChange}
              onOpenIncident={open}
            />
          )}
          {tab === 'wifi' && summary && (
            <WifiPanel summary={summary} incidents={wifi} routerFilter={routerFilter} onOpen={open} />
          )}
          {tab === 'infra' && summary && (
            <InfraPanel summary={summary} incidents={infra} routerFilter={routerFilter} onOpen={open} />
          )}
          {tab === 'stability' && (
            <StabilityView api={api} refreshKey={refreshKey} routers={summary?.routers ?? []} onOpenIncident={open} />
          )}
          {tab === 'settings' && <IntelSettingsView api={api} onSaved={reload} />}
        </>
      )}
    </div>
  );
}

function Overview({
  summary,
  incidents,
  routerFilter,
  onOpen,
  onPickRouter,
}: {
  summary: IntelSummary;
  incidents: IntelIncident[];
  routerFilter: string | null;
  onOpen: (id: string) => void;
  onPickRouter: (id: string | null) => void;
}) {
  const f = summary.fleet;
  const routers = summary.routers.filter(r => !routerFilter || r.id === routerFilter);
  const top = incidents.filter(i => !i.child && i.status !== 'resolved').slice(0, 5);
  return (
    <>
      <div className="diag-cards">
        <div className="settings-card">
          <div className="settings-card__heading">Flotten-Score</div>
          <div className="diag-big"><ScoreValue score={f.score} /></div>
          <div className="settings-info">
            Abdeckung {Math.round(f.coverage * 100)} % · {f.routers} Router bewertet
            {f.maintenance > 0 ? ` · ${f.maintenance} in Wartung` : ''}
            {f.maintenance_until ? ` · Flotten-Wartung bis ${formatTs(f.maintenance_until)}` : ''}
          </div>
        </div>
        <div className="settings-card">
          <div className="settings-card__heading">Offene Incidents</div>
          <CountPills counts={summary.incidents} />
          <div className="settings-info">
            {summary.incidents_open_total} offen inkl. Folgeprobleme · {summary.incidents_ignored} ignoriert
          </div>
        </div>
        <div className="settings-card">
          <div className="settings-card__heading">Ereignisse 24 h</div>
          <div className="diag-kv">
            {Object.keys(summary.events_24h).length === 0 && <span className="settings-info">keine</span>}
            {Object.entries(summary.events_24h).map(([k, v]) => (
              <span key={k}>{CATEGORY_LABEL[k] ?? k}: <b>{v}</b></span>
            ))}
          </div>
          <div className="settings-info">{summary.events_stored} Ereignisse gespeichert</div>
        </div>
      </div>

      <div className="settings-card">
        <div className="settings-card__heading">Router</div>
        <div className="diag-table">
          {routers.map(r => (
            <button key={r.id} type="button" className="diag-table__row" onClick={() => onPickRouter(r.id === routerFilter ? null : r.id)}>
              <span className="diag-table__name">{r.name}</span>
              <span><ScoreValue score={r.score} /></span>
              <span className="diag-table__meta">
                {r.offline ? 'offline' : `${Math.round(r.coverage * 100)} % Daten`}
                {r.maintenance ? ' · Wartung' : ''}
                {r.log ? ` · ${logLabel(r.log)}` : ''}
              </span>
              <CountPills counts={r.incidents} />
            </button>
          ))}
        </div>
      </div>

      <div className="settings-card">
        <div className="settings-card__heading">Wichtigste offene Incidents</div>
        <IncidentTree incidents={top} onOpen={onOpen} empty="Keine offenen Incidents – alles in Ordnung." />
      </div>
    </>
  );
}

function WifiPanel({
  summary,
  incidents,
  routerFilter,
  onOpen,
}: {
  summary: IntelSummary;
  incidents: IntelIncident[];
  routerFilter: string | null;
  onOpen: (id: string) => void;
}) {
  const routers = summary.routers.filter(r => !routerFilter || r.id === routerFilter);
  const clients = summary.wifi.top_clients.filter(c => !routerFilter || c.router === routerFilter);
  return (
    <>
      <div className="settings-card">
        <div className="settings-card__heading">WLAN je Router (letzte Stunde)</div>
        <div className="diag-table">
          {routers.map(r => (
            <div key={r.id} className="diag-table__row">
              <span className="diag-table__name">{r.name}</span>
              <span><ScoreValue score={r.areas.wifi?.score ?? null} /></span>
              <span className="diag-table__meta">{r.reconnects_1h} Reconnects · {r.auth_errors_1h} Anmeldefehler</span>
            </div>
          ))}
        </div>
      </div>
      <div className="settings-card">
        <div className="settings-card__heading">Auffällige Clients (24 h)</div>
        {clients.length === 0 ? (
          <div className="settings-info">Keine WLAN-Problemereignisse.</div>
        ) : (
          <div className="diag-table">
            {clients.map(c => (
              <div key={c.mac} className="diag-table__row">
                <span className="diag-table__name diag-mono">{c.mac}</span>
                <span className="diag-table__meta">{c.router_name}</span>
                <span className="diag-table__meta">
                  {c.events} Ereignisse · {c.reconnects} Reconnects · {c.auth_errors} Anmeldefehler
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="settings-card">
        <div className="settings-card__heading">WLAN-Incidents</div>
        <IncidentTree incidents={incidents} onOpen={onOpen} empty="Keine WLAN-Incidents." />
      </div>
    </>
  );
}

function InfraPanel({
  summary,
  incidents,
  routerFilter,
  onOpen,
}: {
  summary: IntelSummary;
  incidents: IntelIncident[];
  routerFilter: string | null;
  onOpen: (id: string) => void;
}) {
  const routers = summary.routers.filter(r => !routerFilter || r.id === routerFilter);
  const areas = ['system', 'lan', 'wan', 'dhcp_dns'];
  return (
    <>
      <div className="settings-card">
        <div className="settings-card__heading">Bereiche je Router</div>
        <div className="diag-table">
          {routers.map(r => (
            <div key={r.id} className="diag-table__row diag-table__row--areas">
              <span className="diag-table__name">{r.name}</span>
              {areas.map(a => (
                <span key={a} className="diag-area" title={r.areas[a] ? `Abdeckung ${Math.round(r.areas[a].coverage * 100)} %` : 'nicht zutreffend'}>
                  {AREA_LABEL[a]} {r.areas[a] ? <ScoreValue score={r.areas[a].score} /> : '–'}
                </span>
              ))}
              <span className="diag-table__meta">{r.wan_reconnects_24h} WAN-Reconnects 24 h</span>
            </div>
          ))}
        </div>
      </div>
      <div className="settings-card">
        <div className="settings-card__heading">Infrastruktur-Incidents</div>
        <IncidentTree incidents={incidents} onOpen={onOpen} empty="Keine Infrastruktur-Incidents." />
      </div>
    </>
  );
}
