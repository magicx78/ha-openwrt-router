/**
 * TimeMachineView — Enterprise sub-tab "Zeitreise" (Network Time Machine,
 * Phase A, read only).
 *
 * One timeline of the marks of every source (audit, configuration versions,
 * Network Intelligence events and incidents, Security Center), newest first,
 * grouped by local calendar day. The component is mounted only while its tab
 * is shown. It loads the first page when opened, on "Aktualisieren", on a
 * change of window, source, severity or router, and then at most every 60 s
 * while the page is visible and the Time Machine is on. Older pages are
 * loaded on request and kept; a newer answer never loses to a stale one
 * (listReducer). The group chips only filter what is loaded.
 *
 * Everything the server sends is rendered as React text, never as HTML.
 */

import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import configCSS from '../config/config.css?inline';
import wifiCSS from '../wifi/wifi.css?inline';
import tmCSS from './timemachine.css?inline';
import {
  CUT_TEXT, DEFAULT_FILTERS, EMPTY_TEXT, INTRO, LIST_INIT, LOADING_TEXT, NO_SOURCE_TEXT, OFF_HOW, OFF_TITLE, PARTIAL_TEXT,
  POLL_MIN_MS, SEVERITY_FILTERS, SOURCE_IDS, TAB_TITLE, WINDOWS,
  adminOnlySources, countText, dayGroups, errorInfo, filterKey, firstQuery, groupText, groupsOf, isoUtc, listReducer,
  olderQuery, omittedText, paramsText, rememberRouters, routerOptionLabel, routerOptions, routerText, severityView,
  shouldPoll, sourcePill, sourceText, standText, timeText, titleOf, visibleMarks,
  type ListState, type RouterNames,
} from './tmLogic.ts';
import type { Filters, Mark, TimelineQuery, TmApi } from './tmTypes';

const CHECK_MS = Math.min(15_000, POLL_MIN_MS);

function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

// ── Pieces ───────────────────────────────────────────────────────────────

function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const info = errorInfo(error);
  return (
    <div className={`cfg-notice cfg-notice--${info.kind === 'failed' ? 'warn' : 'error'}`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && (
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      )}
    </div>
  );
}

function Chip({ on, disabled, onClick, children, title }: {
  on: boolean; disabled?: boolean; onClick: () => void; children: React.ReactNode; title?: string;
}) {
  return (
    <button type="button" className={`wifi-nav__btn tm-chip${on ? ' active' : ''}`} aria-pressed={on}
      disabled={disabled} title={title} onClick={onClick}>
      {children}
    </button>
  );
}

function OffBox() {
  return (
    <div className="cfg-notice cfg-notice--info tm-off" role="status">
      <strong>{OFF_TITLE}</strong>
      <span>{OFF_HOW}</span>
    </div>
  );
}

function SourceRow({ state }: { state: ListState }) {
  const sources = state.head?.sources ?? [];
  if (!sources.length) return null;
  return (
    <ul className="tm-sources" aria-label="Quellen">
      {sources.map(s => {
        const p = sourcePill(s);
        return (
          <li key={s.id} className={`cfg-badge cfg-badge--${p.tone} tm-pill`}>
            <span className="tm-pill__name">{p.name}</span>: {p.text}
          </li>
        );
      })}
    </ul>
  );
}

function MarkRow({ m }: { m: Mark }) {
  const sev = severityView(m.severity);
  const params = paramsText(m.params);
  const iso = isoUtc(m.ts);
  return (
    <li className="tm-mark" data-source={m.source}>
      <time className="tm-mark__time" dateTime={iso} title={iso}>{timeText(m.ts)}</time>
      <span className={`tm-mark__sev tm-sev tm-sev--${sev.tone}`}>
        <span className="tm-sev__dot" aria-hidden="true" />{sev.label}
      </span>
      <span className="tm-mark__group">
        <span className="cfg-badge cfg-badge--muted">{groupText(m.group)}</span>
        {m.derived && <span className="cfg-badge cfg-badge--info">abgeleitet</span>}
      </span>
      <span className="tm-mark__main">
        <span className="tm-mark__title">{titleOf(m)}</span>
        {params && <span className="tm-mark__params">{params}</span>}
      </span>
      <span className="tm-mark__router">{routerText(m)}</span>
      <span className="tm-mark__source">{sourceText(m.source)}</span>
    </li>
  );
}

export interface FilterBarProps {
  filters: Filters;
  adminOnly: readonly string[];
  routers: RouterNames;
  groups: readonly string[];
  hidden: readonly string[];
  shown: number;
  total: number;
  onFilters: (f: Filters) => void;
  onToggleGroup: (group: string) => void;
}

export function FilterBar({ filters, adminOnly, routers, groups, hidden, shown, total, onFilters, onToggleGroup }: FilterBarProps) {
  const options = routerOptions(routers);
  if (filters.routerId && !options.some(o => o.value === filters.routerId)) {
    options.push({ value: filters.routerId, label: routerOptionLabel(filters.routerId, null) });
  }
  const toggleSource = (id: string) => {
    const off = filters.sourcesOff.includes(id) ? filters.sourcesOff.filter(s => s !== id) : [...filters.sourcesOff, id];
    onFilters({ ...filters, sourcesOff: off });
  };
  return (
    <div className="tm-filters" role="group" aria-label="Filter der Zeitleiste">
      <div className="tm-filter">
        <span className="tm-filter__name">Zeitfenster</span>
        <div className="tm-chips">
          {WINDOWS.map(w => (
            <Chip key={w.id} on={filters.window === w.id} onClick={() => onFilters({ ...filters, window: w.id })}>{w.label}</Chip>
          ))}
        </div>
      </div>
      <div className="tm-filter">
        <span className="tm-filter__name">Quelle</span>
        <div className="tm-chips">
          {SOURCE_IDS.map(id => {
            const locked = adminOnly.includes(id);
            return (
              <Chip key={id} on={!locked && !filters.sourcesOff.includes(id)} disabled={locked} onClick={() => toggleSource(id)}>
                {sourceText(id)}{locked && <span className="tm-chip__note"> · nur für Administratoren</span>}
              </Chip>
            );
          })}
        </div>
      </div>
      <div className="tm-filter">
        <span className="tm-filter__name">Schwere</span>
        <div className="tm-chips">
          {SEVERITY_FILTERS.map(s => (
            <Chip key={s.id} on={filters.severity === s.id} onClick={() => onFilters({ ...filters, severity: s.id })}>{s.label}</Chip>
          ))}
        </div>
      </div>
      <label className="tm-filter tm-field">
        <span className="tm-filter__name">Router</span>
        <select value={filters.routerId ?? ''} onChange={e => onFilters({ ...filters, routerId: e.target.value || null })}>
          <option value="">Alle Router</option>
          {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </label>
      {groups.length > 0 && (
        <div className="tm-filter">
          <span className="tm-filter__name">Art</span>
          <div className="tm-chips">
            {groups.map(g => (
              <Chip key={g} on={!hidden.includes(g)} onClick={() => onToggleGroup(g)}>{groupText(g)}</Chip>
            ))}
          </div>
          <span className="tm-count" aria-live="polite">{countText(shown, total)}</span>
        </div>
      )}
    </div>
  );
}

// ── Screen (pure: everything from props) ─────────────────────────────────

export interface ScreenProps {
  state: ListState;
  filters: Filters;
  hidden: readonly string[];
  routers: RouterNames;
  nowMs: number;
  onFilters: (f: Filters) => void;
  onToggleGroup: (group: string) => void;
  onRefresh: () => void;
  onMore: () => void;
}

export function TimeMachineScreen({ state, filters, hidden, routers, nowMs, onFilters, onToggleGroup, onRefresh, onMore }: ScreenProps) {
  const head = state.head;
  const off = head?.status === 'off';
  const adminOnly = adminOnlySources(head);
  const noSource = !off && firstQuery(filters, nowMs, adminOnly) === null;
  const groups = [...groupsOf(state.marks), ...hidden.filter(g => !state.marks.some(m => m.group === g))];
  const shown = visibleMarks(state.marks, hidden);
  const omitted = head && !off ? omittedText(head.omittedClientMarks) : null;
  const firstLoad = head === null || (state.loading && !state.marks.length && !off);

  const body = (() => {
    if (head === null) {
      if (state.error !== null) return <ErrorBox error={state.error} onRetry={onRefresh} />;
      return <div className="cfg-spinner tm-loading" aria-busy="true"><span className="cfg-spinner__dot" />{LOADING_TEXT}</div>;
    }
    if (off) {
      return (
        <>
          {state.error !== null && <ErrorBox error={state.error} onRetry={onRefresh} />}
          <OffBox />
        </>
      );
    }
    return (
      <>
        <FilterBar filters={filters} adminOnly={adminOnly} routers={routers} groups={groups} hidden={hidden}
          shown={shown.length} total={state.marks.length} onFilters={onFilters} onToggleGroup={onToggleGroup} />
        {state.error !== null && <ErrorBox error={state.error} onRetry={onRefresh} />}
        {head.status === 'partial' && <div className="cfg-notice cfg-notice--warn" role="note">{PARTIAL_TEXT}</div>}
        <SourceRow state={state} />
        {omitted && <div className="cfg-hint tm-omitted" role="note">{omitted}</div>}
        {noSource && <div className="cfg-hint" role="note">{NO_SOURCE_TEXT}</div>}
        {state.loading && state.marks.length > 0 && !noSource && (
          <div className="cfg-spinner tm-loading" aria-busy="true"><span className="cfg-spinner__dot" />{LOADING_TEXT}</div>
        )}
        {noSource ? null : firstLoad
          ? <div className="cfg-spinner tm-loading" aria-busy="true"><span className="cfg-spinner__dot" />{LOADING_TEXT}</div>
          : <TimelineList marks={shown} total={state.marks.length} nowMs={nowMs} />}
        {state.moreError !== null && <ErrorBox error={state.moreError} onRetry={onMore} />}
        {!noSource && state.nextUntil !== null && state.marks.length > 0 && (
          <div className="tm-more">
            <button type="button" className="diag-btn cfg-btn" disabled={state.loadingMore} onClick={onMore}>Ältere laden</button>
            {state.loadingMore && <span className="cfg-spinner"><span className="cfg-spinner__dot" />lädt …</span>}
          </div>
        )}
        {!noSource && state.nextUntil === null && state.truncated && <div className="cfg-hint tm-cut" role="note">{CUT_TEXT}</div>}
      </>
    );
  })();

  return (
    <div className="cfg wifi tm">
      <style>{configCSS}</style>
      <style>{wifiCSS}</style>
      <style>{tmCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={state.loading} onClick={onRefresh}>
          Aktualisieren
        </button>
      </div>
      <div className="cfg-hint">{INTRO}</div>
      {head && <div className="cfg-hint tm-stand">{standText(head.generatedAt)}</div>}
      {body}
    </div>
  );
}

function TimelineList({ marks, total, nowMs }: { marks: readonly Mark[]; total: number; nowMs: number }) {
  if (!marks.length) {
    return <div className="cfg-empty tm-empty">{total ? 'Keine Marken der gewählten Arten.' : EMPTY_TEXT}</div>;
  }
  return (
    <div className="tm-list">
      {dayGroups(marks, nowMs).map(day => (
        <section key={day.key} className="tm-day" aria-label={day.label}>
          <h3 className="cfg-subtitle tm-day__title">{day.label}</h3>
          <ol className="tm-rows">
            {day.marks.map(m => <MarkRow key={m.id} m={m} />)}
          </ol>
        </section>
      ))}
    </div>
  );
}

// ── Container (state, fetching, polling) ─────────────────────────────────

export function TimeMachineView({ api }: { api: TmApi }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [hidden, setHidden] = useState<string[]>([]);
  const [routers, setRouters] = useState<RouterNames>({});
  const [state, dispatch] = useReducer(listReducer, LIST_INIT);
  const stateRef = useRef(state);
  stateRef.current = state;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const seq = useRef(0);
  const lastMs = useRef<number | null>(null);
  const firstQ = useRef<TimelineQuery | null>(null);

  const loadFirst = useCallback(() => {
    const s = stateRef.current;
    const q = firstQuery(filtersRef.current, Date.now(), adminOnlySources(s.head));
    if (q === null) return;
    const n = ++seq.current;
    const gen = s.gen;
    firstQ.current = q;
    lastMs.current = Date.now();
    dispatch({ type: 'start', seq: n, more: false });
    api.timeline(q).then(
      answer => dispatch({ type: 'first', gen, seq: n, answer }),
      error => dispatch({ type: 'fail', gen, seq: n, more: false, error }),
    );
  }, [api]);

  const loadMore = useCallback(() => {
    const s = stateRef.current;
    const base = firstQ.current;
    if (base === null || s.nextUntil === null) return;
    const q = olderQuery(base, s.head?.from ?? null, s.nextUntil);
    const n = ++seq.current;
    const gen = s.gen;
    dispatch({ type: 'start', seq: n, more: true });
    api.timeline(q).then(
      answer => dispatch({ type: 'older', gen, seq: n, answer }),
      error => dispatch({ type: 'fail', gen, seq: n, more: true, error }),
    );
  }, [api]);

  // A change of what the server is asked starts a new list (stale answers dropped).
  const key = filterKey(filters);
  const mounted = useRef(false);
  useEffect(() => {
    if (mounted.current) dispatch({ type: 'filters' });
    mounted.current = true;
  }, [key]);

  // Load the first page when opened and after every filter change; a hidden
  // page waits until it is visible again.
  useEffect(() => {
    if (!pageVisible()) {
      lastMs.current = null;
      return;
    }
    loadFirst();
  }, [state.gen, loadFirst]);

  // At most every 60 s while visible and on (shouldPoll); nothing while off.
  useEffect(() => {
    const check = () => {
      if (shouldPoll({ visible: pageVisible(), lastMs: lastMs.current, nowMs: Date.now(), off: stateRef.current.head?.status === 'off' })) {
        loadFirst();
      }
    };
    const id = setInterval(check, CHECK_MS);
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [loadFirst]);

  useEffect(() => {
    setRouters(prev => rememberRouters(prev, state.marks));
  }, [state.marks]);

  const toggleGroup = useCallback((g: string) => {
    setHidden(h => (h.includes(g) ? h.filter(x => x !== g) : [...h, g]));
  }, []);

  return (
    <TimeMachineScreen state={state} filters={filters} hidden={hidden} routers={routers} nowMs={Date.now()}
      onFilters={setFilters} onToggleGroup={toggleGroup} onRefresh={loadFirst} onMore={loadMore} />
  );
}
