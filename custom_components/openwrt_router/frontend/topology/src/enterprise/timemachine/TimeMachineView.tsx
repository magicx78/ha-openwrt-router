/**
 * TimeMachineView — Enterprise sub-tab "Zeitreise" (Network Time Machine,
 * read only).
 *
 * Two views, switched in the tab (state kept here, no router or URL change):
 *
 * - "Zeitleiste": one timeline of the marks of every source (audit,
 *   configuration versions, Network Intelligence, Security Center, and since
 *   1.51.0 the Time Machine's own history, its references and the client
 *   histories), newest first, grouped by local calendar day. Intervals that
 *   began before the window and still reach into it stand in a block of their
 *   own at the top ("Läuft seit vor dem Zeitfenster").
 * - "Client-Sitzungen" (administrators only, 1.51.0): the client sessions of
 *   GET …/sessions, newest start first, grouped by day.
 *
 * Both containers stay mounted once opened (their lists survive a switch) but
 * only the visible one loads and polls: when opened, on "Aktualisieren", on a
 * filter change, and then at most every 60 s while the page is visible. Older
 * pages are loaded on request and kept; a newer answer never loses to a stale
 * one, and a list that cannot be joined without a gap starts anew and says so
 * (listReducer, sessionReducer).
 *
 * Everything the server sends is rendered as React text, never as HTML. The
 * tab never builds a MAC, IP address, hostname or interface name; a client is
 * shown by the name the server sends or by the pseudonym's last six
 * characters.
 */

import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import configCSS from '../config/config.css?inline';
import wifiCSS from '../wifi/wifi.css?inline';
import tmCSS from './timemachine.css?inline';
import {
  CLIENTS_OFF_HOW, CLIENTS_OFF_TITLE, CLIENTS_PRIVACY, CUT_TEXT, DEFAULT_FILTERS, DEFAULT_SESSION_FILTERS, EMPTY_TEXT,
  HIDDEN_ONLY_TEXT, INTRO, LIST_INIT, LOADING_TEXT, NO_SOURCE_TEXT, OFF_HOW, OFF_TITLE, PARTIAL_TEXT, POLL_MIN_MS,
  RECORDING_OFF, RECORDING_ON, RESTART_TEXT, SESSIONS_CUT_TEXT, SESSIONS_EMPTY_TEXT, SESSIONS_LOADING_TEXT,
  SESSIONS_VIEW_TITLE, SESSION_LIST_INIT, SEVERITY_FILTERS, SOURCES_NEWEST, SOURCES_TITLE, SOURCE_IDS, SPANS_TITLE,
  TAB_TITLE, TIMELINE_VIEW_TITLE, WINDOWS,
  adminOnlySources, bandText, clientLabel, clientOptions, clientsOff, countText, dayGroups, detailText, errorInfo,
  filterKey, firstQuery, firstSessionQuery, groupText, groupsOf, isoUtc, listReducer, olderQuery, olderSessionQuery,
  omittedText, rememberClients, rememberRouters, rememberSessionRouters, roamText, routerOptionLabel, routerOptions,
  routerText, sessionDays, sessionDurationText, sessionFilterKey, sessionReducer, severityView, shouldPoll,
  shouldPollSessions, sourcePill, sourceText, splitSpans, standText, startText, timeText, titleOf, unavailableText,
  visibleMarks,
  type ClientNames, type ListState, type RouterNames, type SessionListState,
} from './tmLogic.ts';
import type { Filters, Mark, Session, SessionFilters, SessionQuery, TimelineQuery, TmApi } from './tmTypes';

const CHECK_MS = Math.min(15_000, POLL_MIN_MS);

export type TmView = 'timeline' | 'sessions';

function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

// ── Pieces ───────────────────────────────────────────────────────────────

function ErrorBox({ error, onRetry, of = 'timeline' }: { error: unknown; onRetry?: () => void; of?: 'timeline' | 'sessions' }) {
  const info = errorInfo(error, of);
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

function Spinner({ text }: { text: string }) {
  return <div className="cfg-spinner tm-loading" aria-busy="true"><span className="cfg-spinner__dot" />{text}</div>;
}

function OffBox() {
  return (
    <div className="cfg-notice cfg-notice--info tm-off" role="status">
      <strong>{OFF_TITLE}</strong>
      <span>{OFF_HOW}</span>
    </div>
  );
}

function RestartNotice({ onDismiss }: { onDismiss: () => void }) {
  return (
    <div className="cfg-notice cfg-notice--info tm-restart" role="status">
      <span>{RESTART_TEXT}</span>
      <button type="button" className="diag-btn cfg-btn" onClick={onDismiss}>Ausblenden</button>
    </div>
  );
}

/** "Zeitleiste | Client-Sitzungen" (administrators only). */
export function ViewSwitch({ view, onView }: { view: TmView; onView: (v: TmView) => void }) {
  return (
    <div className="tm-chips tm-views" role="group" aria-label="Ansicht">
      <Chip on={view === 'timeline'} onClick={() => onView('timeline')}>{TIMELINE_VIEW_TITLE}</Chip>
      <Chip on={view === 'sessions'} onClick={() => onView('sessions')}>{SESSIONS_VIEW_TITLE}</Chip>
    </div>
  );
}

function Frame({ loading, onRefresh, viewSwitch, generatedAt, children }: {
  loading: boolean; onRefresh: () => void; viewSwitch?: React.ReactNode; generatedAt: number | null | undefined;
  children: React.ReactNode;
}) {
  return (
    <div className="cfg wifi tm">
      <style>{configCSS}</style>
      <style>{wifiCSS}</style>
      <style>{tmCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={loading} onClick={onRefresh}>
          Aktualisieren
        </button>
      </div>
      {viewSwitch}
      <div className="cfg-hint">{INTRO}</div>
      {generatedAt !== undefined && generatedAt !== null && <div className="cfg-hint tm-stand">{standText(generatedAt)}</div>}
      {children}
    </div>
  );
}

function SourceRow({ state }: { state: ListState }) {
  const sources = state.head?.sources ?? [];
  if (!sources.length) return null;
  return (
    <div className="tm-sources-box">
      <h3 className="cfg-subtitle tm-sources__title">
        {SOURCES_TITLE}{state.older && <span className="tm-sources__newest"> {SOURCES_NEWEST}</span>}
      </h3>
      <ul className="tm-sources" aria-label="Quellen">
        {sources.map(s => {
          const p = sourcePill(s);
          return (
            <li key={s.id} className={`cfg-badge cfg-badge--${p.tone} tm-pill`} title={p.title}>
              <span className="tm-pill__name">{p.name}</span>: {p.text}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function MarkRow({ m, nowMs, start = false }: { m: Mark; nowMs: number; start?: boolean }) {
  const sev = severityView(m.severity);
  const detail = detailText(m, nowMs);
  const iso = isoUtc(m.ts);
  return (
    <li className="tm-mark" data-source={m.source}>
      <time className="tm-mark__time" dateTime={iso} title={iso}>{start ? startText(m.ts) : timeText(m.ts)}</time>
      <span className={`tm-mark__sev tm-sev tm-sev--${sev.tone}`}>
        <span className="tm-sev__dot" aria-hidden="true" />{sev.label}
      </span>
      <span className="tm-mark__group">
        <span className="cfg-badge cfg-badge--muted">{groupText(m.group)}</span>
        {m.derived && <span className="cfg-badge cfg-badge--info">abgeleitet</span>}
      </span>
      <span className="tm-mark__main">
        <span className="tm-mark__title">{titleOf(m)}</span>
        {detail && <span className="tm-mark__params">{detail}</span>}
      </span>
      <span className="tm-mark__router">{routerText(m)}</span>
      <span className="tm-mark__source">{sourceText(m.source)}</span>
    </li>
  );
}

function WindowChips({ value, onChange }: { value: string; onChange: (id: string) => void }) {
  return (
    <div className="tm-filter">
      <span className="tm-filter__name">Zeitfenster</span>
      <div className="tm-chips">
        {WINDOWS.map(w => <Chip key={w.id} on={value === w.id} onClick={() => onChange(w.id)}>{w.label}</Chip>)}
      </div>
    </div>
  );
}

function RouterSelect({ value, routers, onChange }: { value: string | null; routers: RouterNames; onChange: (id: string | null) => void }) {
  const options = routerOptions(routers);
  if (value && !options.some(o => o.value === value)) options.push({ value, label: routerOptionLabel(value, null) });
  return (
    <label className="tm-filter tm-field">
      <span className="tm-filter__name">Router</span>
      <select value={value ?? ''} onChange={e => onChange(e.target.value || null)}>
        <option value="">Alle Router</option>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
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
  const toggleSource = (id: string) => {
    const off = filters.sourcesOff.includes(id) ? filters.sourcesOff.filter(s => s !== id) : [...filters.sourcesOff, id];
    onFilters({ ...filters, sourcesOff: off });
  };
  return (
    <div className="tm-filters" role="group" aria-label="Filter der Zeitleiste">
      <WindowChips value={filters.window} onChange={window => onFilters({ ...filters, window })} />
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
      <RouterSelect value={filters.routerId} routers={routers} onChange={routerId => onFilters({ ...filters, routerId })} />
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

// ── Timeline screen (pure: everything from props) ────────────────────────

export interface ScreenProps {
  state: ListState;
  filters: Filters;
  hidden: readonly string[];
  routers: RouterNames;
  nowMs: number;
  viewSwitch?: React.ReactNode;
  onFilters: (f: Filters) => void;
  onToggleGroup: (group: string) => void;
  onRefresh: () => void;
  onMore: () => void;
  onDismiss?: () => void;
}

export function TimeMachineScreen({ state, filters, hidden, routers, nowMs, viewSwitch, onFilters, onToggleGroup, onRefresh, onMore, onDismiss }: ScreenProps) {
  const head = state.head;
  const off = head?.status === 'off';
  const adminOnly = adminOnlySources(head);
  const noSource = !off && firstQuery(filters, nowMs, adminOnly) === null;
  const groups = [...groupsOf(state.marks), ...hidden.filter(g => !state.marks.some(m => m.group === g))];
  const shown = visibleMarks(state.marks, hidden);
  const omitted = head && !off ? omittedText(head.omittedClientMarks, clientsOff(head)) : null;
  const firstLoad = head === null || (state.loading && !state.marks.length && !off);
  // a page without marks that goes on: only left-out entries in this part (review S1)
  const hiddenOnly = !state.marks.length && state.nextUntil !== null;

  const body = (() => {
    if (head === null) {
      if (state.error !== null) return <ErrorBox error={state.error} onRetry={onRefresh} />;
      return <Spinner text={LOADING_TEXT} />;
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
        {state.restarted && <RestartNotice onDismiss={onDismiss ?? (() => {})} />}
        {head.status === 'partial' && <div className="cfg-notice cfg-notice--warn" role="note">{PARTIAL_TEXT}</div>}
        <SourceRow state={state} />
        {omitted && <div className="cfg-hint tm-omitted" role="note">{omitted}</div>}
        {noSource && <div className="cfg-hint" role="note">{NO_SOURCE_TEXT}</div>}
        {state.loading && state.marks.length > 0 && !noSource && <Spinner text={LOADING_TEXT} />}
        {noSource ? null : firstLoad
          ? <Spinner text={LOADING_TEXT} />
          : hiddenOnly
            ? <div className="cfg-empty tm-empty tm-hidden-only">{HIDDEN_ONLY_TEXT}</div>
            : <TimelineList marks={shown} total={state.marks.length} from={head.from} nowMs={nowMs} />}
        {state.moreError !== null && <ErrorBox error={state.moreError} onRetry={onMore} />}
        {!noSource && !firstLoad && state.nextUntil !== null && (
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
    <Frame loading={state.loading} onRefresh={onRefresh} viewSwitch={viewSwitch} generatedAt={head?.generatedAt}>
      {body}
    </Frame>
  );
}

function TimelineList({ marks, total, from, nowMs }: { marks: readonly Mark[]; total: number; from: number | null; nowMs: number }) {
  if (!marks.length) {
    return <div className="cfg-empty tm-empty">{total ? 'Keine Marken der gewählten Arten.' : EMPTY_TEXT}</div>;
  }
  const { spans, rest } = splitSpans(marks, from);
  return (
    <div className="tm-list">
      {spans.length > 0 && (
        <section className="tm-day tm-spans" aria-label={SPANS_TITLE}>
          <h3 className="cfg-subtitle tm-day__title">{SPANS_TITLE}</h3>
          <ol className="tm-rows">
            {spans.map(m => <MarkRow key={m.id} m={m} nowMs={nowMs} start />)}
          </ol>
        </section>
      )}
      {dayGroups(rest, nowMs).map(day => (
        <section key={day.key} className="tm-day" aria-label={day.label}>
          <h3 className="cfg-subtitle tm-day__title">{day.label}</h3>
          <ol className="tm-rows">
            {day.marks.map(m => <MarkRow key={m.id} m={m} nowMs={nowMs} />)}
          </ol>
        </section>
      ))}
    </div>
  );
}

// ── Sessions screen (pure: everything from props) ────────────────────────

function SessionRow({ x }: { x: Session }) {
  const iso = isoUtc(x.ts);
  const band = bandText(x.band);
  const roam = roamText(x.params);
  return (
    <li className="tm-session" data-end={x.endState ?? 'none'}>
      <time className="tm-session__time" dateTime={iso} title={iso}>{timeText(x.ts)}</time>
      <span className="tm-session__dur">{sessionDurationText(x)}</span>
      <span className="tm-session__client">
        {clientLabel(x.client, x.clientName)}
        {x.derived && <span className="cfg-badge cfg-badge--info">abgeleitet</span>}
      </span>
      <span className="tm-session__router">{routerText({ fleet: false, routerId: x.routerId, routerName: x.routerName })}</span>
      <span className="tm-session__band">{band ?? 'Band unbekannt'}</span>
      <span className="tm-session__roam">{roam ?? ''}</span>
    </li>
  );
}

export interface SessionsScreenProps {
  state: SessionListState;
  filters: SessionFilters;
  routers: RouterNames;
  clients: ClientNames;
  nowMs: number;
  viewSwitch?: React.ReactNode;
  onFilters: (f: SessionFilters) => void;
  onRefresh: () => void;
  onMore: () => void;
  onDismiss?: () => void;
}

export function SessionsScreen({ state, filters, routers, clients, nowMs, viewSwitch, onFilters, onRefresh, onMore, onDismiss }: SessionsScreenProps) {
  const head = state.head;
  const options = clientOptions(clients);
  if (filters.client && !options.some(o => o.value === filters.client)) {
    options.push({ value: filters.client, label: clientLabel(filters.client, null) });
  }
  const firstLoad = head === null || (state.loading && !state.sessions.length && head.status === 'ok');

  const body = (() => {
    if (head === null) {
      if (state.error !== null) return <ErrorBox of="sessions" error={state.error} onRetry={onRefresh} />;
      return <Spinner text={SESSIONS_LOADING_TEXT} />;
    }
    const error = state.error !== null && <ErrorBox of="sessions" error={state.error} onRetry={onRefresh} />;
    if (head.status === 'off') return <>{error}<OffBox /></>;
    if (head.status === 'clients_off') {
      return (
        <>
          {error}
          <div className="cfg-notice cfg-notice--info tm-off tm-clients-off" role="status">
            <strong>{CLIENTS_OFF_TITLE}</strong>
            <span>{CLIENTS_OFF_HOW}</span>
            <span>{CLIENTS_PRIVACY}</span>
          </div>
        </>
      );
    }
    if (head.status !== 'ok') {
      return (
        <>
          {error}
          <div className="cfg-notice cfg-notice--warn tm-unavailable" role="status">{unavailableText(head.reason)}</div>
        </>
      );
    }
    return (
      <>
        <div className="tm-filters" role="group" aria-label="Filter der Client-Sitzungen">
          <WindowChips value={filters.window} onChange={window => onFilters({ ...filters, window })} />
          <RouterSelect value={filters.routerId} routers={routers} onChange={routerId => onFilters({ ...filters, routerId })} />
          <label className="tm-filter tm-field">
            <span className="tm-filter__name">Client</span>
            <select value={filters.client ?? ''} onChange={e => onFilters({ ...filters, client: e.target.value || null })}>
              <option value="">Alle Clients</option>
              {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </label>
        </div>
        {error}
        {state.restarted && <RestartNotice onDismiss={onDismiss ?? (() => {})} />}
        <div className="cfg-hint tm-recording" role="note">{head.recording ? RECORDING_ON : RECORDING_OFF}</div>
        {state.loading && state.sessions.length > 0 && <Spinner text={SESSIONS_LOADING_TEXT} />}
        {firstLoad
          ? <Spinner text={SESSIONS_LOADING_TEXT} />
          : !state.sessions.length
            ? <div className="cfg-empty tm-empty">{SESSIONS_EMPTY_TEXT}</div>
            : (
              <div className="tm-sessions">
                {sessionDays(state.sessions, nowMs).map(day => (
                  <section key={day.key} className="tm-day" aria-label={day.label}>
                    <h3 className="cfg-subtitle tm-day__title">{day.label}</h3>
                    <ol className="tm-rows">{day.sessions.map(x => <SessionRow key={x.id} x={x} />)}</ol>
                  </section>
                ))}
              </div>
            )}
        {state.moreError !== null && <ErrorBox of="sessions" error={state.moreError} onRetry={onMore} />}
        {!firstLoad && state.nextUntil !== null && (
          <div className="tm-more">
            <button type="button" className="diag-btn cfg-btn" disabled={state.loadingMore} onClick={onMore}>Ältere laden</button>
            {state.loadingMore && <span className="cfg-spinner"><span className="cfg-spinner__dot" />lädt …</span>}
          </div>
        )}
        {state.nextUntil === null && state.truncated && <div className="cfg-hint tm-cut" role="note">{SESSIONS_CUT_TEXT}</div>}
      </>
    );
  })();

  return (
    <Frame loading={state.loading} onRefresh={onRefresh} viewSwitch={viewSwitch} generatedAt={head?.generatedAt}>
      {body}
    </Frame>
  );
}

// ── Containers (state, fetching, polling) ────────────────────────────────

/** The timeline: loads and polls only while `active` (its view is shown). */
export function TimelineContainer({ api, active, viewSwitch }: { api: TmApi; active: boolean; viewSwitch?: React.ReactNode }) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [hidden, setHidden] = useState<string[]>([]);
  const [routers, setRouters] = useState<RouterNames>({});
  const [state, dispatch] = useReducer(listReducer, LIST_INIT);
  const stateRef = useRef(state);
  stateRef.current = state;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const activeRef = useRef(active);
  activeRef.current = active;
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
  // page or view waits until it is visible again.
  useEffect(() => {
    if (!activeRef.current || !pageVisible()) {
      lastMs.current = null;
      return;
    }
    loadFirst();
  }, [state.gen, loadFirst]);

  // At most every 60 s while visible, shown and on (shouldPoll); nothing while off.
  useEffect(() => {
    const check = () => {
      if (!activeRef.current) return;
      if (shouldPoll({ visible: pageVisible(), lastMs: lastMs.current, nowMs: Date.now(), off: stateRef.current.head?.status === 'off' })) {
        loadFirst();
      }
    };
    if (active) check();
    const id = setInterval(check, CHECK_MS);
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [loadFirst, active]);

  useEffect(() => {
    setRouters(prev => rememberRouters(prev, state.marks));
  }, [state.marks]);

  const toggleGroup = useCallback((g: string) => {
    setHidden(h => (h.includes(g) ? h.filter(x => x !== g) : [...h, g]));
  }, []);
  const dismiss = useCallback(() => dispatch({ type: 'dismiss' }), []);

  if (!active) return null;
  return (
    <TimeMachineScreen state={state} filters={filters} hidden={hidden} routers={routers} nowMs={Date.now()} viewSwitch={viewSwitch}
      onFilters={setFilters} onToggleGroup={toggleGroup} onRefresh={loadFirst} onMore={loadMore} onDismiss={dismiss} />
  );
}

/** The client sessions: loads and polls only while `active`. */
export function SessionsContainer({ api, active, viewSwitch }: { api: TmApi; active: boolean; viewSwitch?: React.ReactNode }) {
  const [filters, setFilters] = useState<SessionFilters>(DEFAULT_SESSION_FILTERS);
  const [routers, setRouters] = useState<RouterNames>({});
  const [clients, setClients] = useState<ClientNames>({});
  const [state, dispatch] = useReducer(sessionReducer, SESSION_LIST_INIT);
  const stateRef = useRef(state);
  stateRef.current = state;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const activeRef = useRef(active);
  activeRef.current = active;
  const seq = useRef(0);
  const lastMs = useRef<number | null>(null);
  const firstQ = useRef<SessionQuery | null>(null);

  const loadFirst = useCallback(() => {
    const s = stateRef.current;
    const q = firstSessionQuery(filtersRef.current, Date.now());
    const n = ++seq.current;
    const gen = s.gen;
    firstQ.current = q;
    lastMs.current = Date.now();
    dispatch({ type: 'start', seq: n, more: false });
    api.sessions(q).then(
      answer => dispatch({ type: 'first', gen, seq: n, answer }),
      error => dispatch({ type: 'fail', gen, seq: n, more: false, error }),
    );
  }, [api]);

  const loadMore = useCallback(() => {
    const s = stateRef.current;
    const base = firstQ.current;
    if (base === null || s.nextUntil === null) return;
    const q = olderSessionQuery(base, s.head?.from ?? null, s.nextUntil);
    const n = ++seq.current;
    const gen = s.gen;
    dispatch({ type: 'start', seq: n, more: true });
    api.sessions(q).then(
      answer => dispatch({ type: 'older', gen, seq: n, answer }),
      error => dispatch({ type: 'fail', gen, seq: n, more: true, error }),
    );
  }, [api]);

  const key = sessionFilterKey(filters);
  const mounted = useRef(false);
  useEffect(() => {
    if (mounted.current) dispatch({ type: 'filters' });
    mounted.current = true;
  }, [key]);

  useEffect(() => {
    if (!activeRef.current || !pageVisible()) {
      lastMs.current = null;
      return;
    }
    loadFirst();
  }, [state.gen, loadFirst]);

  // At most every 60 s while visible and shown; nothing while off or clients_off.
  useEffect(() => {
    const check = () => {
      if (!activeRef.current) return;
      if (shouldPollSessions({ visible: pageVisible(), lastMs: lastMs.current, nowMs: Date.now(), status: stateRef.current.head?.status ?? null })) {
        loadFirst();
      }
    };
    if (active) check();
    const id = setInterval(check, CHECK_MS);
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [loadFirst, active]);

  useEffect(() => {
    setRouters(prev => rememberSessionRouters(prev, state.sessions));
    setClients(prev => rememberClients(prev, state.sessions));
  }, [state.sessions]);

  const dismiss = useCallback(() => dispatch({ type: 'dismiss' }), []);

  if (!active) return null;
  return (
    <SessionsScreen state={state} filters={filters} routers={routers} clients={clients} nowMs={Date.now()} viewSwitch={viewSwitch}
      onFilters={setFilters} onRefresh={loadFirst} onMore={loadMore} onDismiss={dismiss} />
  );
}

/**
 * The tab. The view switch is offered to administrators only (the panel's
 * hass user); the sessions route answers 403 to everyone else anyway. The
 * sessions container is mounted the first time its view is chosen.
 */
export function TimeMachineView({ api, isAdmin = false }: { api: TmApi; isAdmin?: boolean }) {
  const [view, setView] = useState<TmView>('timeline');
  const [sessionsOpened, setSessionsOpened] = useState(false);
  const choose = useCallback((v: TmView) => {
    if (v === 'sessions') setSessionsOpened(true);
    setView(v);
  }, []);
  const shown: TmView = isAdmin ? view : 'timeline';
  const viewSwitch = isAdmin ? <ViewSwitch view={shown} onView={choose} /> : undefined;
  return (
    <>
      <TimelineContainer api={api} active={shown === 'timeline'} viewSwitch={viewSwitch} />
      {isAdmin && sessionsOpened && <SessionsContainer api={api} active={shown === 'sessions'} viewSwitch={viewSwitch} />}
    </>
  );
}
