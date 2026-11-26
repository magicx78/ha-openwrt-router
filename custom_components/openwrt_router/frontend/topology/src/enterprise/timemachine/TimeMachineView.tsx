/**
 * TimeMachineView — Enterprise sub-tab "Zeitreise" (Network Time Machine,
 * read only).
 *
 * Four views, switched in the tab (state kept here, no router or URL change):
 *
 * - "Zeitleiste": one timeline of the marks of every source (audit,
 *   configuration versions, Network Intelligence, Security Center, and since
 *   1.51.0 the Time Machine's own history, its references and the client
 *   histories), newest first, grouped by local calendar day. Intervals that
 *   began before the window and still reach into it stand in a block of their
 *   own at the top ("Läuft seit vor dem Zeitfenster").
 * - "Zustand" (1.52.0): the reconstructed state at one moment (…/state),
 *   and "Vergleich": two moments side by side (…/compare); both in
 *   TimeMachineState.tsx, for every user.
 * - "Client-Sitzungen" (administrators only, 1.51.0): the client sessions of
 *   GET …/sessions, newest start first, grouped by day.
 *
 * Since 1.52.0 the timeline also has a fifth window state "Eigenes Fenster"
 * (set only by "In der Zeitleiste zeigen" of the other views), a client
 * filter and the export (administrators), and jump buttons into the tab a
 * mark belongs to (tmUi.JumpButton).
 *
 * Every container stays mounted once opened (its state survives a switch) but
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

import React, { useCallback, useEffect, useId, useReducer, useRef, useState } from 'react';
import {
  CLIENTS_OFF_HOW, CLIENTS_OFF_TITLE, CLIENTS_PRIVACY, CUSTOM_WINDOW, CUT_TEXT, DEFAULT_FILTERS, DEFAULT_SESSION_FILTERS,
  EMPTY_TEXT, HIDDEN_ONLY_TEXT, LIST_INIT, LOADING_TEXT, NO_SOURCE_TEXT, PARTIAL_TEXT, POLL_MIN_MS,
  RECORDING_OFF, RECORDING_ON, RESTART_TEXT, SPANS_CUT_TEXT, SESSIONS_CUT_TEXT, SESSIONS_EMPTY_TEXT, SESSIONS_LOADING_TEXT,
  SESSIONS_VIEW_TITLE, SESSION_LIST_INIT, SEVERITY_FILTERS, SOURCES_NEWEST, SOURCES_TITLE, SOURCE_IDS, SPANS_TITLE,
  TIMELINE_VIEW_TITLE, WINDOWS,
  adminOnlySources, askedFilters, bandText, clientLabel, clientOptions, clientsOff, countText, customWindowText, dayGroups,
  filterKey, firstQuery, firstSessionQuery, groupText, groupsOf, isoUtc, listReducer, olderQuery, olderSessionQuery,
  omittedText, rememberClients, rememberMarkClients, rememberRouters, rememberSessionRouters, roamText,
  routerText, sessionDays, sessionDurationText, sessionFilterKey, sessionReducer, shouldPoll,
  shouldPollSessions, sourcePill, sourceText, timeText, unavailableText,
  visibleMarks,
  type ClientNames, type ListState, type RouterNames, type SessionListState,
} from './tmLogic.ts';
import {
  COMPARE_VIEW_TITLE, EXPORT_CONFIRM_TEXT, EXPORT_FILENAME, STATE_VIEW_TITLE, activeIn, dialogFocus, dialogKey, exportOmittedText,
} from './tmState.ts';
import type { CustomWindow, Filters, Mark, Session, SessionFilters, TimelineQuery, TmApi } from './tmTypes';
import {
  Chip, ClientFilterContext, ClientLabel, ErrorBox, Frame, JumpContext, MarkRow, OffBox, RouterSelect, Spinner,
  pageVisible, saveBlob, type JumpApi,
} from './tmUi';
import { CompareContainer, StateContainer } from './TimeMachineState';

export { Frame, MarkRow };

const CHECK_MS = Math.min(15_000, POLL_MIN_MS);

export type TmView = 'timeline' | 'state' | 'compare' | 'sessions';

// ── Pieces ───────────────────────────────────────────────────────────────

function RestartNotice({ onDismiss }: { onDismiss: () => void }) {
  return (
    <div className="cfg-notice cfg-notice--info tm-restart" role="status">
      <span>{RESTART_TEXT}</span>
      <button type="button" className="diag-btn cfg-btn" onClick={onDismiss}>Ausblenden</button>
    </div>
  );
}

/**
 * "Zeitleiste | Zustand | Vergleich | Client-Sitzungen"; the sessions only
 * for administrators. Wraps to two rows of two at 360 px (timemachine.css).
 */
export function ViewSwitch({ view, onView, isAdmin = true }: { view: TmView; onView: (v: TmView) => void; isAdmin?: boolean }) {
  return (
    <div className="tm-chips tm-views" role="group" aria-label="Ansicht">
      <Chip on={view === 'timeline'} onClick={() => onView('timeline')}>{TIMELINE_VIEW_TITLE}</Chip>
      <Chip on={view === 'state'} onClick={() => onView('state')}>{STATE_VIEW_TITLE}</Chip>
      <Chip on={view === 'compare'} onClick={() => onView('compare')}>{COMPARE_VIEW_TITLE}</Chip>
      {isAdmin && <Chip on={view === 'sessions'} onClick={() => onView('sessions')}>{SESSIONS_VIEW_TITLE}</Chip>}
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

function WindowChips({ value, custom, onChange, onClearCustom }: {
  value: string; custom?: CustomWindow | null; onChange: (id: string) => void; onClearCustom?: () => void;
}) {
  const own = value === CUSTOM_WINDOW && custom;
  return (
    <div className="tm-filter">
      <span className="tm-filter__name">Zeitfenster</span>
      <div className="tm-chips">
        {WINDOWS.map(w => <Chip key={w.id} on={value === w.id} onClick={() => onChange(w.id)}>{w.label}</Chip>)}
        {own && (
          <span className="tm-own" role="status">
            <span className="tm-own__text">{customWindowText(custom)}</span>
            <button type="button" className="diag-btn cfg-btn tm-own__close" aria-label="Eigenes Fenster schließen, zurück zu 24 Stunden"
              title="Zurück zu 24 Stunden" onClick={onClearCustom}>×</button>
          </span>
        )}
      </div>
    </div>
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
  /** Administrators: the clients of the loaded marks (the "Client" select). */
  clients?: ClientNames | null;
}

export function FilterBar({ filters, adminOnly, routers, groups, hidden, shown, total, onFilters, onToggleGroup, clients = null }: FilterBarProps) {
  const toggleSource = (id: string) => {
    const off = filters.sourcesOff.includes(id) ? filters.sourcesOff.filter(s => s !== id) : [...filters.sourcesOff, id];
    onFilters({ ...filters, sourcesOff: off });
  };
  return (
    <div className="tm-filters" role="group" aria-label="Filter der Zeitleiste">
      <WindowChips value={filters.window} custom={filters.custom} onChange={window => onFilters({ ...filters, window, custom: null })}
        onClearCustom={() => onFilters({ ...filters, window: DEFAULT_FILTERS.window, custom: null })} />
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
      {clients && <ClientSelect value={filters.client} clients={clients} onChange={client => onFilters({ ...filters, client })} />}
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

function ClientSelect({ value, clients, onChange }: { value: string | null; clients: ClientNames; onChange: (c: string | null) => void }) {
  const options = clientOptions(clients);
  if (value && !options.some(o => o.value === value)) options.push({ value, label: clientLabel(value, null) });
  return (
    <label className="tm-filter tm-field">
      <span className="tm-filter__name">Client</span>
      <select value={value ?? ''} onChange={e => onChange(e.target.value || null)}>
        <option value="">Alle Clients</option>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  );
}

// ── Export (administrators only) ─────────────────────────────────────────

export interface ExportState {
  /** The confirmation is open (in the tab, never window.confirm). */
  confirm: boolean;
  busy: boolean;
  error: unknown;
  /** Pages saved so far (1-based number of the last one), null before the first. */
  saved: number | null;
  /** A cut export goes on here (the query of its first page and the cursor). */
  next: { query: TimelineQuery; cursor: string } | null;
  /** Client marks of the window not in the file (omitted_client_marks of the last page), null before the first. */
  omitted?: number | null;
}

export const EXPORT_INIT: ExportState = { confirm: false, busy: false, error: null, saved: null, next: null, omitted: null };

export function ExportBox({ state, onAsk, onConfirm, onCancel, onNext }: {
  state: ExportState; onAsk: () => void; onConfirm: () => void; onCancel: () => void; onNext: () => void;
}) {
  const trigger = useRef<HTMLButtonElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const wasOpen = useRef(state.confirm);
  const textId = useId();
  // open: focus on "Abbrechen"; closed (cancelled or confirmed): back to the button that opened it
  useEffect(() => {
    const target = dialogFocus(wasOpen.current, state.confirm);
    wasOpen.current = state.confirm;
    if (target === 'cancel') cancel.current?.focus();
    else if (target === 'trigger') trigger.current?.focus();
  }, [state.confirm]);
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const buttons = Array.from(dialog.current?.querySelectorAll<HTMLButtonElement>('button:not([disabled])') ?? []);
    const step = dialogKey(e.key, e.shiftKey, buttons.indexOf(activeIn(dialog.current) as HTMLButtonElement), buttons.length);
    if (!step) return;
    e.preventDefault();
    if (step.action === 'cancel') onCancel();
    else buttons[step.index]?.focus();
  };
  const omitted = state.error === null && !state.busy ? exportOmittedText(state.omitted ?? null) : null;
  return (
    <div className="tm-export">
      {!state.confirm && (
        // aria-disabled, not disabled, while busy: the focus comes back to it after the confirmation
        <button type="button" className="diag-btn cfg-btn" ref={trigger} aria-disabled={state.busy || undefined}
          onClick={() => { if (!state.busy) onAsk(); }}>Exportieren</button>
      )}
      {state.confirm && (
        <div className="cfg-notice cfg-notice--info tm-export__ask" role="alertdialog" aria-label="Export bestätigen"
          aria-modal="true" aria-describedby={textId} ref={dialog} onKeyDown={onKey}>
          <span id={textId}>{EXPORT_CONFIRM_TEXT}</span>
          <span className="tm-export__buttons">
            <button type="button" className="diag-btn cfg-btn" disabled={state.busy} onClick={onConfirm}>Exportieren</button>
            <button type="button" className="diag-btn cfg-btn" ref={cancel} onClick={onCancel}>Abbrechen</button>
          </span>
        </div>
      )}
      {state.busy && <span className="cfg-spinner"><span className="cfg-spinner__dot" />Export läuft …</span>}
      {state.error !== null && <ErrorBox of="export" error={state.error} />}
      {state.saved !== null && state.error === null && !state.busy && (
        <span className="cfg-hint tm-export__done" role="status">
          {state.next
            ? `Seite ${state.saved} gespeichert. Der Export ist gekürzt; die nächste Seite folgt mit „Weitere Seite exportieren“.`
            : `Export gespeichert${state.saved > 1 ? ` (Seite ${state.saved})` : ''}.`}
          {omitted && ` ${omitted}`}
        </span>
      )}
      {state.next && !state.busy && (
        <button type="button" className="diag-btn cfg-btn" onClick={onNext}>Weitere Seite exportieren</button>
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
  /** Administrators (1.52.0): the client filter and the export. */
  isAdmin?: boolean;
  clients?: ClientNames;
  exportState?: ExportState;
  onExport?: { ask: () => void; confirm: () => void; cancel: () => void; next: () => void };
}

export function TimeMachineScreen({
  state, filters, hidden, routers, nowMs, viewSwitch, onFilters, onToggleGroup, onRefresh, onMore, onDismiss,
  isAdmin = false, clients, exportState, onExport,
}: ScreenProps) {
  const head = state.head;
  const off = head?.status === 'off';
  const adminOnly = adminOnlySources(head);
  const noSource = !off && firstQuery(filters, nowMs, adminOnly) === null;
  const spanning = head && !off ? head.spanning : [];
  const all = [...spanning, ...state.marks];
  const groups = [...groupsOf(all), ...hidden.filter(g => !all.some(m => m.group === g))];
  const shown = visibleMarks(state.marks, hidden);
  const shownSpans = visibleMarks(spanning, hidden);
  const omitted = head && !off ? omittedText(head.omittedClientMarks, clientsOff(head)) : null;
  const firstLoad = head === null || (state.loading && !all.length && !off);
  // a page without marks that goes on: only left-out entries in this part (review S1)
  const hiddenOnly = !state.marks.length && state.nextCursor !== null;

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
          shown={shown.length + shownSpans.length} total={all.length} onFilters={onFilters} onToggleGroup={onToggleGroup}
          clients={isAdmin ? clients ?? rememberMarkClients({}, all) : null} />
        {isAdmin && onExport && !noSource && (
          <ExportBox state={exportState ?? EXPORT_INIT} onAsk={onExport.ask} onConfirm={onExport.confirm}
            onCancel={onExport.cancel} onNext={onExport.next} />
        )}
        {state.error !== null && <ErrorBox error={state.error} onRetry={onRefresh} />}
        {state.restarted && <RestartNotice onDismiss={onDismiss ?? (() => {})} />}
        {head.status === 'partial' && <div className="cfg-notice cfg-notice--warn" role="note">{PARTIAL_TEXT}</div>}
        <SourceRow state={state} />
        {omitted && <div className="cfg-hint tm-omitted" role="note">{omitted}</div>}
        {noSource && <div className="cfg-hint" role="note">{NO_SOURCE_TEXT}</div>}
        {state.loading && all.length > 0 && !noSource && <Spinner text={LOADING_TEXT} />}
        {noSource ? null : firstLoad
          ? <Spinner text={LOADING_TEXT} />
          : (
            // one size container (tmlist) around the block and the list: both get the cards
            <div className="tm-timeline">
              <SpansBlock marks={shownSpans} cut={head.spanningTruncated} nowMs={nowMs} />
              {hiddenOnly
                ? <div className="cfg-empty tm-empty tm-hidden-only">{HIDDEN_ONLY_TEXT}</div>
                : <TimelineList marks={shown} total={state.marks.length} spans={spanning.length} nowMs={nowMs} />}
            </div>
          )}
        {state.moreError !== null && <ErrorBox error={state.moreError} onRetry={onMore} />}
        {!noSource && !firstLoad && state.nextCursor !== null && !state.cursorRefused && (
          <div className="tm-more">
            <button type="button" className="diag-btn cfg-btn" disabled={state.loadingMore} onClick={onMore}>Ältere laden</button>
            {state.loadingMore && <span className="cfg-spinner"><span className="cfg-spinner__dot" />lädt …</span>}
          </div>
        )}
        {!noSource && state.nextCursor === null && state.truncated && <div className="cfg-hint tm-cut" role="note">{CUT_TEXT}</div>}
      </>
    );
  })();

  const filterBy = useCallback((client: string) => onFilters({ ...filters, client }), [filters, onFilters]);
  return (
    <ClientFilterContext.Provider value={isAdmin ? filterBy : null}>
      <Frame loading={state.loading} onRefresh={onRefresh} viewSwitch={viewSwitch} generatedAt={head?.generatedAt}>
        {body}
      </Frame>
    </ClientFilterContext.Provider>
  );
}

/** Intervals that began before the window (the first page's `spanning`), on top, start as date and time. */
function SpansBlock({ marks, cut, nowMs }: { marks: readonly Mark[]; cut: boolean; nowMs: number }) {
  if (!marks.length && !cut) return null;
  return (
    <section className="tm-day tm-spans" aria-label={SPANS_TITLE}>
      <h3 className="cfg-subtitle tm-day__title">{SPANS_TITLE}</h3>
      {marks.length > 0 && (
        <ol className="tm-rows">
          {marks.map(m => <MarkRow key={m.id} m={m} nowMs={nowMs} start />)}
        </ol>
      )}
      {cut && <div className="cfg-hint tm-spans-cut" role="note">{SPANS_CUT_TEXT}</div>}
    </section>
  );
}

function TimelineList({ marks, total, spans, nowMs }: { marks: readonly Mark[]; total: number; spans: number; nowMs: number }) {
  if (!marks.length) {
    // the block above alone: no "no marks" line under running intervals
    if (!total && spans) return null;
    return <div className="cfg-empty tm-empty">{total || spans ? 'Keine Marken der gewählten Arten.' : EMPTY_TEXT}</div>;
  }
  return (
    <div className="tm-list">
      {dayGroups(marks, nowMs).map(day => (
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
  const router = routerText({ fleet: false, routerId: x.routerId, routerName: x.routerName });
  return (
    <li className="tm-session" data-end={x.endState ?? 'none'}>
      <time className="tm-session__time" dateTime={iso} title={iso}>{timeText(x.ts)}</time>
      <span className="tm-session__dur">{sessionDurationText(x)}</span>
      <span className="tm-session__client">
        <ClientLabel client={x.client} name={x.clientName} />
        {x.derived && <span className="cfg-badge cfg-badge--info">abgeleitet</span>}
      </span>
      <span className="tm-session__router" title={router}>{router}</span>
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
        {!firstLoad && state.nextCursor !== null && !state.cursorRefused && (
          <div className="tm-more">
            <button type="button" className="diag-btn cfg-btn" disabled={state.loadingMore} onClick={onMore}>Ältere laden</button>
            {state.loadingMore && <span className="cfg-spinner"><span className="cfg-spinner__dot" />lädt …</span>}
          </div>
        )}
        {state.nextCursor === null && state.truncated && <div className="cfg-hint tm-cut" role="note">{SESSIONS_CUT_TEXT}</div>}
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

/** A request of another view: show this window in the timeline (`n` counts the requests). */
export interface WindowRequest {
  window: CustomWindow;
  n: number;
}

/**
 * The timeline: loads and polls only while `active` (its view is shown).
 * Never while its window is a custom one (a fixed window of the past). A
 * client filter is only ever sent by administrators.
 */
export function TimelineContainer({ api, active, viewSwitch, isAdmin = false, request = null }: {
  api: TmApi; active: boolean; viewSwitch?: React.ReactNode; isAdmin?: boolean; request?: WindowRequest | null;
}) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [hidden, setHidden] = useState<string[]>([]);
  const [routers, setRouters] = useState<RouterNames>({});
  const [clients, setClients] = useState<ClientNames>({});
  const [exp, setExp] = useState<ExportState>(EXPORT_INIT);
  const [state, dispatch] = useReducer(listReducer, LIST_INIT);
  const stateRef = useRef(state);
  stateRef.current = state;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const activeRef = useRef(active);
  activeRef.current = active;
  const seq = useRef(0);
  const lastMs = useRef<number | null>(null);

  const adminRef = useRef(isAdmin);
  adminRef.current = isAdmin;
  const asked = useCallback((): Filters => askedFilters(filtersRef.current, adminRef.current), []);

  // "In der Zeitleiste zeigen" of another view: the custom window, the rest of the filters kept
  const lastRequest = useRef(0);
  useEffect(() => {
    if (!request || request.n === lastRequest.current) return;
    lastRequest.current = request.n;
    setFilters(f => ({ ...f, window: CUSTOM_WINDOW, custom: request.window }));
  }, [request]);

  const loadFirst = useCallback(() => {
    const s = stateRef.current;
    const q = firstQuery(asked(), Date.now(), adminOnlySources(s.head));
    if (q === null) return;
    const n = ++seq.current;
    const gen = s.gen;
    lastMs.current = Date.now();
    dispatch({ type: 'start', seq: n, more: false });
    api.timeline(q).then(
      answer => dispatch({ type: 'first', gen, seq: n, answer, query: q }),
      error => dispatch({ type: 'fail', gen, seq: n, more: false, error }),
    );
  }, [api, asked]);

  const loadMore = useCallback(() => {
    const s = stateRef.current;
    // the cursor belongs to the window it came with (the server checks it against that)
    if (s.cursorQuery === null || s.nextCursor === null) return;
    const q = olderQuery(s.cursorQuery, s.nextCursor);
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
      if (!activeRef.current || filtersRef.current.window === CUSTOM_WINDOW) return;
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
    if (adminRef.current) {
      setClients(prev => rememberMarkClients(rememberMarkClients(prev, state.marks), state.head?.spanning ?? []));
    }
  }, [state.marks, state.head]);

  const toggleGroup = useCallback((g: string) => {
    setHidden(h => (h.includes(g) ? h.filter(x => x !== g) : [...h, g]));
  }, []);
  const dismiss = useCallback(() => dispatch({ type: 'dismiss' }), []);

  // Export (administrators): the window and filters of the list on screen, page by page
  const exportSeq = useRef(0);
  const runExport = useCallback((query: TimelineQuery, cursor: string | null, page: number) => {
    if (!adminRef.current || !api.exportFile) return;
    const n = ++exportSeq.current;
    setExp(e => ({ ...e, confirm: false, busy: true, error: null }));
    api.exportFile({ ...query, cursor }).then(
      file => {
        if (n !== exportSeq.current) return;
        saveBlob(file.blob, page === 1 ? EXPORT_FILENAME : EXPORT_FILENAME.replace(/\.json$/, `-${page}.json`));
        setExp({
          confirm: false, busy: false, error: null, saved: page,
          next: file.truncated && file.nextCursor ? { query, cursor: file.nextCursor } : null,
          omitted: file.omittedClientMarks,
        });
      },
      error => {
        if (n !== exportSeq.current) return;
        setExp(e => ({ ...e, busy: false, error }));
      },
    );
  }, [api]);
  const onExport = {
    ask: () => setExp(e => ({ ...e, confirm: true, error: null })),
    cancel: () => setExp(e => ({ ...e, confirm: false })),
    confirm: () => {
      const q = firstQuery(asked(), Date.now(), adminOnlySources(stateRef.current.head));
      if (q) runExport(q, null, 1);
    },
    next: () => {
      const next = exp.next;
      if (next) runExport(next.query, next.cursor, (exp.saved ?? 0) + 1);
    },
  };
  // a new filter (window, source, router …) is a new export: the "next page" of the old one goes
  useEffect(() => { setExp(e => (e.next || e.saved !== null ? { ...EXPORT_INIT } : e)); }, [key]);

  if (!active) return null;
  return (
    <TimeMachineScreen state={state} filters={filters} hidden={hidden} routers={routers} nowMs={Date.now()} viewSwitch={viewSwitch}
      onFilters={setFilters} onToggleGroup={toggleGroup} onRefresh={loadFirst} onMore={loadMore} onDismiss={dismiss}
      isAdmin={isAdmin} clients={clients} exportState={exp} onExport={api.exportFile ? onExport : undefined} />
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

  const loadFirst = useCallback(() => {
    const s = stateRef.current;
    const q = firstSessionQuery(filtersRef.current, Date.now());
    const n = ++seq.current;
    const gen = s.gen;
    lastMs.current = Date.now();
    dispatch({ type: 'start', seq: n, more: false });
    api.sessions(q).then(
      answer => dispatch({ type: 'first', gen, seq: n, answer, query: q }),
      error => dispatch({ type: 'fail', gen, seq: n, more: false, error }),
    );
  }, [api]);

  const loadMore = useCallback(() => {
    const s = stateRef.current;
    if (s.cursorQuery === null || s.nextCursor === null) return;
    const q = olderSessionQuery(s.cursorQuery, s.nextCursor);
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
 * The tab. Every user gets "Zeitleiste", "Zustand" and "Vergleich"; only
 * administrators (the panel's hass user) get "Client-Sitzungen" (the route
 * answers 403 to everyone else anyway). A container is mounted the first time
 * its view is chosen and keeps its state when another one is shown. `jump`
 * opens another Enterprise tab (register.ts binds it to the registry).
 */
export function TimeMachineView({ api, isAdmin = false, jump = null }: { api: TmApi; isAdmin?: boolean; jump?: JumpApi | null }) {
  const [view, setView] = useState<TmView>('timeline');
  const [opened, setOpened] = useState<Record<TmView, boolean>>({ timeline: true, state: false, compare: false, sessions: false });
  const [request, setRequest] = useState<WindowRequest | null>(null);
  const choose = useCallback((v: TmView) => {
    setOpened(o => (o[v] ? o : { ...o, [v]: true }));
    setView(v);
  }, []);
  const showWindow = useCallback((window: CustomWindow) => {
    setRequest(r => ({ window, n: (r?.n ?? 0) + 1 }));
    setView('timeline');
  }, []);
  const shown: TmView = view === 'sessions' && !isAdmin ? 'timeline' : view;
  const viewSwitch = <ViewSwitch view={shown} onView={choose} isAdmin={isAdmin} />;
  return (
    <JumpContext.Provider value={jump}>
      <TimelineContainer api={api} active={shown === 'timeline'} viewSwitch={viewSwitch} isAdmin={isAdmin} request={request} />
      {opened.state && <StateContainer api={api} active={shown === 'state'} viewSwitch={viewSwitch} isAdmin={isAdmin} onShowWindow={showWindow} />}
      {opened.compare && <CompareContainer api={api} active={shown === 'compare'} viewSwitch={viewSwitch} isAdmin={isAdmin} onShowWindow={showWindow} />}
      {isAdmin && opened.sessions && <SessionsContainer api={api} active={shown === 'sessions'} viewSwitch={viewSwitch} />}
    </JumpContext.Provider>
  );
}
