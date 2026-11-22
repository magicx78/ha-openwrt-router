/**
 * tmLogic.ts — pure logic of the "Zeitreise" tab (Network Time Machine,
 * Phases A–C, read only).
 *
 * Parser of the server answers (timeline and client sessions), the query of
 * a page, the state of a loaded list (first page, older pages, dropped stale
 * answers, never a silent gap), the client-side group filter, the days in
 * local time and every German text the view shows. No React, no DOM, no
 * network: node --test imports it.
 *
 * Rules kept here:
 *  - Titles come from TITLE_TEXT; without an entry the server's (masked)
 *    `text`, else "Code <title_key>". Network Intelligence incidents say in
 *    front whether the incident was opened or resolved.
 *  - Only known number parameters are shown; nothing here builds or shows a
 *    MAC or IP address, a host name or an interface name. A client is shown
 *    by the name the server sends (administrators only) or by the last six
 *    characters of its pseudonym; nothing is derived here.
 *  - An empty timeline is never an all-clear: no green, no tick.
 *  - The tab only reads; nothing here builds a write.
 */

import { num } from '../../utils/format.ts';
import { durationText, scrub } from '../traffic/trafficLogic.ts';
import { DASH, POLL_MIN_MS, pollDelay, routerLabel, shouldFetch } from '../wifi/wifiLogic.ts';
import {
  GROUP_TEXT, PARAM_ONE, PARAM_TEXT, REASON_TEXT, SEVERITY_TEXT, SOURCE_TEXT, STATE_TEXT, TITLE_TEXT, UNAVAILABLE_TEXT,
} from './tmTexts.ts';
import type {
  CustomWindow, EndState, Filters, Mark, Peer, Ref, Session, SessionFilters, SessionQuery, SessionsAnswer, Severity,
  SourceInfo, Timeline, TimelineQuery, Tone,
} from './tmTypes';

export { DASH, POLL_MIN_MS, pollDelay, shouldFetch };

// ── Constants ────────────────────────────────────────────────────────────

export const TAB_ID = 'timemachine';
export const TAB_TITLE = 'Zeitreise';
/** After Traffic Analytics (50). */
export const TAB_ORDER = 60;

export const INTRO =
  'Was war wann im Netz los: Ereignisse, Vorfälle und Konfigurationsänderungen aller Router auf einer Zeitleiste. Nur Beobachtung; es wird nichts am Router geändert.';
export const OFF_TITLE = 'Die Zeitreise ist ausgeschaltet.';
export const OFF_HOW =
  'Einstellungen → Geräte & Dienste → OpenWrt Router → einen Router → Konfigurieren → ‚Zeitreise‘ einschalten. Der Schalter gilt für alle Router.';
export const PARTIAL_TEXT = 'Mindestens eine Quelle war nicht lesbar; die Zeitleiste ist unvollständig.';
export const EMPTY_TEXT = 'Keine Marken im gewählten Zeitfenster.';
export const CUT_TEXT = 'Weitere Marken im Zeitfenster wurden gekürzt; Zeitfenster oder Filter enger wählen.';
export const NO_SOURCE_TEXT = 'Keine Quelle gewählt. Mindestens eine Quelle einschalten.';
export const LOADING_TEXT = 'Zeitleiste wird geladen …';
/** Heading of the block of intervals that began before the window (1.51.0). */
export const SPANS_TITLE = 'Läuft seit vor dem Zeitfenster';
/** Under the block when the server sent only part of it (spanning_truncated). */
export const SPANS_CUT_TEXT = 'Weitere laufen seit vor dem Zeitfenster; Zeitfenster oder Filter enger wählen.';
/** The list started anew after a refresh brought more than a page (dismissable). */
export const RESTART_TEXT = 'Viele neue Einträge: Die Liste beginnt neu. Ältere bei Bedarf erneut laden.';
export const SOURCES_TITLE = 'Quellen';
/** Added to the sources heading once older pages are loaded: the pills are the first page's. */
export const SOURCES_NEWEST = '(neueste Seite)';
/** A page without marks that goes on (only left-out entries in this part of the window). */
export const HIDDEN_ONLY_TEXT = 'In diesem Abschnitt gibt es nur ausgeblendete Einträge. Ältere laden, um weiter zurückzugehen.';

export const SOURCE_IDS: readonly string[] = [
  'core_audit', 'config_versions', 'ni_events', 'ni_incidents', 'security_timeline', 'tm_index', 'tm_refs', 'tm_clients',
];
export const SEVERITIES: readonly Severity[] = ['info', 'warning', 'critical'];
export const GROUP_ORDER: readonly string[] = [
  'infrastructure', 'radio', 'topology', 'configuration', 'disruption', 'security', 'administration', 'clients', 'time_machine',
];

export const WINDOWS: readonly { id: string; label: string; seconds: number }[] = [
  { id: '1h', label: '1 Stunde', seconds: 3600 },
  { id: '24h', label: '24 Stunden', seconds: 86_400 },
  { id: '7d', label: '7 Tage', seconds: 7 * 86_400 },
  { id: '14d', label: '14 Tage', seconds: 14 * 86_400 },
];
export const DEFAULT_WINDOW = '24h';

export const SEVERITY_FILTERS: readonly { id: Filters['severity']; label: string }[] = [
  { id: 'all', label: 'Alle' },
  { id: 'warning', label: 'ab Warnung' },
  { id: 'critical', label: 'nur kritisch' },
];

export const DEFAULT_FILTERS: Filters = {
  window: DEFAULT_WINDOW, sourcesOff: [], severity: 'all', routerId: null, custom: null, client: null,
};
/** The fifth window state: set only by a jump from "Zustand" or "Vergleich" (1.52.0). */
export const CUSTOM_WINDOW = 'custom';
/** Half of the window around a moment that "In der Zeitleiste zeigen" opens (±30 min). */
export const AROUND_S = 1800;
const MAX_WINDOW_S = 14 * 86_400;

export const ROUTER_ID_RE = /^rtr_[0-9a-f]{32}$/;
const KEY_RE = /^[a-z0-9_.]{1,200}$/;
const MARK_ID_RE = /^tmm_[0-9a-f]{16}$/;
export const CLIENT_RE = /^tmc_[0-9a-f]{16}$/;
const MODULE_RE = /^[a-z_]{1,40}$/;
const REF_ID_RE = /^[A-Za-z0-9_:.-]{1,80}$/;
const VERSION_ID_RE = /^bkp_[0-9a-f]{32}$/;
/** A position of the server's order (1.51.0): "<ms>" or "<ms>:tmm_<16 hex>". */
const CURSOR_RE = /^(\d{1,16})(?::(tmm_[0-9a-f]{16}))?$/;
const END_STATES: readonly EndState[] = ['open', 'closed', 'unknown'];

// ── Parser ───────────────────────────────────────────────────────────────

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {};
}
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}
function fin(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function severityOf(v: unknown): Severity {
  return v === 'warning' || v === 'critical' ? v : 'info';
}

function parseParams(v: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(v))) {
    const value = fin(n);
    if (value !== null && /^[a-z_]{1,40}$/.test(k)) out[k] = value;
  }
  return out;
}

export function parseMark(v: unknown): Mark | null {
  const m = obj(v);
  const id = str(m.id);
  const ts = fin(m.ts);
  const titleKey = str(m.title_key);
  if (!id || ts === null || !titleKey) return null;
  const routerId = str(m.router_id);
  return {
    id,
    ts,
    source: str(m.source) ?? '',
    kind: str(m.kind) ?? '',
    group: str(m.group) ?? '',
    severity: severityOf(m.severity),
    routerId: routerId && ROUTER_ID_RE.test(routerId) ? routerId : null,
    routerName: str(m.router_name),
    fleet: m.fleet === true,
    titleKey,
    text: str(m.text),
    params: parseParams(m.params),
    derived: m.derived === true,
    code: str(m.code),
    end: fin(m.end),
    endState: endStateOf(m.end_state),
    client: clientOf(m.client),
    clientName: str(m.client_name),
    peers: peersOf(m.peers),
    spansIn: m.spans_in === true,
    ref: refOf(m.ref),
  };
}

/** The `ref` of a mark or item, every part checked (else null). */
export function refOf(v: unknown): Ref | null {
  if (!v || typeof v !== 'object') return null;
  const r = obj(v);
  const module = str(r.module);
  if (!module || !MODULE_RE.test(module)) return null;
  const type = str(r.type);
  const id = str(r.id);
  const versionId = str(r.version_id);
  return {
    module,
    type: type && MODULE_RE.test(type) ? type : null,
    id: id && REF_ID_RE.test(id) ? id : null,
    versionId: versionId && VERSION_ID_RE.test(versionId) ? versionId : null,
  };
}

function endStateOf(v: unknown): EndState | null {
  return END_STATES.includes(v as EndState) ? (v as EndState) : null;
}

function clientOf(v: unknown): string | null {
  const c = str(v);
  return c && CLIENT_RE.test(c) ? c : null;
}

function peerOf(v: unknown): Peer | null {
  if (!v || typeof v !== 'object') return null;
  const p = obj(v);
  const routerId = str(p.router_id);
  return { routerId: routerId && ROUTER_ID_RE.test(routerId) ? routerId : null, routerName: str(p.router_name) };
}

function peersOf(v: unknown): Mark['peers'] {
  if (!v || typeof v !== 'object') return null;
  const p = obj(v);
  const before = peerOf(p.before);
  const after = peerOf(p.after);
  return before || after ? { before, after } : null;
}

function parseSource(v: unknown): SourceInfo | null {
  const s = obj(v);
  const id = str(s.id);
  if (!id) return null;
  return {
    id,
    state: str(s.state) ?? '',
    reason: str(s.reason),
    count: fin(s.count) ?? 0,
    oldest: fin(s.oldest),
    truncated: s.truncated === true,
    cut: str(s.cut),
    duplicates: Math.max(0, fin(s.duplicates) ?? 0),
  };
}

export function parseTimeline(v: unknown): Timeline {
  const b = obj(v);
  const w = obj(b.window);
  const marks = Array.isArray(b.marks) ? b.marks.map(parseMark).filter((m): m is Mark => m !== null) : [];
  const sources = Array.isArray(b.sources) ? b.sources.map(parseSource).filter((s): s is SourceInfo => s !== null) : [];
  return {
    status: str(b.status) ?? '',
    generatedAt: fin(b.generated_at),
    from: fin(w.from),
    until: fin(w.until),
    marks: dedupe(marks),
    sources,
    omittedClientMarks: Math.max(0, fin(b.omitted_client_marks) ?? 0),
    truncated: b.truncated === true,
    nextCursor: cursorOf(b.next_cursor),
    spanning: dedupe(Array.isArray(b.spanning) ? b.spanning.map(parseMark).filter((m): m is Mark => m !== null) : []),
    spanningTruncated: b.spanning_truncated === true,
  };
}

/** A cursor of the server, or null (never anything else is sent back). */
export function cursorOf(v: unknown): string | null {
  return typeof v === 'string' && CURSOR_RE.test(v) ? v : null;
}

/** [ms, id] of a cursor; id null for "<ms>" (everything older than ms). */
export function cursorPos(c: string): [number, string | null] {
  const m = CURSOR_RE.exec(c);
  return m ? [Number(m[1]), m[2] ?? null] : [Number.NaN, null];
}

// ── Query ────────────────────────────────────────────────────────────────

export function windowSeconds(id: string): number {
  return (WINDOWS.find(w => w.id === id) ?? WINDOWS[1]).seconds;
}

/**
 * The first page of the filters at `nowMs`. Both ends are sent, so the
 * window never grows past 14 days by a clock difference. Sources the server
 * reported as not shown to this user (`disabled`) are always asked for: the
 * server answers them as `off` without reading. Null when no source is left.
 */
export function firstQuery(f: Filters, nowMs: number, disabled: readonly string[] = []): TimelineQuery | null {
  const custom = f.window === CUSTOM_WINDOW ? f.custom : null;
  const until = custom ? custom.until : Math.floor(nowMs / 1000) + 1;
  const picked = SOURCE_IDS.filter(s => !f.sourcesOff.includes(s) || disabled.includes(s));
  if (!picked.some(s => !disabled.includes(s))) return null;
  return {
    from: custom ? custom.from : until - windowSeconds(f.window),
    until,
    sources: picked.length === SOURCE_IDS.length ? null : picked,
    minSeverity: f.severity === 'all' ? null : f.severity,
    routerId: f.routerId && ROUTER_ID_RE.test(f.routerId) ? f.routerId : null,
    spans: true,
    cursor: null,
    client: f.client && CLIENT_RE.test(f.client) ? f.client : null,
  };
}

/** What the timeline asks with: a client filter only for administrators (never sent otherwise). */
export function askedFilters(f: Filters, isAdmin: boolean): Filters {
  return isAdmin || f.client === null ? f : { ...f, client: null };
}

/**
 * The custom window of a jump: `from`–`until` (epoch seconds), the upper end
 * at most `nowMs` (+1 s, like a first page), at most 14 days, never empty.
 * Null when nothing of it is left.
 */
export function customWindow(from: number, until: number, nowMs: number): CustomWindow | null {
  if (!Number.isFinite(from) || !Number.isFinite(until)) return null;
  const top = Math.min(Math.ceil(until), Math.floor(nowMs / 1000) + 1);
  const low = Math.max(Math.floor(from), top - MAX_WINDOW_S);
  return low < top ? { from: low, until: top } : null;
}

/** The ±30 min window around a moment. */
export function aroundWindow(at: number, nowMs: number): CustomWindow | null {
  return customWindow(at - AROUND_S, at + AROUND_S, nowMs);
}

/** "Fenster: 21.11. 13:30 – 14:30" (local time; the date of the end only when it differs). */
export function customWindowText(c: CustomWindow): string {
  const a = new Date(c.from * 1000);
  const b = new Date(c.until * 1000);
  const day = (d: Date) => `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`;
  const hm = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const end = dayKey(a) === dayKey(b) ? hm(b) : `${day(b)} ${hm(b)}`;
  return `Fenster: ${day(a)} ${hm(a)} – ${end}`;
}

/**
 * The next older page: the same window and filters as the page that gave
 * the cursor (the server checks the cursor against that window), the
 * cursor, and no spans (the block came with the first page).
 */
export function olderQuery(base: TimelineQuery, cursor: string): TimelineQuery {
  return { ...base, spans: false, cursor };
}

function epochText(x: number): string {
  return String(Math.round(x * 1000) / 1000);
}

/** Query string in a fixed order from checked values only (never free text). */
export function queryString(q: TimelineQuery): string {
  const p = new URLSearchParams();
  p.set('from', epochText(q.from));
  p.set('until', epochText(q.until));
  if (q.sources) p.set('source', q.sources.filter(s => SOURCE_IDS.includes(s)).join(','));
  if (q.routerId && ROUTER_ID_RE.test(q.routerId)) p.set('router_id', q.routerId);
  if (q.minSeverity && SEVERITIES.includes(q.minSeverity)) p.set('min_severity', q.minSeverity);
  if (q.spans) p.set('spans', '1');
  if (q.cursor && CURSOR_RE.test(q.cursor)) p.set('cursor', q.cursor);
  if (q.client && CLIENT_RE.test(q.client)) p.set('client', q.client);
  return p.toString();
}

/**
 * The export of a timeline query (administrators only): the same window and
 * filters, never `spans` or `client` (the route refuses both; the export has
 * no client histories). `cursor`: the next page of a cut export.
 */
export function exportQueryString(q: TimelineQuery, cursor: string | null = null): string {
  return queryString({ ...q, spans: false, client: null, cursor: cursor && CURSOR_RE.test(cursor) ? cursor : null });
}

/** A stable key of what the server is asked (a change starts a new list). */
export function filterKey(f: Filters): string {
  const custom = f.window === CUSTOM_WINDOW && f.custom ? [f.custom.from, f.custom.until] : null;
  return JSON.stringify([f.window, [...f.sourcesOff].sort(), f.severity, f.routerId, custom, f.client ?? null]);
}

// ── Marks: order, dedupe, merge ──────────────────────────────────────────

export function compareMarks(a: Mark, b: Mark): number {
  return b.ts - a.ts || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** Newest first, ties by id; each id once (the first one wins). */
export function dedupe(marks: readonly Mark[]): Mark[] {
  const seen = new Set<string>();
  const out: Mark[] = [];
  for (const m of marks) {
    if (seen.has(m.id)) continue;
    seen.add(m.id);
    out.push(m);
  }
  return out.sort(compareMarks);
}

export function mergeMarks(newer: readonly Mark[], older: readonly Mark[]): Mark[] {
  return dedupe([...newer, ...older]);
}

// ── List state (first page, older pages, stale answers) ──────────────────

export interface ListState {
  /** Generation of the filters; an answer of an older generation is dropped. */
  gen: number;
  /** Sequence number of the latest first-page / older-page request. */
  firstSeq: number;
  moreSeq: number;
  /** The latest first-page answer (status, sources, counts). */
  head: Timeline | null;
  marks: Mark[];
  /** Older pages were appended. */
  older: boolean;
  /** Where the next older page starts, and the query (window, filters) it belongs to. */
  nextCursor: string | null;
  cursorQuery: TimelineQuery | null;
  /** Upper end (until, epoch s) of what the list covers without a gap. */
  topUntil: number | null;
  truncated: boolean;
  loading: boolean;
  loadingMore: boolean;
  error: unknown;
  moreError: unknown;
  /** A refresh started the list anew (more new marks than a page); until dismissed. */
  restarted: boolean;
  /** The server refused the cursor (400, field cursor): no "Ältere laden" until a new first page. */
  cursorRefused: boolean;
}

export const LIST_INIT: ListState = {
  gen: 0, firstSeq: 0, moreSeq: 0, head: null, marks: [], older: false, nextCursor: null, cursorQuery: null,
  topUntil: null, truncated: false, loading: false, loadingMore: false, error: null, moreError: null, restarted: false,
  cursorRefused: false,
};

export type ListAction =
  | { type: 'filters' }
  | { type: 'dismiss' }
  | { type: 'start'; seq: number; more: boolean }
  | { type: 'first'; gen: number; seq: number; answer: Timeline; query: TimelineQuery }
  | { type: 'older'; gen: number; seq: number; answer: Timeline }
  | { type: 'fail'; gen: number; seq: number; more: boolean; error: unknown };

/**
 * One step of the loaded list. A filter change starts a new generation and
 * empties the list; an answer of an older generation or an older request is
 * dropped, so a stale answer never overwrites a newer one. A new first page
 * replaces the list, or — when older pages are loaded or one is being loaded —
 * puts its marks in front of them (deduplicated) and keeps their cursor and
 * the query that cursor belongs to. It goes in front only when it reaches the
 * list (`reaches`); otherwise it starts the list anew and drops a pending
 * older page, so the list never has a silent gap (review K3); `restarted`
 * then says so until dismissed. The block of intervals from before the
 * window (`head.spanning`) comes with every first page and stays while older
 * pages are loaded.
 */
export function listReducer(s: ListState, a: ListAction): ListState {
  switch (a.type) {
    case 'filters':
      // loading at once: the empty list of a new filter is never shown as "no marks";
      // the block of the old filters goes with its list
      return {
        ...LIST_INIT, gen: s.gen + 1, firstSeq: s.firstSeq, moreSeq: s.moreSeq, loading: true,
        head: s.head && { ...s.head, spanning: [], spanningTruncated: false },
      };
    case 'dismiss':
      return s.restarted ? { ...s, restarted: false } : s;
    case 'start':
      return a.more
        ? { ...s, moreSeq: a.seq, loadingMore: true, moreError: null }
        : { ...s, firstSeq: a.seq, loading: true };
    case 'first': {
      if (a.gen !== s.gen || a.seq !== s.firstSeq) return s;
      const t = a.answer;
      if (t.status === 'off') {
        return {
          ...s, head: t, marks: [], older: false, nextCursor: null, cursorQuery: null, topUntil: null, truncated: false,
          loading: false, error: null,
        };
      }
      // a refused cursor is never joined to: the new first page starts the list (no notice)
      const kept = (s.older || s.loadingMore) && !s.cursorRefused;
      if (!kept || !reaches(t.nextCursor, s.topUntil)) {
        const stop = s.loadingMore || s.cursorRefused ? { moreSeq: -1, loadingMore: false, moreError: null } : {};
        return {
          ...s, ...stop, head: t, marks: t.marks, older: false, nextCursor: t.nextCursor, cursorQuery: a.query,
          topUntil: a.query.until, truncated: t.truncated, loading: false, error: null, restarted: kept || s.restarted,
          cursorRefused: false,
        };
      }
      // joined: the older pages keep their cursor and window; marks that left the window go
      const from = t.from ?? a.query.from;
      const marks = mergeMarks(t.marks, s.marks).filter(m => m.ts >= from);
      return { ...s, head: t, marks, topUntil: a.query.until, loading: false, error: null };
    }
    case 'older': {
      if (a.gen !== s.gen || a.seq !== s.moreSeq) return s;
      const t = a.answer;
      const from = s.head?.from ?? -Infinity;
      return {
        ...s, marks: mergeMarks(s.marks, t.marks.filter(m => m.ts >= from)), older: true, nextCursor: t.nextCursor,
        truncated: t.truncated, loadingMore: false, moreError: null,
      };
    }
    case 'fail':
      if (a.gen !== s.gen || a.seq !== (a.more ? s.moreSeq : s.firstSeq)) return s;
      return a.more
        ? { ...s, loadingMore: false, moreError: a.error, cursorRefused: s.cursorRefused || isCursorRefusal(a.error) }
        : { ...s, loading: false, error: a.error };
    default:
      return s;
  }
}

/**
 * A new first page reaches the loaded list when nothing lies between them.
 * The page holds everything from its `until` down to its `next_cursor`; the
 * loaded list holds everything below `topUntil` (the `until` of the first
 * page it was built on; `until` is exclusive) down to its own cursor. The
 * two join when the page's cursor is not above `topUntil`: a cursor "<ms>"
 * (all older than ms still to come) joins at ms <= topUntil; a cursor
 * "<ms>:<id>" (more marks of that very millisecond still to come) joins only
 * at ms < topUntil, because the rest of that millisecond lies at or above
 * `topUntil` and is in neither list. A page without a cursor covers the
 * whole window and always joins.
 */
export function reaches(nextCursor: string | null, topUntil: number | null): boolean {
  if (nextCursor === null) return true;
  if (topUntil === null) return false;
  const [ms, id] = cursorPos(nextCursor);
  const top = Math.round(topUntil * 1000);
  return id === null ? ms <= top : ms < top;
}

/** An interval that began before `from` and is open or ended at or after it. */
export function reachesInto(m: { ts: number; end: number | null; endState: EndState | null }, from: number): boolean {
  return m.ts < from && (m.endState === 'open' || (m.endState !== null && m.end !== null && m.end >= from));
}

/** Automatic reload of the first page: visible page, at most every 60 s, never while off. */
export function shouldPoll(a: { visible: boolean; lastMs: number | null; nowMs: number; off: boolean }): boolean {
  if (a.off) return false;
  return shouldFetch({ visible: a.visible, lastMs: a.lastMs, nowMs: a.nowMs, intervalMs: POLL_MIN_MS });
}

// ── Client sessions (1.51.0, administrators only) ───────────────────────

export const SESSIONS_VIEW_TITLE = 'Client-Sitzungen';
export const TIMELINE_VIEW_TITLE = 'Zeitleiste';
export const SESSIONS_EMPTY_TEXT = 'Keine Client-Sitzungen im gewählten Zeitfenster.';
export const SESSIONS_CUT_TEXT = 'Weitere Sitzungen im Zeitfenster wurden gekürzt; Zeitfenster oder Filter enger wählen.';
export const SESSIONS_LOADING_TEXT = 'Client-Sitzungen werden geladen …';
export const CLIENTS_OFF_TITLE = 'Client-Verläufe sind ausgeschaltet.';
export const CLIENTS_OFF_HOW =
  'Einstellungen → Geräte & Dienste → OpenWrt Router → einen Router → Konfigurieren → ‚Client-Verläufe in der Time Machine‘ einschalten. Der Schalter gilt für alle Router und wirkt nur, solange Client-Stabilität läuft.';
/** What is kept, as docs/time-machine.md §15.2/§16.3 say (open sessions stay until they end). */
export const CLIENTS_PRIVACY =
  'Gespeichert werden Pseudonyme, keine MAC-Adressen, IP-Adressen oder Hostnamen. Abgeschlossene Sitzungen werden nach 14 Tagen gelöscht.';
export const UNAVAILABLE_TITLE = 'Client-Sitzungen sind noch nicht verfügbar.';
export const RECORDING_ON = 'Aufzeichnung läuft';
export const RECORDING_OFF = 'Aufzeichnung pausiert: Client-Stabilität liefert gerade nichts.';
export const DEFAULT_SESSION_FILTERS: SessionFilters = { window: DEFAULT_WINDOW, routerId: null, client: null };

function parseSession(v: unknown): Session | null {
  const m = obj(v);
  const id = str(m.id);
  const ts = fin(m.start);
  if (!id || ts === null) return null;
  const routerId = str(m.router_id);
  const band = fin(m.band);
  return {
    id,
    client: clientOf(m.client),
    clientName: str(m.client_name),
    routerId: routerId && ROUTER_ID_RE.test(routerId) ? routerId : null,
    routerName: str(m.router_name),
    ts,
    end: fin(m.end),
    endState: endStateOf(m.end_state),
    band: band !== null && [2.4, 5, 6].includes(band) ? band : null,
    params: parseParams(m.params),
    derived: m.derived === true,
  };
}

function compareSessions(a: Session, b: Session): number {
  return b.ts - a.ts || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** Newest start first, ties by id; each id once (the first one wins). */
export function dedupeSessions(items: readonly Session[]): Session[] {
  const seen = new Set<string>();
  const out: Session[] = [];
  for (const x of items) {
    if (seen.has(x.id)) continue;
    seen.add(x.id);
    out.push(x);
  }
  return out.sort(compareSessions);
}

export function parseSessions(v: unknown): SessionsAnswer {
  const b = obj(v);
  const w = obj(b.window);
  const items = Array.isArray(b.sessions) ? b.sessions.map(parseSession).filter((x): x is Session => x !== null) : [];
  return {
    status: str(b.status) ?? '',
    reason: str(b.reason),
    generatedAt: fin(b.generated_at),
    from: fin(w.from),
    until: fin(w.until),
    recording: b.recording === true,
    sessions: dedupeSessions(items),
    truncated: b.truncated === true,
    nextCursor: cursorOf(b.next_cursor),
  };
}

export function firstSessionQuery(f: SessionFilters, nowMs: number): SessionQuery {
  const until = Math.floor(nowMs / 1000) + 1;
  return {
    from: until - windowSeconds(f.window),
    until,
    client: f.client && CLIENT_RE.test(f.client) ? f.client : null,
    routerId: f.routerId && ROUTER_ID_RE.test(f.routerId) ? f.routerId : null,
    cursor: null,
  };
}

/** The next older page of sessions: the same window and filters, the cursor. */
export function olderSessionQuery(base: SessionQuery, cursor: string): SessionQuery {
  return { ...base, cursor };
}

/** Query string of …/sessions in a fixed order from checked values only. */
export function sessionQueryString(q: SessionQuery): string {
  const p = new URLSearchParams();
  p.set('from', epochText(q.from));
  p.set('until', epochText(q.until));
  if (q.client && CLIENT_RE.test(q.client)) p.set('client', q.client);
  if (q.routerId && ROUTER_ID_RE.test(q.routerId)) p.set('router_id', q.routerId);
  if (q.cursor && CURSOR_RE.test(q.cursor)) p.set('cursor', q.cursor);
  return p.toString();
}

export function sessionFilterKey(f: SessionFilters): string {
  return JSON.stringify([f.window, f.routerId, f.client]);
}

export interface SessionListState {
  gen: number;
  firstSeq: number;
  moreSeq: number;
  head: SessionsAnswer | null;
  sessions: Session[];
  older: boolean;
  nextCursor: string | null;
  cursorQuery: SessionQuery | null;
  topUntil: number | null;
  truncated: boolean;
  loading: boolean;
  loadingMore: boolean;
  error: unknown;
  moreError: unknown;
  restarted: boolean;
  /** As in ListState: the cursor was refused, no older page until a new first page. */
  cursorRefused: boolean;
}

export const SESSION_LIST_INIT: SessionListState = {
  gen: 0, firstSeq: 0, moreSeq: 0, head: null, sessions: [], older: false, nextCursor: null, cursorQuery: null,
  topUntil: null, truncated: false,
  loading: false, loadingMore: false, error: null, moreError: null, restarted: false, cursorRefused: false,
};

export type SessionListAction =
  | { type: 'filters' }
  | { type: 'dismiss' }
  | { type: 'start'; seq: number; more: boolean }
  | { type: 'first'; gen: number; seq: number; answer: SessionsAnswer; query: SessionQuery }
  | { type: 'older'; gen: number; seq: number; answer: SessionsAnswer }
  | { type: 'fail'; gen: number; seq: number; more: boolean; error: unknown };

/** The sessions list: the same rules as listReducer (stale answers, no silent gap). */
export function sessionReducer(s: SessionListState, a: SessionListAction): SessionListState {
  switch (a.type) {
    case 'filters':
      return { ...SESSION_LIST_INIT, gen: s.gen + 1, firstSeq: s.firstSeq, moreSeq: s.moreSeq, head: s.head, loading: true };
    case 'dismiss':
      return s.restarted ? { ...s, restarted: false } : s;
    case 'start':
      return a.more
        ? { ...s, moreSeq: a.seq, loadingMore: true, moreError: null }
        : { ...s, firstSeq: a.seq, loading: true };
    case 'first': {
      if (a.gen !== s.gen || a.seq !== s.firstSeq) return s;
      const t = a.answer;
      if (t.status !== 'ok') {
        return {
          ...s, head: t, sessions: [], older: false, nextCursor: null, cursorQuery: null, topUntil: null, truncated: false,
          loading: false, error: null, loadingMore: false, moreSeq: s.loadingMore ? -1 : s.moreSeq,
        };
      }
      // a refused cursor is never joined to: the new first page starts the list (no notice)
      const kept = (s.older || s.loadingMore) && !s.cursorRefused;
      if (!kept || !reaches(t.nextCursor, s.topUntil)) {
        const stop = s.loadingMore || s.cursorRefused ? { moreSeq: -1, loadingMore: false, moreError: null } : {};
        return {
          ...s, ...stop, head: t, sessions: t.sessions, older: false, nextCursor: t.nextCursor, cursorQuery: a.query,
          topUntil: a.query.until, truncated: t.truncated, loading: false, error: null, restarted: kept || s.restarted,
          cursorRefused: false,
        };
      }
      const from = t.from ?? a.query.from;
      const sessions = dedupeSessions([...t.sessions, ...s.sessions]).filter(x => x.ts >= from || reachesInto(x, from));
      return { ...s, head: t, sessions, topUntil: a.query.until, loading: false, error: null };
    }
    case 'older': {
      if (a.gen !== s.gen || a.seq !== s.moreSeq) return s;
      const t = a.answer;
      return {
        ...s, sessions: dedupeSessions([...s.sessions, ...t.sessions]), older: true, nextCursor: t.nextCursor,
        truncated: t.truncated, loadingMore: false, moreError: null,
      };
    }
    case 'fail':
      if (a.gen !== s.gen || a.seq !== (a.more ? s.moreSeq : s.firstSeq)) return s;
      return a.more
        ? { ...s, loadingMore: false, moreError: a.error, cursorRefused: s.cursorRefused || isCursorRefusal(a.error) }
        : { ...s, loading: false, error: a.error };
    default:
      return s;
  }
}

/** Automatic reload of the sessions: visible, at most every 60 s, only while they can come. */
export function shouldPollSessions(a: { visible: boolean; lastMs: number | null; nowMs: number; status: string | null }): boolean {
  if (a.status === 'off' || a.status === 'clients_off') return false;
  return shouldFetch({ visible: a.visible, lastMs: a.lastMs, nowMs: a.nowMs, intervalMs: POLL_MIN_MS });
}

export type ClientNames = Record<string, string | null>;

/** Clients seen in loaded sessions so far (kept while the client filter narrows the list). */
export function rememberClients(prev: ClientNames, items: readonly { client: string | null; clientName: string | null }[]): ClientNames {
  let next: ClientNames | null = null;
  for (const x of items) {
    if (!x.client) continue;
    const known = (next ?? prev)[x.client];
    if (known === undefined || (known === null && x.clientName) || (known && x.clientName && known !== x.clientName)) {
      next = next ?? { ...prev };
      next[x.client] = x.clientName;
    }
  }
  return next ?? prev;
}

/** Clients of loaded marks (the timeline's client filter, administrators only). */
export function rememberMarkClients(prev: ClientNames, marks: readonly Mark[]): ClientNames {
  return rememberClients(prev, marks);
}

export function clientOptions(names: ClientNames): { value: string; label: string }[] {
  return Object.entries(names)
    .map(([id, name]) => ({ value: id, label: clientLabel(id, name) }))
    .sort((a, b) => a.label.localeCompare(b.label, 'de') || a.value.localeCompare(b.value));
}

/** Remembered routers of loaded sessions (same shape as the timeline's). */
export function rememberSessionRouters(prev: RouterNames, items: readonly Session[]): RouterNames {
  return rememberRouters(prev, items as unknown as readonly Mark[]);
}

export const BAND_TEXT: Record<string, string> = { '2.4': '2,4 GHz', '5': '5 GHz', '6': '6 GHz' };

export function bandText(band: number | null | undefined): string | null {
  return band === null || band === undefined ? null : BAND_TEXT[String(band)] ?? null;
}

/** Duration column of a session: "Dauer …", "noch verbunden" or "Ende unbekannt". */
export function sessionDurationText(x: Pick<Session, 'ts' | 'end' | 'endState'>): string {
  if (x.endState === 'open') return 'noch verbunden';
  if (x.endState === 'closed' && x.end !== null) return `Dauer ${exactDuration(x.end - x.ts)}`;
  return 'Ende unbekannt';
}

export function roamText(params: Record<string, number>): string | null {
  const n = params.roam;
  return n !== undefined && n > 0 ? (n === 1 ? '1 Wechsel' : `${num(n)} Wechsel`) : null;
}

/** Days of sessions (newest start first), like dayGroups. */
export function sessionDays(items: readonly Session[], nowMs: number): { key: string; label: string; sessions: Session[] }[] {
  const out: { key: string; label: string; sessions: Session[] }[] = [];
  for (const x of [...items].sort(compareSessions)) {
    const key = dayKey(new Date(x.ts * 1000));
    const last = out[out.length - 1];
    if (last && last.key === key) last.sessions.push(x);
    else out.push({ key, label: dayLabel(x.ts, nowMs), sessions: [x] });
  }
  return out;
}

/** Why the sessions are not available, by the reasons the route sends (tmTexts.UNAVAILABLE_TEXT). */
export function unavailableText(reason: string | null): string {
  const why = reason ? UNAVAILABLE_TEXT[reason] : undefined;
  return `${UNAVAILABLE_TITLE} ${why ?? 'Grund unbekannt.'}`;
}

// ── Group filter (client side) ───────────────────────────────────────────

/** Groups present in the marks, in the fixed order (unknown ones last). */
export function groupsOf(marks: readonly Mark[]): string[] {
  const present = new Set(marks.map(m => m.group).filter(Boolean));
  const known = GROUP_ORDER.filter(g => present.has(g));
  const rest = [...present].filter(g => !GROUP_ORDER.includes(g)).sort();
  return [...known, ...rest];
}

export function visibleMarks(marks: readonly Mark[], hiddenGroups: readonly string[]): Mark[] {
  return hiddenGroups.length ? marks.filter(m => !hiddenGroups.includes(m.group)) : [...marks];
}

export function countText(shown: number, total: number): string {
  return `${num(shown)} von ${num(total)} ${total === 1 ? 'Marke' : 'Marken'}`;
}

// ── Routers of the select ───────────────────────────────────────────────

export type RouterNames = Record<string, string | null>;

/** Routers seen in loaded marks so far (kept while a router filter narrows the list). */
export function rememberRouters(prev: RouterNames, marks: readonly Mark[]): RouterNames {
  let next: RouterNames | null = null;
  for (const m of marks) {
    if (!m.routerId) continue;
    const known = (next ?? prev)[m.routerId];
    if (known === undefined || (known === null && m.routerName)) {
      next = next ?? { ...prev };
      next[m.routerId] = m.routerName;
    }
  }
  return next ?? prev;
}

export function routerOptionLabel(id: string, name: string | null | undefined): string {
  return name ? scrub(name) : routerLabel(id);
}

export function routerOptions(names: RouterNames): { value: string; label: string }[] {
  return Object.entries(names)
    .map(([id, name]) => ({ value: id, label: routerOptionLabel(id, name) }))
    .sort((a, b) => a.label.localeCompare(b.label, 'de') || a.value.localeCompare(b.value));
}

// ── Texts of one mark ────────────────────────────────────────────────────

/** Title of a mark (see the fallback rule in tmTexts.ts). */
export function titleOf(m: Pick<Mark, 'titleKey' | 'text' | 'source' | 'kind'> & { code?: string | null }): string {
  // the own index names a code variant first (`<key>.<code>`)
  const variant = m.code && (m.source === 'tm_index' || m.source === 'tm_clients') ? TITLE_TEXT[`${m.titleKey}.${m.code}`] : undefined;
  const known = variant ?? TITLE_TEXT[m.titleKey];
  const title = known ?? (m.text ? scrub(m.text) : `Code ${KEY_RE.test(m.titleKey) ? m.titleKey : 'unbekannt'}`);
  if (m.source === 'ni_incidents') {
    return `${m.kind === 'incident_resolved' ? 'Vorfall behoben' : 'Vorfall eröffnet'}: ${title}`;
  }
  return title;
}

/** True when the title is the fallback (no German text for the key). */
export function isFallbackTitle(titleKey: string): boolean {
  return TITLE_TEXT[titleKey] === undefined;
}

/** The numbers of `params` in plain words, known keys only, in a fixed order. */
export function paramsText(params: Record<string, number>): string | null {
  const parts: string[] = [];
  const fmt = (v: number) => (Number.isInteger(v) ? num(v) : num(v, 1));
  for (const key of Object.keys(PARAM_TEXT)) {
    const v = params[key];
    if (v === undefined || !Number.isFinite(v)) continue;
    if (v === 0 && key !== 'changes') continue;
    // "Kanal 36 → 100": the *_to value goes with its *_from
    if (key.endsWith('_to') && params[`${key.slice(0, -3)}_from`] !== undefined) continue;
    if (v === 1 && PARAM_ONE[key]) {
      parts.push(PARAM_ONE[key]);
      continue;
    }
    const to = key.endsWith('_from') ? params[`${key.slice(0, -5)}_to`] : undefined;
    const text = PARAM_TEXT[key];
    if (text.includes('{g}') && bandText(v) === null) continue;
    if (text.includes('{to}') && to === undefined) {
      parts.push(fmt(v));
      continue;
    }
    parts.push(text
      .replace('{n}', fmt(v))
      .replace('{to}', to === undefined ? '' : fmt(to))
      .replace('{d}', durationText(v))
      .replace('{D}', exactDuration(Math.abs(v)))
      .replace('{g}', bandText(v) ?? ''));
  }
  return parts.length ? parts.join(' · ') : null;
}

/** A duration to the second, short: "12 s", "4 min 12 s", "2 Std. 5 min", "3 Tage 4 Std.". */
export function exactDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return DASH;
  const t = Math.round(seconds);
  const d = Math.floor(t / 86_400);
  const h = Math.floor((t % 86_400) / 3600);
  const m = Math.floor((t % 3600) / 60);
  const sec = t % 60;
  if (d > 0) return h ? `${d} ${d === 1 ? 'Tag' : 'Tage'} ${h} Std.` : `${d} ${d === 1 ? 'Tag' : 'Tage'}`;
  if (h > 0) return m ? `${h} Std. ${m} min` : `${h} Std.`;
  if (m > 0) return sec ? `${m} min ${sec} s` : `${m} min`;
  return `${sec} s`;
}

/** Start of an interval as date and time (local), "20.11.2026, 14:03". */
export function startText(ts: number): string {
  const d = new Date(ts * 1000);
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** The duration of an interval mark: closed, open or with an unknown end; null for a point. */
export function intervalText(m: Pick<Mark, 'ts' | 'end' | 'endState'>, nowMs: number): string | null {
  switch (m.endState) {
    case 'closed':
      return m.end !== null ? `Dauer ${exactDuration(m.end - m.ts)}` : 'Ende unbekannt';
    case 'open': {
      const d = new Date(m.ts * 1000);
      const today = dayKey(d) === dayKey(new Date(nowMs));
      const at = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
      return `seit ${today ? at : `${pad(d.getDate())}.${pad(d.getMonth() + 1)}., ${at}`}, noch offen`;
    }
    case 'unknown':
      return 'Ende unbekannt';
    default:
      return null;
  }
}

/** "Client <name>" with the server's name, else "Client ·" and the pseudonym's last six characters. */
export function clientLabel(client: string | null, name: string | null): string {
  if (name) return `Client ${scrub(name)}`;
  if (client && CLIENT_RE.test(client)) return `Client ·${client.slice(-6)}`;
  return 'Client unbekannt';
}

export function clientText(m: Pick<Mark, 'client' | 'clientName'>): string | null {
  return m.client || m.clientName ? clientLabel(m.client, m.clientName) : null;
}

function peerText(p: Peer): string {
  return p.routerId ? routerOptionLabel(p.routerId, p.routerName) : p.routerName ? scrub(p.routerName) : 'unbekanntem Router';
}

/** "von Router 1 nach Router 2" (roam, uplink); null without peers. */
export function peersText(m: Pick<Mark, 'peers'>): string | null {
  const p = m.peers;
  if (!p) return null;
  if (p.before && p.after) return `von ${peerText(p.before)} nach ${peerText(p.after)}`;
  if (p.after) return `nach ${peerText(p.after)}`;
  return p.before ? `von ${peerText(p.before)}` : null;
}

/**
 * The duration of a mark in the block "Läuft seit vor dem Zeitfenster": its
 * start already stands in the time column, so an open one says how long it
 * has run ("noch offen, bisher 2 Tage 3 Std."), a closed one its duration.
 */
export function spanText(m: Pick<Mark, 'ts' | 'end' | 'endState'>, nowMs: number): string | null {
  if (m.endState === 'open') return `noch offen, bisher ${exactDuration(nowMs / 1000 - m.ts)}`;
  return intervalText(m, nowMs);
}

/** The full pseudonym for the title of a client label ("tmc_…"), nothing else; null without one. */
export function clientTitle(client: string | null): string | null {
  return client && CLIENT_RE.test(client) ? client : null;
}

/**
 * The second line of a mark: client, peers, duration and numbers, in this
 * order. `client: false` leaves the client out (the row shows it as its own
 * label with the pseudonym as title); `inBlock` uses spanText.
 */
export function detailText(m: Mark, nowMs: number, opts: { client?: boolean; inBlock?: boolean } = {}): string | null {
  const parts = [
    opts.client === false ? null : clientText(m),
    peersText(m),
    opts.inBlock ? spanText(m, nowMs) : intervalText(m, nowMs),
    paramsText(m.params),
  ].filter((x): x is string => !!x);
  return parts.length ? parts.join(' · ') : null;
}

export function routerText(m: Pick<Mark, 'fleet' | 'routerId' | 'routerName'>): string {
  if (m.fleet) return 'alle Router';
  if (m.routerId) return routerOptionLabel(m.routerId, m.routerName);
  return 'ohne Router';
}

export function sourceText(id: string): string {
  return SOURCE_TEXT[id] ?? 'Quelle unbekannt';
}

export function groupText(group: string): string {
  return GROUP_TEXT[group] ?? 'Sonstiges';
}

export function severityView(s: Severity): { label: string; tone: Tone } {
  const label = SEVERITY_TEXT[s] ?? SEVERITY_TEXT.info;
  return { label, tone: s === 'critical' ? 'critical' : s === 'warning' ? 'warn' : 'info' };
}

export function reasonText(reason: string | null): string {
  return reason ? REASON_TEXT[reason] ?? 'Grund unbekannt' : 'Grund unbekannt';
}

/** One pill of the sources row: state as words (never colour alone), never green. */
export function sourcePill(s: SourceInfo): { name: string; text: string; tone: Tone; title?: string } {
  let text: string;
  let tone: Tone = 'muted';
  // a cut source is never "empty": what lies below its cut is not read yet
  const state = s.state === 'empty' && s.truncated ? 'ok' : s.state;
  switch (state) {
    case 'ok':
      text = `${num(s.count)} ${s.count === 1 ? 'Marke' : 'Marken'}`;
      tone = 'info';
      break;
    case 'empty':
      text = STATE_TEXT.empty;
      break;
    case 'off':
      text = `${STATE_TEXT.off} · ${reasonText(s.reason)}`;
      break;
    case 'unreadable':
      text = `${STATE_TEXT.unreadable} · ${reasonText(s.reason)}`;
      tone = 'warn';
      break;
    default:
      text = 'Zustand unbekannt';
  }
  if (s.truncated) text += s.cut === 'unreachable' ? ' · gekürzt, Älteres nicht abrufbar' : ' · gekürzt';
  // doubles of another source: short in the pill, the whole sentence as tooltip
  const dup = s.duplicates ?? 0;
  if (dup > 0) {
    text += ` · ${num(dup)} doppelt`;
    return { name: sourceText(s.id), text, tone, title: `${num(dup)} doppelt ausgeblendet` };
  }
  return { name: sourceText(s.id), text, tone };
}

/** Sources the server does not show to this user (chip greyed out, not selectable). */
export function adminOnlySources(head: Timeline | null): string[] {
  return (head?.sources ?? []).filter(s => s.state === 'off' && s.reason === 'admin_only').map(s => s.id);
}

// Relies on the server sending omitted_client_marks = 0 to non-admins
// (tm_query.merge: only administrators get that count); the tab does not
// check the user's role here itself.
export function omittedText(n: number, clientsOff = false): string | null {
  if (!(n > 0)) return null;
  const what = n === 1 ? 'client-bezogenes Ereignis ist' : 'client-bezogene Ereignisse sind';
  const how = clientsOff ? ' Client-Verläufe lassen sich in den Optionen einschalten.' : '';
  return `${num(n)} ${what} ausgeblendet.${how}`;
}

/** The client switch is off (the source `tm_clients` says `clients_off`). */
export function clientsOff(head: Timeline | null): boolean {
  return (head?.sources ?? []).some(s => s.id === 'tm_clients' && s.state === 'off' && s.reason === 'clients_off');
}

// ── Time (local time of the browser) ─────────────────────────────────────

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

/** HH:MM:SS in local time. */
export function timeText(ts: number): string {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** Full ISO instant in UTC (title attribute). */
export function isoUtc(ts: number): string {
  const d = new Date(ts * 1000);
  return Number.isNaN(d.getTime()) ? DASH : d.toISOString();
}

/** "Stand TT.MM.JJ, HH:MM" of generated_at, local time. */
export function standText(ts: number | null): string {
  if (ts === null || !Number.isFinite(ts) || ts <= 0) return `Stand ${DASH}`;
  const d = new Date(ts * 1000);
  return `Stand ${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${pad(d.getFullYear() % 100)}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const WEEKDAYS = ['Sonntag', 'Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag'];

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** "Heute", "Gestern", else "Wochentag, TT.MM.JJJJ" (local calendar days, DST safe). */
export function dayLabel(ts: number, nowMs: number): string {
  const d = new Date(ts * 1000);
  const now = new Date(nowMs);
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
  if (dayKey(d) === dayKey(today)) return 'Heute';
  if (dayKey(d) === dayKey(yesterday)) return 'Gestern';
  return `${WEEKDAYS[d.getDay()]}, ${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
}

export interface DayGroup {
  key: string;
  label: string;
  marks: Mark[];
}

/** Marks (newest first) grouped by their local calendar day. */
export function dayGroups(marks: readonly Mark[], nowMs: number): DayGroup[] {
  const out: DayGroup[] = [];
  for (const m of [...marks].sort(compareMarks)) {
    const key = dayKey(new Date(m.ts * 1000));
    const last = out[out.length - 1];
    if (last && last.key === key) last.marks.push(m);
    else out.push({ key, label: dayLabel(m.ts, nowMs), marks: [m] });
  }
  return out;
}

// ── Errors ───────────────────────────────────────────────────────────────

/** 400 with field `cursor`: sending the same cursor again would be refused again. */
export function isCursorRefusal(err: unknown): boolean {
  return err instanceof TmApiError && err.status === 400 && err.details?.field === 'cursor';
}

export class TmApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly details: { field?: string; reason?: string };

  constructor(status: number | null, code: string, details: { field?: string; reason?: string } = {}) {
    super(`time machine api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'TmApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const FIELD_TEXT: Record<string, string> = {
  from: 'Zeitfenster', until: 'Zeitfenster', window: 'Zeitfenster', source: 'Quelle', router_id: 'Router',
  kind: 'Art', min_severity: 'Schwere', limit: 'Seitengröße', query: 'Abfrage', body: 'Anfrage', client: 'Client',
  cursor: 'Blätterstelle', spans: 'Abfrage',
};

export interface ErrorInfo {
  kind: 'forbidden' | 'gone' | 'invalid' | 'failed' | 'refused';
  message: string;
  retry: boolean;
  /** The field the server named (shown next to that field: at, t1, t2, window). */
  field?: string;
}

export type ErrorOf = 'timeline' | 'sessions' | 'state' | 'compare' | 'export';

export const FAILED_TEXT = 'Die Zeitleiste konnte nicht geladen werden.';
export const SESSIONS_FAILED_TEXT = 'Die Client-Sitzungen konnten nicht geladen werden.';
export const STATE_FAILED_TEXT = 'Der Zustand konnte nicht geladen werden.';
export const COMPARE_FAILED_TEXT = 'Der Vergleich konnte nicht geladen werden.';
export const EXPORT_FAILED_TEXT = 'Der Export ist fehlgeschlagen.';
export const EXPORT_REFUSED_TEXT = 'Export nicht möglich: Das Audit-Protokoll ist nicht verfügbar.';
const FAILED_OF: Record<ErrorOf, string> = {
  timeline: FAILED_TEXT, sessions: SESSIONS_FAILED_TEXT, state: STATE_FAILED_TEXT, compare: COMPARE_FAILED_TEXT,
  export: EXPORT_FAILED_TEXT,
};
const FORBIDDEN_OF: Record<ErrorOf, string> = {
  timeline: 'Keine Berechtigung für die Zeitreise.',
  sessions: 'Keine Berechtigung für die Client-Sitzungen (nur Administratoren).',
  state: 'Keine Berechtigung für die Zeitreise.',
  compare: 'Keine Berechtigung für die Zeitreise.',
  export: 'Keine Berechtigung für den Export (nur Administratoren).',
};

/** 400 of …/state and …/compare in plain words, by field and reason (1.52.0). */
function momentError(field: string | undefined, reason: string | undefined): string | null {
  switch (field) {
    case 'at':
      return reason === 'out_of_range' ? 'Der Zeitpunkt liegt in der Zukunft. Bitte einen früheren wählen.' : 'Ungültiger Zeitpunkt.';
    case 't1':
      return reason === 'missing' ? 'Bitte „Von“ angeben.' : reason === 'out_of_range' ? '„Von“ liegt in der Zukunft.' : 'Ungültiger Wert bei „Von“.';
    case 't2':
      return reason === 'missing' ? 'Bitte „Bis“ angeben.' : reason === 'out_of_range' ? '„Bis“ liegt in der Zukunft.' : 'Ungültiger Wert bei „Bis“.';
    case 'window':
      return reason === 'empty' ? '„Bis“ muss nach „Von“ liegen.'
        : reason === 'too_large' ? 'Zwischen „Von“ und „Bis“ liegen höchstens 14 Tage.' : 'Ungültiger Zeitraum.';
    case 'clients_cursor':
      return 'Die Stelle zum Weiterladen der Clients ist nicht mehr gültig. Bitte „Aktualisieren“.';
    default:
      return null;
  }
}

/** The message of an error: from status and code only, never the server's text. */
export function errorInfo(err: unknown, of: ErrorOf = 'timeline'): ErrorInfo {
  const failed = FAILED_OF[of];
  if (!(err instanceof TmApiError)) return { kind: 'failed', message: failed, retry: true };
  switch (err.status) {
    case 401:
    case 403:
      return { kind: 'forbidden', message: FORBIDDEN_OF[of], retry: false };
    case 410:
      return { kind: 'gone', message: 'Die Integration wurde entladen.', retry: false };
    case 503:
      if (of === 'export' && err.details.reason === 'audit_unavailable') {
        return { kind: 'refused', message: EXPORT_REFUSED_TEXT, retry: true };
      }
      return { kind: 'failed', message: failed, retry: true };
    case 400: {
      if (err.details.field === 'cursor') {
        // only an older page sends a cursor: the list moved on, a refresh starts it anew
        return {
          kind: 'invalid',
          message: err.details.reason === 'out_of_range'
            ? 'Die Stelle zum Weiterblättern liegt nicht mehr im Zeitfenster. Bitte „Aktualisieren“.'
            : 'Ungültige Stelle zum Weiterblättern. Bitte „Aktualisieren“.',
          retry: false,
        };
      }
      if (of === 'state' || of === 'compare') {
        const text = momentError(err.details.field, err.details.reason);
        if (text) return { kind: 'invalid', message: text, retry: false, field: err.details.field };
      }
      const field = err.details.field ? FIELD_TEXT[err.details.field] ?? 'unbekannt' : null;
      return { kind: 'invalid', message: `Ungültige Filterkombination.${field ? ` Feld: ${field}.` : ''}`, retry: false };
    }
    default:
      return { kind: 'failed', message: failed, retry: true };
  }
}
