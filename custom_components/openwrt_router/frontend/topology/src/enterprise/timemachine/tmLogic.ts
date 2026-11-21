/**
 * tmLogic.ts — pure logic of the "Zeitreise" tab (Network Time Machine,
 * Phase A, read only).
 *
 * Parser of the server answer, the query of a page, the state of the loaded
 * list (first page, older pages, dropped stale answers), the client-side
 * group filter, the days in local time and every German text the view
 * shows. No React, no DOM, no network: node --test imports it.
 *
 * Rules kept here:
 *  - Titles come from TITLE_TEXT; without an entry the server's (masked)
 *    `text`, else "Code <title_key>". Network Intelligence incidents say in
 *    front whether the incident was opened or resolved.
 *  - Only known number parameters are shown; nothing here builds or shows a
 *    MAC or IP address, a host name or an interface name.
 *  - An empty timeline is never an all-clear: no green, no tick.
 *  - The tab only reads; nothing here builds a write.
 */

import { num } from '../../utils/format.ts';
import { durationText, scrub } from '../traffic/trafficLogic.ts';
import { DASH, POLL_MIN_MS, pollDelay, routerLabel, shouldFetch } from '../wifi/wifiLogic.ts';
import { GROUP_TEXT, PARAM_ONE, PARAM_TEXT, REASON_TEXT, SEVERITY_TEXT, SOURCE_TEXT, STATE_TEXT, TITLE_TEXT } from './tmTexts.ts';
import type { Filters, Mark, Severity, SourceInfo, Timeline, TimelineQuery, Tone } from './tmTypes';

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
/** A page without marks that goes on (only left-out entries in this part of the window). */
export const HIDDEN_ONLY_TEXT = 'In diesem Abschnitt gibt es nur ausgeblendete Einträge. Ältere laden, um weiter zurückzugehen.';

export const SOURCE_IDS: readonly string[] = ['core_audit', 'config_versions', 'ni_events', 'ni_incidents', 'security_timeline'];
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

export const DEFAULT_FILTERS: Filters = { window: DEFAULT_WINDOW, sourcesOff: [], severity: 'all', routerId: null };

const ROUTER_ID_RE = /^rtr_[0-9a-f]{32}$/;
const KEY_RE = /^[a-z0-9_.]{1,200}$/;
const MARK_ID_RE = /^tmm_[0-9a-f]{16}$/;

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
  };
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
    nextUntil: fin(b.next_until),
  };
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
  const until = Math.floor(nowMs / 1000) + 1;
  const picked = SOURCE_IDS.filter(s => !f.sourcesOff.includes(s) || disabled.includes(s));
  if (!picked.some(s => !disabled.includes(s))) return null;
  return {
    from: until - windowSeconds(f.window),
    until,
    sources: picked.length === SOURCE_IDS.length ? null : picked,
    minSeverity: f.severity === 'all' ? null : f.severity,
    routerId: f.routerId && ROUTER_ID_RE.test(f.routerId) ? f.routerId : null,
  };
}

/** The next older page: same filters and `from`, `until` = the server's next_until. */
export function olderQuery(first: TimelineQuery, from: number | null, nextUntil: number): TimelineQuery {
  return { ...first, from: from ?? first.from, until: nextUntil };
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
  return p.toString();
}

/** A stable key of what the server is asked (a change starts a new list). */
export function filterKey(f: Filters): string {
  return JSON.stringify([f.window, [...f.sourcesOff].sort(), f.severity, f.routerId]);
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
  nextUntil: number | null;
  truncated: boolean;
  loading: boolean;
  loadingMore: boolean;
  error: unknown;
  moreError: unknown;
}

export const LIST_INIT: ListState = {
  gen: 0, firstSeq: 0, moreSeq: 0, head: null, marks: [], older: false, nextUntil: null, truncated: false,
  loading: false, loadingMore: false, error: null, moreError: null,
};

export type ListAction =
  | { type: 'filters' }
  | { type: 'start'; seq: number; more: boolean }
  | { type: 'first'; gen: number; seq: number; answer: Timeline }
  | { type: 'older'; gen: number; seq: number; answer: Timeline }
  | { type: 'fail'; gen: number; seq: number; more: boolean; error: unknown };

/**
 * One step of the loaded list. A filter change starts a new generation and
 * empties the list; an answer of an older generation or an older request is
 * dropped, so a stale answer never overwrites a newer one. A new first page
 * replaces the list, or — when older pages are loaded or one is being loaded —
 * puts its marks in front of them (deduplicated) and keeps their next_until.
 * It goes in front only when it reaches the list (it ends at or below the
 * newest loaded mark or the end of the previous first page); otherwise it
 * starts the list anew and drops a pending older page, so the list never
 * has a silent gap (review K3).
 */
export function listReducer(s: ListState, a: ListAction): ListState {
  switch (a.type) {
    case 'filters':
      // loading at once: the empty list of a new filter is never shown as "no marks"
      return { ...LIST_INIT, gen: s.gen + 1, firstSeq: s.firstSeq, moreSeq: s.moreSeq, head: s.head, loading: true };
    case 'start':
      return a.more
        ? { ...s, moreSeq: a.seq, loadingMore: true, moreError: null }
        : { ...s, firstSeq: a.seq, loading: true };
    case 'first': {
      if (a.gen !== s.gen || a.seq !== s.firstSeq) return s;
      const t = a.answer;
      if (t.status === 'off') {
        return { ...s, head: t, marks: [], older: false, nextUntil: null, truncated: false, loading: false, error: null };
      }
      if (!(s.older || s.loadingMore) || !reaches(t, s)) {
        const stop = s.loadingMore ? { moreSeq: -1, loadingMore: false, moreError: null } : {};
        return {
          ...s, ...stop, head: t, marks: t.marks, older: false, nextUntil: t.nextUntil, truncated: t.truncated,
          loading: false, error: null,
        };
      }
      const from = t.from ?? -Infinity;
      const marks = mergeMarks(t.marks, s.marks).filter(m => m.ts >= from);
      return { ...s, head: t, marks, loading: false, error: null };
    }
    case 'older': {
      if (a.gen !== s.gen || a.seq !== s.moreSeq) return s;
      const t = a.answer;
      return {
        ...s, marks: mergeMarks(s.marks, t.marks), older: true, nextUntil: t.nextUntil, truncated: t.truncated,
        loadingMore: false, moreError: null,
      };
    }
    case 'fail':
      if (a.gen !== s.gen || a.seq !== (a.more ? s.moreSeq : s.firstSeq)) return s;
      return a.more ? { ...s, loadingMore: false, moreError: a.error } : { ...s, loading: false, error: a.error };
    default:
      return s;
  }
}

/** A first page reaches the loaded list: nothing lies between the two. */
function reaches(t: Timeline, s: ListState): boolean {
  if (t.nextUntil === null) return true;
  const top = Math.max(s.marks.length ? s.marks[0].ts : -Infinity, s.head?.until ?? -Infinity);
  return t.nextUntil <= top;
}

/** Automatic reload of the first page: visible page, at most every 60 s, never while off. */
export function shouldPoll(a: { visible: boolean; lastMs: number | null; nowMs: number; off: boolean }): boolean {
  if (a.off) return false;
  return shouldFetch({ visible: a.visible, lastMs: a.lastMs, nowMs: a.nowMs, intervalMs: POLL_MIN_MS });
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
export function titleOf(m: Pick<Mark, 'titleKey' | 'text' | 'source' | 'kind'>): string {
  const known = TITLE_TEXT[m.titleKey];
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
  for (const key of Object.keys(PARAM_TEXT)) {
    const v = params[key];
    if (v === undefined || !Number.isFinite(v)) continue;
    if (v === 0 && key !== 'changes') continue;
    if (v === 1 && PARAM_ONE[key]) {
      parts.push(PARAM_ONE[key]);
      continue;
    }
    const n = Number.isInteger(v) ? num(v) : num(v, 1);
    parts.push(PARAM_TEXT[key].replace('{n}', n).replace('{d}', durationText(v)));
  }
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
export function sourcePill(s: SourceInfo): { name: string; text: string; tone: Tone } {
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
  return { name: sourceText(s.id), text, tone };
}

/** Sources the server does not show to this user (chip greyed out, not selectable). */
export function adminOnlySources(head: Timeline | null): string[] {
  return (head?.sources ?? []).filter(s => s.state === 'off' && s.reason === 'admin_only').map(s => s.id);
}

// Relies on the server sending omitted_client_marks = 0 to non-admins
// (tm_query.merge: only administrators get that count); the tab does not
// check the user's role here itself.
export function omittedText(n: number): string | null {
  if (!(n > 0)) return null;
  const what = n === 1 ? 'client-bezogenes Ereignis ist' : 'client-bezogene Ereignisse sind';
  return `${num(n)} ${what} ausgeblendet. Client-Verläufe kommen mit einem eigenen Schalter in einer späteren Version.`;
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
  kind: 'Art', min_severity: 'Schwere', limit: 'Seitengröße', query: 'Abfrage', body: 'Anfrage',
};

export interface ErrorInfo {
  kind: 'forbidden' | 'gone' | 'invalid' | 'failed';
  message: string;
  retry: boolean;
}

export const FAILED_TEXT = 'Die Zeitleiste konnte nicht geladen werden.';

/** The message of an error: from status and code only, never the server's text. */
export function errorInfo(err: unknown): ErrorInfo {
  if (!(err instanceof TmApiError)) return { kind: 'failed', message: FAILED_TEXT, retry: true };
  switch (err.status) {
    case 401:
    case 403:
      return { kind: 'forbidden', message: 'Keine Berechtigung für die Zeitreise.', retry: false };
    case 410:
      return { kind: 'gone', message: 'Die Integration wurde entladen.', retry: false };
    case 400: {
      const field = err.details.field ? FIELD_TEXT[err.details.field] ?? 'unbekannt' : null;
      return { kind: 'invalid', message: `Ungültige Filterkombination.${field ? ` Feld: ${field}.` : ''}`, retry: false };
    }
    default:
      return { kind: 'failed', message: FAILED_TEXT, retry: true };
  }
}
