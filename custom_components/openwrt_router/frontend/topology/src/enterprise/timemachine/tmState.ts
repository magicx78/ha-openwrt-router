/**
 * tmState.ts — pure logic of the views "Zustand" and "Vergleich" of the
 * "Zeitreise" tab, of its export and of its jumps into other Enterprise tabs
 * (Network Time Machine, Phases D–F, 1.52.0, read only).
 *
 * Parser of GET …/state and …/compare (docs/time-machine.md §20–§22), the
 * query strings of both and of …/export, the local time of the
 * `datetime-local` fields, the loaded states (stale answers dropped, the
 * client list paged with `clients_cursor`), the rows of the comparison, and
 * where an entry leads (§23, a copy of tm_sources.JUMP_TARGETS checked by
 * tests/test_tm_panel_texts_v1520.py). No React, no DOM, no network.
 *
 * Rules kept here:
 *  - A value with a `reason` is unknown: its value is never shown, only
 *    "unbekannt" and the reason. Unknown is never green or red; "nicht
 *    erreichbar" is a warning, in words.
 *  - Nothing here builds or shows a MAC, IP address, host name or interface
 *    name; a client is shown by the server's name or its pseudonym's end.
 *  - A comparison only says "nothing changed" when both states are known and
 *    nothing differs or happened in between.
 */

import { num } from '../../utils/format.ts';
import { fmtRate, scrub } from '../traffic/trafficLogic.ts';
import {
  CLIENT_RE, CUSTOM_WINDOW, ROUTER_ID_RE, TAB_ID, bandText, clientLabel, cursorOf, isoUtc, parseMark, refOf,
  routerOptionLabel, startText,
} from './tmLogic.ts';
import {
  EXPORT_UNAVAILABLE_TEXT, GLOBAL_REASON_TEXT, JUMP_KIND_TAB, JUMP_OBJECT, JUMP_REF_TAB, JUMP_TAB_TEXT, PART_STATE_TEXT, RADIO_BAND_TEXT,
  RADIO_STATE_TEXT, ROLE_TEXT, SOURCE_TEXT, STATE_REASON_TEXT, TITLE_TEXT,
} from './tmTexts.ts';
import type {
  Change, ClientItem, ClientsPart, CompareAnswer, CompareQuery, ConfigItem, IncidentItem, JumpTarget, Known, Mark,
  OtherSources, Part, RadioChange, RadioItem, RouterChange, RouterState, Severity, StateAnswer, StateQuery, TrafficWan, UplinkValue,
  UtilizationRadio,
} from './tmTypes';

export { CUSTOM_WINDOW };

// ── Texts ────────────────────────────────────────────────────────────────

export const STATE_VIEW_TITLE = 'Zustand';
export const COMPARE_VIEW_TITLE = 'Vergleich';
export const STATE_LOADING_TEXT = 'Zustand wird geladen …';
export const COMPARE_LOADING_TEXT = 'Vergleich wird geladen …';
export const UNKNOWN = 'unbekannt';
export const UNKNOWN_TITLE = 'Für diesen Zeitpunkt ist kein Zustand bekannt.';
export const DERIVED_TITLE = 'Aus aufgezeichneten Ereignissen erschlossen, nicht direkt gemessen.';
export const STATE_UNAVAILABLE_TEXT = 'Der Zustand ist noch nicht verfügbar.';
export const NOTHING_CHANGED = 'Zwischen diesen Zeitpunkten hat sich nichts geändert.';
export const SAME_BUT_EVENTS = 'Die Zustände zu beiden Zeitpunkten sind gleich; dazwischen gab es Ereignisse.';
/** Other sources of the window could not be read (or the server sent none): nothing is "unchanged". */
export const OTHER_UNKNOWN_ONE = 'Ob dazwischen etwas geschah, ist unbekannt: Eine Quelle ließ sich nicht lesen.';
export const OTHER_UNKNOWN_MANY = 'Ob dazwischen etwas geschah, ist unbekannt: Mehrere Quellen ließen sich nicht lesen.';
export const OTHER_UNKNOWN_NONE = 'Ob dazwischen etwas geschah, ist unbekannt: Die anderen Module wurden nicht gelesen.';
/** A part of the state the server could not read (traffic, utilization, versions, incidents). */
export const PART_UNREADABLE_TEXT = 'Konnte nicht gelesen werden.';
/** Radios `partial` with reason not_observed (one stayed off across a restart). */
export const RADIOS_NOT_OBSERVED_TEXT = 'Nicht alle Funkmodule sind bekannt: Eines blieb über einen Neustart aus.';
/** Field errors and notes of a local time on a clock change (Europe/Berlin and the like). */
export const LOCAL_GAP_TEXT = 'Diese Uhrzeit gibt es wegen der Zeitumstellung nicht.';
export const LOCAL_TWICE_TEXT = 'Diese Uhrzeit gibt es wegen der Zeitumstellung zweimal; gezeigt wird die erste.';
export const COMPARE_PICK_TEXT = '„Von“ und „Bis“ wählen.';
export const STATE_PICK_TEXT = 'Einen Zeitpunkt wählen.';
export const EXPORT_CONFIRM_TEXT =
  'Der Export enthält die Marken des gewählten Zeitfensters ohne Namen und ohne Client-Verläufe. Er wird im Audit-Protokoll vermerkt.';
export const EXPORT_FILENAME = 'openwrt-router-time-machine.json';

/** "4 Client-Einträge sind nicht enthalten." after an export (omitted_client_marks, the whole window); null at 0. */
export function exportOmittedText(n: number | null): string | null {
  if (n === null || !(n > 0)) return null;
  return n === 1 ? '1 Client-Eintrag ist nicht enthalten.' : `${num(n)} Client-Einträge sind nicht enthalten.`;
}

/** An export answer without a mark (browser check before the merge): no file is saved, this says so. */
export const EXPORT_EMPTY_TITLE = 'Nichts zu exportieren, es wurde keine Datei gespeichert.';
/** The same on a later page of a cut export (the pages before it stay saved). */
export const EXPORT_EMPTY_MORE = 'Keine weiteren Marken, es wurde keine weitere Datei gespeichert.';
export const EXPORT_OFF_TEXT = 'Die Zeitreise ist ausgeschaltet.';
export const EXPORT_UNAVAILABLE_OTHER = 'Die Zeitreise ist gerade nicht verfügbar.';
export const EXPORT_NO_MARKS_TEXT = 'Im gewählten Zeitfenster gibt es mit den gewählten Filtern keine exportierbaren Marken.';
export const EXPORT_PARTIAL_TEXT = 'Mindestens eine Quelle ließ sich nicht lesen.';

/**
 * Null when an export answer has something to save (a mark or an interval
 * reaching into the window); else the message shown instead of saving a
 * file: that there is nothing, and why when the answer says it (the Time
 * Machine off, not running or still loading; nothing in the window and its
 * filters, a source unreadable, only client marks, which are never exported).
 * `page` > 1: a later page of a cut export.
 */
export function exportEmptyText(file: { status: string; reason: string | null; marks: number; spanning: number; omittedClientMarks: number },
  page = 1): string | null {
  if (file.marks > 0 || file.spanning > 0) return null;
  const why: string[] = [];
  if (file.status === 'off') why.push(EXPORT_OFF_TEXT);
  else if (file.status === 'unavailable') why.push((file.reason ? EXPORT_UNAVAILABLE_TEXT[file.reason] : undefined) ?? EXPORT_UNAVAILABLE_OTHER);
  else if (page <= 1 && (file.status === 'ok' || file.status === 'partial')) {
    why.push(EXPORT_NO_MARKS_TEXT);
    if (file.status === 'partial') why.push(EXPORT_PARTIAL_TEXT);
    const n = file.omittedClientMarks;
    if (n > 0) why.push(n === 1 ? '1 Client-Eintrag wird nie exportiert.' : `${num(n)} Client-Einträge werden nie exportiert.`);
  }
  return [page > 1 ? EXPORT_EMPTY_MORE : EXPORT_EMPTY_TITLE, ...why].join(' ');
}

/**
 * A key in the export confirmation (role alertdialog, browser review):
 * Escape cancels, Tab and Shift+Tab go round its buttons and never leave it.
 * `index` is the focused button (-1: none of them), `count` how many there are.
 */
export function dialogKey(key: string, shift: boolean, index: number, count: number):
  { action: 'cancel' } | { action: 'focus'; index: number } | null {
  if (key === 'Escape' || key === 'Esc') return { action: 'cancel' };
  if (key !== 'Tab' || count <= 0) return null;
  if (index < 0) return { action: 'focus', index: shift ? count - 1 : 0 };
  return { action: 'focus', index: (index + (shift ? count - 1 : 1)) % count };
}

/**
 * The element that has the focus where `node` lives (browser review: the
 * panel is in a Shadow DOM, where `document.activeElement` is only the shadow
 * host, so Tab never found the focused button). The node's root is a
 * ShadowRoot or the Document; both have `activeElement`. No node: the document's.
 */
export function activeIn(node: { getRootNode?: () => unknown } | null | undefined,
  doc: { activeElement: Element | null } | null = typeof document === 'undefined' ? null : document): Element | null {
  const root = node?.getRootNode?.() as { activeElement?: Element | null } | undefined;
  if (root && 'activeElement' in root) return root.activeElement ?? null;
  return doc?.activeElement ?? null;
}

/**
 * The focus fell out of everything (browser check: a tap on a part of the
 * page that takes no focus puts it on `<body>`): nothing is focused in the
 * dialog's root (`inRoot`, from activeIn: null in a shadow root, `<body>`
 * when the root is the document) and the document's focus is `<body>` or
 * none. A focus in another tree (the document's is then that tree's host)
 * or on another control is a real one and is left alone.
 */
export function focusLost(inRoot: unknown, docActive: unknown, body: unknown): boolean {
  if (inRoot !== null && inRoot !== undefined && inRoot !== body) return false;
  return docActive === null || docActive === undefined || docActive === body;
}

/**
 * Where the focus goes when the confirmation opens or closes: on open to
 * "Abbrechen" (nothing is exported by a stray Enter), on close back to the
 * button that opened it; else nowhere.
 */
export function dialogFocus(wasOpen: boolean, open: boolean): 'cancel' | 'trigger' | null {
  if (!wasOpen && open) return 'cancel';
  if (wasOpen && !open) return 'trigger';
  return null;
}
export const SECTION_INTERVALS = 'Laufende Ausfälle und Lücken';
export const SECTION_INCIDENTS = 'Offene Vorfälle';
export const SECTION_TRAFFIC = 'Verkehr und Funkauslastung (Stundenwerte)';
export const SECTION_CONFIG = 'Konfigurationsversionen';
export const SECTION_CLIENTS = 'Verbundene Clients';
export const SECTION_EVENTS = 'Ereignisse dazwischen';
export const SECTION_COMPARE_INCIDENTS = 'Vorfälle';
export const SECTION_COMPARE_CONFIG = 'Konfigurationsänderungen';

/** Quick picks of the comparison (seconds before now). */
export const COMPARE_PICKS: readonly { id: string; label: string; seconds: number }[] = [
  { id: '1h', label: 'letzte Stunde', seconds: 3600 },
  { id: '24h', label: 'letzte 24 Stunden', seconds: 86_400 },
  { id: '7d', label: 'letzte 7 Tage', seconds: 7 * 86_400 },
];
/** Steps of the moment buttons ("−1 h", "−24 h"). */
export const STATE_STEPS: readonly { id: string; label: string; seconds: number }[] = [
  { id: '1h', label: '−1 h', seconds: 3600 },
  { id: '24h', label: '−24 h', seconds: 86_400 },
];

// ── Small parsers ────────────────────────────────────────────────────────

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
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function token(v: unknown): string | null {
  const s = str(v);
  return s && /^[a-z0-9_.]{1,80}$/.test(s) ? s : null;
}
function routerIdOf(v: unknown): string | null {
  const s = str(v);
  return s && ROUTER_ID_RE.test(s) ? s : null;
}
function severityOf(v: unknown): Severity {
  return v === 'warning' || v === 'critical' ? v : 'info';
}

function known<T>(v: unknown, value: (x: unknown) => T | null): Known<T> {
  const k = obj(v);
  const reason = token(k.reason);
  return {
    value: reason ? null : value(k.value),
    derived: k.derived === true,
    reason,
    cause: token(k.cause),
  };
}

function part(v: unknown): Part {
  const p = obj(v);
  return { state: token(p.state) ?? 'unknown', reason: token(p.reason) };
}

function uplinkOf(v: unknown): UplinkValue | null {
  if (!v || typeof v !== 'object') return null;
  const u = obj(v);
  return { routerId: routerIdOf(u.router_id), routerName: str(u.router_name) };
}

function radioItem(v: unknown): RadioItem | null {
  const r = obj(v);
  const key = token(r.key);
  if (!key) return null;
  const reason = token(r.reason);
  return {
    key,
    band: token(r.band),
    channel: reason ? null : fin(r.channel),
    width: reason ? null : fin(r.width),
    state: token(r.state) ?? 'unknown',
    reason,
  };
}

function trafficWan(v: unknown): TrafficWan {
  const w = obj(v);
  return {
    state: token(w.state) ?? 'unknown',
    avgRxBps: fin(w.avg_rx_bps),
    avgTxBps: fin(w.avg_tx_bps),
    timeCoverage: fin(w.time_coverage),
  };
}

function utilizationRadio(v: unknown): UtilizationRadio {
  const u = obj(v);
  return { band: token(u.band), state: token(u.state) ?? 'unknown', mean: fin(u.mean), maximum: fin(u.maximum) };
}

function routerState(v: unknown): RouterState | null {
  const r = obj(v);
  const routerId = routerIdOf(r.router_id);
  if (!routerId) return null;
  const radios = obj(r.radios);
  const traffic = obj(r.traffic);
  const util = obj(r.utilization);
  return {
    routerId,
    routerName: str(r.router_name),
    reachable: known(r.reachable, x => (typeof x === 'boolean' ? x : null)),
    role: known(r.role, token),
    uplink: known(r.uplink, uplinkOf),
    radios: {
      ...part(radios),
      derived: radios.derived === true,
      items: arr(radios.items).map(radioItem).filter((x): x is RadioItem => x !== null),
    },
    traffic: { ...part(traffic), hour: fin(traffic.hour), wan: arr(traffic.wan).map(trafficWan) },
    utilization: { ...part(util), hour: fin(util.hour), radios: arr(util.radios).map(utilizationRadio) },
  };
}

/** A `target` the server sent (§23), the tab checked against the known ones. */
export function targetOf(v: unknown, routerId: string | null = null): JumpTarget | null {
  if (!v || typeof v !== 'object') return null;
  const t = obj(v);
  const tab = str(t.tab);
  if (!tab || JUMP_TAB_TEXT[tab] === undefined) return null;
  const ref = refOf({ module: 'x', type: str(t.object_type), id: t.object_id, version_id: t.version_id });
  return {
    tab,
    objectType: ref?.type ?? null,
    objectId: ref?.id ?? null,
    versionId: ref?.versionId ?? null,
    routerId,
  };
}

function incidentItem(v: unknown): IncidentItem | null {
  const i = obj(v);
  if (!Object.keys(i).length) return null;
  const routerId = routerIdOf(i.router_id);
  return {
    id: refOf({ module: 'x', id: i.id })?.id ?? null,
    type: token(i.type),
    severity: severityOf(i.severity),
    routerId,
    routerName: str(i.router_name),
    fleet: i.fleet === true,
    since: fin(i.since),
    at: fin(i.at),
    state: token(i.state) ?? 'open',
    reason: token(i.reason),
    target: targetOf(i.target, routerId),
  };
}

function configItem(v: unknown): ConfigItem | null {
  const c = obj(v);
  if (!Object.keys(c).length) return null;
  const routerId = routerIdOf(c.router_id);
  return {
    routerId,
    routerName: str(c.router_name),
    versionId: refOf({ module: 'x', version_id: c.version_id })?.versionId ?? null,
    createdAt: fin(c.created_at),
    code: token(c.code),
    target: targetOf(c.target, routerId),
  };
}

function clientItem(v: unknown): ClientItem | null {
  const c = obj(v);
  const id = str(c.id);
  if (!id || !/^tmm_[0-9a-f]{16}$/.test(id)) return null;
  const client = str(c.client);
  return {
    id,
    client: client && CLIENT_RE.test(client) ? client : null,
    clientName: str(c.client_name),
    routerId: routerIdOf(c.router_id),
    routerName: str(c.router_name),
    start: fin(c.start),
    band: fin(c.band),
    derived: c.derived === true,
  };
}

function clientsPart(v: unknown): ClientsPart | null {
  if (!v || typeof v !== 'object') return null;
  const c = obj(v);
  return {
    ...part(c),
    items: arr(c.items).map(clientItem).filter((x): x is ClientItem => x !== null),
    perRouter: arr(c.per_router)
      .map(x => obj(x))
      .map(x => ({ routerId: routerIdOf(x.router_id) ?? '', routerName: str(x.router_name), clients: fin(x.clients) ?? 0 }))
      .filter(x => x.routerId !== ''),
    total: Math.max(0, fin(c.total) ?? 0),
    truncated: c.truncated === true,
    nextCursor: cursorOf(c.next_cursor),
  };
}

export function parseState(v: unknown): StateAnswer {
  const b = obj(v);
  const incidents = b.incidents && typeof b.incidents === 'object' ? obj(b.incidents) : null;
  const config = b.config && typeof b.config === 'object' ? obj(b.config) : null;
  return {
    status: token(b.status) ?? '',
    reason: token(b.reason),
    generatedAt: fin(b.generated_at),
    at: fin(b.at),
    known: b.known === true,
    unknownReason: token(b.unknown_reason),
    routers: arr(b.routers).map(routerState).filter((x): x is RouterState => x !== null),
    routersTruncated: b.routers_truncated === true,
    intervals: arr(b.intervals).map(parseMark).filter((m): m is Mark => m !== null),
    intervalsTotal: Math.max(0, fin(b.intervals_total) ?? 0),
    intervalsTruncated: b.intervals_truncated === true,
    incidents: incidents && {
      ...part(incidents),
      items: arr(incidents.items).map(incidentItem).filter((x): x is IncidentItem => x !== null),
      total: Math.max(0, fin(incidents.total) ?? 0),
      truncated: incidents.truncated === true,
    },
    config: config && { ...part(config), items: arr(config.items).map(configItem).filter((x): x is ConfigItem => x !== null) },
    clients: clientsPart(b.clients),
  };
}

function change<T>(v: unknown, value: (x: unknown) => T | null): Change<T> {
  const c = obj(v);
  const state = c.state === 'changed' || c.state === 'same' ? c.state : 'unknown';
  return { from: value(c.from), to: value(c.to), state };
}

function radioSide(v: unknown): RadioChange['from'] {
  if (!v || typeof v !== 'object') return null;
  const r = obj(v);
  return { channel: fin(r.channel), width: fin(r.width), state: token(r.state) ?? 'unknown' };
}

function radioChange(v: unknown): RadioChange {
  const r = obj(v);
  const state = r.state === 'changed' || r.state === 'same' ? r.state : 'unknown';
  return { key: token(r.key), band: token(r.band), from: radioSide(r.from), to: radioSide(r.to), state, reason: token(r.reason) };
}

function routerChange(v: unknown): RouterChange | null {
  const r = obj(v);
  const routerId = routerIdOf(r.router_id);
  if (!routerId) return null;
  const c = r.clients && typeof r.clients === 'object' ? obj(r.clients) : null;
  const from = c ? fin(c.from) : null;
  const to = c ? fin(c.to) : null;
  return {
    routerId,
    routerName: str(r.router_name),
    reachable: change(r.reachable, x => (typeof x === 'boolean' ? x : null)),
    role: change(r.role, token),
    uplink: change(r.uplink, uplinkOf),
    radios: arr(r.radios).map(radioChange),
    clients: from !== null && to !== null ? { from, to, delta: to - from } : null,
  };
}

export function parseCompare(v: unknown): CompareAnswer {
  const b = obj(v);
  const ch = obj(b.changes);
  const marks = obj(ch.marks);
  const inc = obj(ch.incidents);
  const cfg = obj(ch.config_versions);
  const byGroup: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(marks.by_group))) {
    const value = fin(n);
    if (value !== null && /^[a-z_]{1,40}$/.test(k)) byGroup[k] = value;
  }
  return {
    status: token(b.status) ?? '',
    reason: token(b.reason),
    generatedAt: fin(b.generated_at),
    t1: fin(b.t1),
    t2: fin(b.t2),
    before: b.before && typeof b.before === 'object' ? parseState(b.before) : null,
    after: b.after && typeof b.after === 'object' ? parseState(b.after) : null,
    routers: arr(ch.routers).map(routerChange).filter((x): x is RouterChange => x !== null),
    marks: { count: Math.max(0, fin(marks.count) ?? 0), byGroup },
    incidents: {
      ...part(inc),
      opened: arr(inc.opened).map(incidentItem).filter((x): x is IncidentItem => x !== null),
      resolved: arr(inc.resolved).map(incidentItem).filter((x): x is IncidentItem => x !== null),
      truncated: inc.truncated === true,
    },
    configVersions: {
      ...part(cfg),
      items: arr(cfg.items).map(configItem).filter((x): x is ConfigItem => x !== null),
      total: Math.max(0, fin(cfg.total) ?? 0),
      truncated: cfg.truncated === true,
    },
    otherSources: otherSourcesOf(ch.other_sources),
  };
}

function otherSourcesOf(v: unknown): OtherSources | null {
  if (!v || typeof v !== 'object') return null;
  const o = obj(v);
  return {
    state: token(o.state) ?? 'unknown',
    reason: token(o.reason),
    count: Math.max(0, fin(o.count) ?? 0),
    truncated: o.truncated === true,
    unreadable: arr(o.unreadable).map(token).filter((x): x is string => x !== null),
  };
}

// ── Queries ──────────────────────────────────────────────────────────────

function epochText(x: number): string {
  return String(Math.round(x * 1000) / 1000);
}

export function stateQueryString(q: StateQuery): string {
  const p = new URLSearchParams();
  p.set('at', epochText(q.at));
  if (q.routerId && ROUTER_ID_RE.test(q.routerId)) p.set('router_id', q.routerId);
  const cursor = q.clientsCursor ? cursorOf(q.clientsCursor) : null;
  if (cursor) p.set('clients_cursor', cursor);
  return p.toString();
}

export function compareQueryString(q: CompareQuery): string {
  const p = new URLSearchParams();
  p.set('t1', epochText(q.t1));
  p.set('t2', epochText(q.t2));
  if (q.routerId && ROUTER_ID_RE.test(q.routerId)) p.set('router_id', q.routerId);
  return p.toString();
}

// ── Local time of the datetime-local fields ──────────────────────────────

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

/** "YYYY-MM-DDTHH:MM:SS" in local time (the value of a datetime-local field). */
export function toLocalInput(ts: number): string {
  const d = new Date(Math.floor(ts) * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const LOCAL_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?$/;

export interface LocalInput {
  /** Epoch seconds (the first one of a doubled hour); null when not a date or not a time of the day. */
  ts: number | null;
  /** The field's error (a time in the hour the clock skips). */
  error: string | null;
  /** A note under the field (a time of the hour the clock repeats). */
  note: string | null;
}

/**
 * A datetime-local value (seconds optional) in the browser's time zone. A
 * time the clock skips in spring is no moment (an error, never the hour
 * after); a time it repeats in autumn is its first occurrence, with a note.
 */
export function parseLocalInput(value: string): LocalInput {
  const m = LOCAL_RE.exec(value.trim());
  if (!m) return { ts: null, error: null, note: null };
  const [y, mo, d, h, mi, s] = m.slice(1).map(x => (x === undefined ? 0 : Number(x)));
  const date = new Date(y, mo - 1, d, h, mi, s);
  if (Number.isNaN(date.getTime()) || date.getMonth() !== mo - 1 || date.getDate() !== d) return { ts: null, error: null, note: null };
  const wall = (t: number) => {
    const x = new Date(t);
    return x.getFullYear() === y && x.getMonth() === mo - 1 && x.getDate() === d
      && x.getHours() === h && x.getMinutes() === mi && x.getSeconds() === s;
  };
  const t = date.getTime();
  // the engine moved a skipped time past the gap: no instant shows this wall time
  if (!wall(t) || h > 23 || mi > 59 || s > 59) {
    return h <= 23 && mi <= 59 && s <= 59 ? { ts: null, error: LOCAL_GAP_TEXT, note: null } : { ts: null, error: null, note: null };
  }
  // the same wall time an hour (or, in rare zones, half an hour) apart: the hour came twice
  const twins = [-3600_000, -1800_000, 1800_000, 3600_000].map(o => t + o).filter(wall);
  if (twins.length) return { ts: Math.floor(Math.min(t, ...twins) / 1000), error: null, note: LOCAL_TWICE_TEXT };
  return { ts: Math.floor(t / 1000), error: null, note: null };
}

/** Epoch seconds of a datetime-local value (seconds optional); null when not a date or a skipped time. */
export function fromLocalInput(value: string): number | null {
  return parseLocalInput(value).ts;
}

/**
 * The moment "Zustand" loads and the field that goes with it: under "Jetzt"
 * the server's now and the field set to it (the heading and the field never
 * disagree, browser review), else the field's own time.
 */
export function stateLoadAt(live: boolean, input: string, nowS: number): { at: number | null; input: string } {
  if (!live) return { at: fromLocalInput(input), input };
  const at = Math.floor(nowS) - 1;
  return { at, input: toLocalInput(at) };
}

// ── Loading when a view opens (1.52.1) ───────────────────────────────────

/** The pause after a change of a field (typing) before "Zustand" or "Vergleich" loads. */
export const TM_DEBOUNCE_MS = 400;

/**
 * When a view loads after its fields or its visibility changed: at once when
 * it has just been opened (its prefilled fields need no typing pause; browser
 * review 1.52.0: until the pause ended the view said "wählen"), after
 * TM_DEBOUNCE_MS for a change while it is shown, and not now on a hidden page
 * (null: the load is due and runs when the page is shown again).
 */
export function loadDelay(opening: boolean, visible: boolean): number | null {
  if (!visible) return null;
  return opening ? 0 : TM_DEBOUNCE_MS;
}

/**
 * What a view shows before its first answer (no answer, no error): "lädt"
 * while a load runs or while every field holds a moment (the load is due);
 * the hint "wählen" only when a field is really empty (cleared, or no
 * complete date); nothing when a field holds a time the clock skips (the
 * field shows that error itself).
 */
export function waitingBody(values: readonly string[], loading: boolean): 'loading' | 'pick' | 'none' {
  if (loading) return 'loading';
  const parsed = values.map(parseLocalInput);
  if (parsed.some(p => p.ts === null && p.error === null)) return 'pick';
  if (parsed.some(p => p.error !== null)) return 'none';
  return 'loading';
}

// ── Loaded state of "Zustand" ────────────────────────────────────────────

export interface StateView {
  seq: number;
  moreSeq: number;
  answer: StateAnswer | null;
  /** The query of the answer (its moment: the client cursor belongs to it). */
  query: StateQuery | null;
  /** Client sessions of every loaded page (the first page and "Weitere laden"). */
  clients: ClientItem[];
  clientsCursor: string | null;
  loading: boolean;
  loadingMore: boolean;
  error: unknown;
  moreError: unknown;
}

export const STATE_INIT: StateView = {
  seq: 0, moreSeq: 0, answer: null, query: null, clients: [], clientsCursor: null, loading: false, loadingMore: false,
  error: null, moreError: null,
};

export type StateAction =
  | { type: 'start'; seq: number }
  | { type: 'done'; seq: number; answer: StateAnswer; query: StateQuery }
  | { type: 'fail'; seq: number; error: unknown }
  | { type: 'moreStart'; seq: number }
  | { type: 'moreDone'; seq: number; answer: StateAnswer }
  | { type: 'moreFail'; seq: number; error: unknown };

/** One step: only the latest request counts; an older answer is dropped. */
export function stateReducer(s: StateView, a: StateAction): StateView {
  switch (a.type) {
    case 'start':
      // a new moment drops a pending "Weitere laden"
      return { ...s, seq: a.seq, moreSeq: -1, loading: true, loadingMore: false, moreError: null };
    case 'done':
      if (a.seq !== s.seq) return s;
      return {
        ...s, answer: a.answer, query: a.query, clients: a.answer.clients?.items ?? [],
        clientsCursor: a.answer.clients?.nextCursor ?? null, loading: false, error: null,
      };
    case 'fail':
      return a.seq !== s.seq ? s : { ...s, loading: false, error: a.error };
    case 'moreStart':
      return { ...s, moreSeq: a.seq, loadingMore: true, moreError: null };
    case 'moreDone': {
      if (a.seq !== s.moreSeq) return s;
      const seen = new Set(s.clients.map(c => c.id));
      const more = (a.answer.clients?.items ?? []).filter(c => !seen.has(c.id));
      return { ...s, clients: [...s.clients, ...more], clientsCursor: a.answer.clients?.nextCursor ?? null, loadingMore: false };
    }
    case 'moreFail':
      return a.seq !== s.moreSeq ? s : { ...s, loadingMore: false, moreError: a.error };
    default:
      return s;
  }
}

export interface CompareView {
  seq: number;
  answer: CompareAnswer | null;
  loading: boolean;
  error: unknown;
}

export const COMPARE_INIT: CompareView = { seq: 0, answer: null, loading: false, error: null };

export type CompareAction =
  | { type: 'start'; seq: number }
  | { type: 'done'; seq: number; answer: CompareAnswer }
  | { type: 'fail'; seq: number; error: unknown };

export function compareReducer(s: CompareView, a: CompareAction): CompareView {
  switch (a.type) {
    case 'start':
      return { ...s, seq: a.seq, loading: true };
    case 'done':
      return a.seq !== s.seq ? s : { ...s, answer: a.answer, loading: false, error: null };
    case 'fail':
      return a.seq !== s.seq ? s : { ...s, loading: false, error: a.error };
    default:
      return s;
  }
}

/** The query of "Weitere laden": administrators only, the answer's moment and its cursor; else null. */
export function moreClientsQuery(s: StateView, isAdmin: boolean): StateQuery | null {
  if (!isAdmin || s.query === null || s.clientsCursor === null) return null;
  return { ...s.query, clientsCursor: s.clientsCursor };
}

// ── Values in words ──────────────────────────────────────────────────────

export interface ValueView {
  text: string;
  /** "unbekannt": muted, never coloured. */
  unknown: boolean;
  /** The reason in words (only with unknown). */
  reason: string | null;
  derived: boolean;
  /** 'warn' only for "nicht erreichbar". */
  tone: 'warn' | null;
}

export function stateReasonText(reason: string | null): string {
  return reason ? STATE_REASON_TEXT[reason] ?? 'Grund unbekannt' : 'Grund unbekannt';
}

export function globalReasonText(reason: string | null): string {
  return reason ? GLOBAL_REASON_TEXT[reason] ?? 'Der Grund ist unbekannt.' : 'Der Grund ist unbekannt.';
}

export function partStateText(p: Part): string {
  if (p.state === 'unreadable') {
    return p.reason && p.reason !== 'unreadable'
      ? `${PART_UNREADABLE_TEXT.slice(0, -1)}: ${stateReasonText(p.reason)}.`
      : PART_UNREADABLE_TEXT;
  }
  const word = PART_STATE_TEXT[p.state] ?? UNKNOWN;
  return p.reason ? `${word} · ${stateReasonText(p.reason)}` : word;
}

/**
 * The radios of one router card: `whole` the block is one "unbekannt" with
 * `reason`; `note` what follows the list of a partial block. A reason is said
 * once: never again in the note when the value before already says it
 * (browser review: "unbekannt · Router nicht erreichbar · unvollständig ·
 * Router nicht erreichbar").
 */
export function radiosView(radios: Part & { items: RadioItem[] }): { whole: boolean; reason: string | null; note: string | null } {
  const whole = radios.state === 'unknown' || radios.state === 'off' || radios.state === 'unreadable' || !radios.items.length;
  const reason = whole ? (radios.reason ? stateReasonText(radios.reason) : 'keine Funkdaten') : null;
  if (radios.state !== 'partial') return { whole, reason, note: null };
  if (radios.reason === 'not_observed') return { whole, reason: whole ? null : reason, note: RADIOS_NOT_OBSERVED_TEXT };
  const said = new Set(whole
    ? [reason]
    : radios.items.filter(i => i.reason || i.state === 'unknown').map(i => stateReasonText(i.reason)));
  const own = radios.reason ? stateReasonText(radios.reason) : null;
  const word = PART_STATE_TEXT.partial;
  return { whole, reason, note: own && !said.has(own) ? `${word} · ${own}` : word };
}

function unknownView(reason: string | null): ValueView {
  return { text: UNKNOWN, unknown: true, reason: stateReasonText(reason), derived: false, tone: null };
}

export function reachableView(k: Known<boolean>): ValueView {
  if (k.reason || k.value === null) return unknownView(k.reason);
  if (k.value) return { text: 'erreichbar', unknown: false, reason: null, derived: k.derived, tone: null };
  const text = k.cause === 'lan_down' ? 'nicht erreichbar (LAN)' : 'nicht erreichbar';
  return { text, unknown: false, reason: null, derived: k.derived, tone: 'warn' };
}

export function roleText(role: string | null): string {
  return role ? ROLE_TEXT[role] ?? 'Rolle unbekannt' : UNKNOWN;
}

export function roleView(k: Known<string>): ValueView {
  if (k.reason || k.value === null) return unknownView(k.reason);
  return { text: roleText(k.value), unknown: false, reason: null, derived: k.derived, tone: null };
}

export const NO_UPLINK = 'kein vorgeschalteter Router';

export function uplinkText(u: UplinkValue | null): string {
  if (!u) return NO_UPLINK;
  if (u.routerId) return `über ${routerOptionLabel(u.routerId, u.routerName)}`;
  return u.routerName ? `über ${scrub(u.routerName)}` : 'über einen unbekannten Router';
}

/** A known uplink of null means: directly at the gateway (or the gateway itself). */
export function uplinkView(k: Known<UplinkValue>): ValueView {
  if (k.reason) return unknownView(k.reason);
  return { text: uplinkText(k.value), unknown: false, reason: null, derived: k.derived, tone: null };
}

export function radioBandText(band: string | null): string {
  return band ? RADIO_BAND_TEXT[band] ?? 'Band unbekannt' : 'Band unbekannt';
}

/** "Kanal 44 · 80 MHz · an" of one radio (width null: "Breite unbekannt"). */
export function radioValueText(r: { channel: number | null; width: number | null; state: string }): string {
  const parts = [
    r.channel !== null ? `Kanal ${num(r.channel)}` : 'Kanal unbekannt',
    r.width !== null ? `${num(r.width)} MHz` : 'Breite unbekannt',
    RADIO_STATE_TEXT[r.state] ?? UNKNOWN,
  ];
  return parts.join(' · ');
}

export function radioView(r: RadioItem, derived: boolean): ValueView {
  if (r.reason || r.state === 'unknown') return unknownView(r.reason);
  return { text: radioValueText(r), unknown: false, reason: null, derived, tone: null };
}

/** One router's name: the server's name, else "Router ·" and the id's end (never built from anything else). */
export function routerName(r: { routerId: string | null; routerName: string | null }): string {
  if (r.routerId) return routerOptionLabel(r.routerId, r.routerName);
  return r.routerName ? scrub(r.routerName) : 'ohne Router';
}

/** "seit 21.11.2026, 13:03" of a client session or an incident (local time). */
export function sinceText(ts: number | null): string {
  return ts === null ? 'seit unbekannt' : `seit ${startText(ts)}`;
}

export function clientRowText(c: ClientItem): { label: string; band: string } {
  return { label: clientLabel(c.client, c.clientName), band: bandText(c.band) ?? 'Band unbekannt' };
}

export function hourText(hour: number | null): string {
  if (hour === null) return 'Stunde unbekannt';
  const a = new Date(hour * 1000);
  const b = new Date((hour + 3600) * 1000);
  return `${pad(a.getHours())}:00–${pad(b.getHours())}:00`;
}

/** "Empfangen Ø 1,2 Mbit/s · Gesendet Ø 300 kbit/s" of one WAN point, "—" for what is unknown. */
export function wanText(w: TrafficWan): string {
  if (w.state !== 'available') return 'keine Messwerte in dieser Stunde';
  return `Empfangen Ø ${fmtRate(w.avgRxBps)} · Gesendet Ø ${fmtRate(w.avgTxBps)}`;
}

export function utilizationText(u: UtilizationRadio): string {
  const band = radioBandText(u.band);
  if (u.state !== 'measured' || u.mean === null) return `${band}: —`;
  return `${band}: Ø ${num(u.mean)} %${u.maximum !== null ? ` · höchstens ${num(u.maximum)} %` : ''}`;
}

export function incidentTitle(i: IncidentItem): string {
  return (i.type && TITLE_TEXT[`ni_incidents.${i.type}`]) || 'Vorfall';
}

export function configTitle(c: ConfigItem): string {
  return (c.code && TITLE_TEXT[`config_versions.${c.code}`]) || 'Konfigurationsversion';
}

export function isoOrDash(ts: number | null): string {
  return ts === null ? '—' : isoUtc(ts);
}

// ── Comparison rows ──────────────────────────────────────────────────────

export interface CompareRow {
  key: string;
  label: string;
  before: string;
  after: string;
  /** changed | same | unknown */
  state: string;
  /** Why a side is unknown, in words (null when both are known). */
  reason: string | null;
}

function sideReason(side: StateAnswer | null): string | null {
  return side && !side.known ? stateReasonText(side.unknownReason) : null;
}

function boolText(v: boolean | null): string {
  return v === null ? UNKNOWN : v ? 'erreichbar' : 'nicht erreichbar';
}

/**
 * The rows of one router: Erreichbar, Rolle, Uplink, each radio, and (for
 * administrators) the client count. A side that is unknown says
 * "unbekannt"; an unknown row is never a change.
 */
export function compareRows(r: RouterChange, a: CompareAnswer, isAdmin: boolean): CompareRow[] {
  const reason = [sideReason(a.before), sideReason(a.after)].filter(Boolean).join(' / ') || null;
  const row = <T>(key: string, label: string, c: Change<T>, text: (v: T | null) => string): CompareRow => ({
    key, label,
    before: c.state === 'unknown' && c.from === null ? UNKNOWN : text(c.from),
    after: c.state === 'unknown' && c.to === null ? UNKNOWN : text(c.to),
    state: c.state,
    reason: c.state === 'unknown' ? reason : null,
  });
  const rows: CompareRow[] = [
    row('reachable', 'Erreichbar', r.reachable, boolText),
    row('role', 'Rolle', r.role, v => roleText(v)),
    row('uplink', 'Uplink', r.uplink, v => uplinkText(v)),
  ];
  for (const x of r.radios) {
    if (x.key === null) {
      rows.push({ key: 'radios', label: 'Funk', before: UNKNOWN, after: UNKNOWN, state: 'unknown', reason: stateReasonText(x.reason) });
      continue;
    }
    rows.push({
      key: `radio-${x.key}`,
      label: `Funk ${radioBandText(x.band)}`,
      before: x.from ? radioValueText(x.from) : UNKNOWN,
      after: x.to ? radioValueText(x.to) : UNKNOWN,
      state: x.state,
      reason: x.state === 'unknown' ? (x.reason ? stateReasonText(x.reason) : reason) : null,
    });
  }
  if (isAdmin && r.clients) {
    rows.push({
      key: 'clients', label: 'Clients', before: num(r.clients.from), after: num(r.clients.to),
      state: r.clients.delta === 0 ? 'same' : 'changed', reason: null,
    });
  }
  return rows;
}

/** "von 2 auf 1 (−1)" of the client count. */
export function deltaText(c: { from: number; to: number; delta: number }): string {
  const d = c.delta === 0 ? '±0' : c.delta > 0 ? `+${num(c.delta)}` : `−${num(-c.delta)}`;
  return `von ${num(c.from)} auf ${num(c.to)} (${d})`;
}

/**
 * The sentence under the comparison: "nothing changed" only when both
 * states are known and nothing differs, nothing is unknown and nothing
 * happened in between; else what is true.
 */
export function compareSummary(a: CompareAnswer, isAdmin: boolean): string {
  const rows = a.routers.flatMap(r => compareRows(r, a, isAdmin));
  const changed = rows.filter(r => r.state === 'changed').length;
  const unknown = rows.filter(r => r.state === 'unknown').length;
  const bothKnown = !!a.before?.known && !!a.after?.known;
  if (!bothKnown) {
    const which = !a.before?.known && !a.after?.known ? 'beiden Zeitpunkten' : a.before?.known ? '„Bis“' : '„Von“';
    return `Für ${which} ist kein Zustand bekannt; Änderungen, die davon abhängen, sind unbekannt.`;
  }
  if (changed > 0) return `${num(changed)} ${changed === 1 ? 'Merkmal hat' : 'Merkmale haben'} sich geändert.`;
  if (unknown > 0) {
    return `Keine bekannte Änderung; ${num(unknown)} ${unknown === 1 ? 'Merkmal ist' : 'Merkmale sind'} zu einem der Zeitpunkte unbekannt.`;
  }
  const other = a.otherSources;
  const happened = a.marks.count > 0 || a.incidents.opened.length > 0 || a.incidents.resolved.length > 0
    || a.configVersions.items.length > 0 || (other !== null && other.count > 0);
  if (happened) return SAME_BUT_EVENTS;
  // "nothing changed" only when the other modules were read and are empty too (review F)
  if (other === null || other.state !== 'ok' || other.truncated) return otherUnknownText(other);
  return NOTHING_CHANGED;
}

/** Why it is unknown whether anything happened in between, with the names of the sources not read. */
export function otherUnknownText(o: OtherSources | null): string {
  const ids = o?.unreadable ?? [];
  if (o === null || (o.state !== 'unreadable' && !ids.length)) return OTHER_UNKNOWN_NONE;
  const names = ids.map(id => SOURCE_TEXT[id] ?? 'unbekannte Quelle');
  const head = ids.length > 1 ? OTHER_UNKNOWN_MANY : OTHER_UNKNOWN_ONE;
  return names.length ? `${head} Nicht gelesen: ${names.join(', ')}.` : head;
}

/**
 * The line under "Ereignisse dazwischen" for the other modules: "Dazu 3
 * Einträge aus anderen Modulen." ("mindestens" when cut), the sentence of
 * unknown when a source was not read, else null.
 */
export function otherSourcesText(o: OtherSources | null): string | null {
  if (o === null || o.state !== 'ok') return otherUnknownText(o);
  if (o.count <= 0) return null;
  const n = `${o.truncated ? 'mindestens ' : ''}${num(o.count)}`;
  return `Dazu ${n} ${o.count === 1 && !o.truncated ? 'Eintrag' : 'Einträge'} aus anderen Modulen.`;
}

// ── Jumps (§23) ──────────────────────────────────────────────────────────

/** Where a timeline mark leads (null: no Enterprise tab, or an unknown ref). */
export function markTarget(m: Pick<Mark, 'ref' | 'kind' | 'routerId'>): JumpTarget | null {
  const ref = m.ref;
  if (!ref) return null;
  const key = `${ref.module}.${ref.type ?? ''}`;
  let tab = JUMP_REF_TAB[key];
  if (tab === 'by_kind') tab = JUMP_KIND_TAB[m.kind];
  if (!tab || tab === 'none' || JUMP_TAB_TEXT[tab] === undefined) return null;
  const objectType = JUMP_OBJECT[key] ?? null;
  const objectId = key === 'config_manager.version' ? ref.versionId : objectType ? ref.id : null;
  return {
    tab,
    objectType: objectId !== null ? objectType : null,
    objectId,
    versionId: ref.versionId,
    routerId: m.routerId,
  };
}

/** A target shown as a button: never this tab itself, never a tab this user does not have. */
export function shownTarget(t: JumpTarget | null, canOpen: (tab: string) => boolean): JumpTarget | null {
  if (!t || t.tab === TAB_ID) return null;
  return canOpen(t.tab) ? t : null;
}

export function jumpLabel(tab: string): string {
  return `Im Tab ${JUMP_TAB_TEXT[tab] ?? tab} öffnen`;
}

/** A client pseudonym `tmc_…` (the only value the client filter sends). */
export function isClient(v: string | null): boolean {
  return !!v && CLIENT_RE.test(v);
}
