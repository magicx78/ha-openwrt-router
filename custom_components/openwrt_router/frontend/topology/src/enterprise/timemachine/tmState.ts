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
  GLOBAL_REASON_TEXT, JUMP_KIND_TAB, JUMP_OBJECT, JUMP_REF_TAB, JUMP_TAB_TEXT, PART_STATE_TEXT, RADIO_BAND_TEXT,
  RADIO_STATE_TEXT, ROLE_TEXT, STATE_REASON_TEXT, TITLE_TEXT,
} from './tmTexts.ts';
import type {
  Change, ClientItem, ClientsPart, CompareAnswer, CompareQuery, ConfigItem, IncidentItem, JumpTarget, Known, Mark, Part,
  RadioChange, RadioItem, RouterChange, RouterState, Severity, StateAnswer, StateQuery, TrafficWan, UplinkValue,
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
export const COMPARE_PICK_TEXT = '„Von“ und „Bis“ wählen.';
export const STATE_PICK_TEXT = 'Einen Zeitpunkt wählen.';
export const EXPORT_CONFIRM_TEXT =
  'Der Export enthält die Marken des gewählten Zeitfensters ohne Namen und ohne Client-Verläufe. Er wird im Audit-Protokoll vermerkt.';
export const EXPORT_FILENAME = 'openwrt-router-time-machine.json';
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

/** Epoch seconds of a datetime-local value (seconds optional); null when not a date. */
export function fromLocalInput(value: string): number | null {
  const m = LOCAL_RE.exec(value.trim());
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(x => (x === undefined ? 0 : Number(x)));
  const date = new Date(y, mo - 1, d, h, mi, s);
  if (Number.isNaN(date.getTime()) || date.getMonth() !== mo - 1 || date.getDate() !== d) return null;
  return Math.floor(date.getTime() / 1000);
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
  const word = PART_STATE_TEXT[p.state] ?? UNKNOWN;
  return p.reason ? `${word} · ${stateReasonText(p.reason)}` : word;
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
  const happened = a.marks.count > 0 || a.incidents.opened.length > 0 || a.incidents.resolved.length > 0 || a.configVersions.items.length > 0;
  return happened ? SAME_BUT_EVENTS : NOTHING_CHANGED;
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
