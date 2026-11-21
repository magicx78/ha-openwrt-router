/**
 * wifiLogic.ts — pure logic of the WiFi Intelligence tab.
 *
 * Parsers (server JSON -> view types), German texts per code, number
 * formatting, status / health / metric display, error mapping, the polling
 * rule, the timeline query and the SVG line. No React, no DOM, no network:
 * node --test imports it.
 *
 * Hard rules kept here:
 *  - Unknown is never 0 and never green: a missing value is "—" with its
 *    reason (no_data / unsupported / unreachable / stale / not assessed).
 *  - A health score is shown only while the module is "ready".
 *  - The parsers keep only what the views show: no SSID, BSSID, MAC or
 *    interface name; every free token shown passes scrub() (MAC -> [MAC]).
 *  - Server text is never shown: errors map from status and code.
 *  - The module observes and recommends; nothing here builds a write.
 */

import { num } from '../../utils/format.ts';
import type {
  Base,
  ChannelEntry,
  ChannelMap,
  Conflict,
  Counts,
  Distribution,
  Health,
  LoadAp,
  Metric,
  MetricState,
  Overview,
  Radio,
  RadiosView,
  Recommendation,
  Recommendations,
  Ref,
  RfStatus,
  RoamEvent,
  Roaming,
  RouterRow,
  Series,
  SeriesPoint,
  Timeline,
  TimelineQuery,
  TimelineRadio,
  Tone,
} from './wifiTypes';

// ── Constants ────────────────────────────────────────────────────────────

export const TAB_ID = 'wifi';
export const TAB_TITLE = 'WiFi Intelligence';
/** After Konfiguration (10), Security Center (20) and Netzwerkdiagnose (30). */
export const TAB_ORDER = 40;

export const DASH = '—';
/** Never poll faster than this (rule of the task and of the backend cadence). */
export const POLL_MIN_MS = 60_000;

export const WINDOWS: readonly string[] = ['1h', '24h', '7d', '30d'];
export const WINDOW_LABEL: Record<string, string> = {
  '1h': '1 Stunde', '24h': '24 Stunden', '7d': '7 Tage', '30d': '30 Tage',
};

export type ValueKind = 'pct' | 'dbm' | 'per_packet' | 'score' | 'count';

/** Series of rf_store.SERIES with label and unit. */
export const SERIES_INFO: Record<string, { label: string; kind: ValueKind }> = {
  utilization: { label: 'Kanalauslastung', kind: 'pct' },
  noise: { label: 'Rauschen', kind: 'dbm' },
  clients: { label: 'Clients', kind: 'count' },
  retry_rate: { label: 'Wiederholungen', kind: 'per_packet' },
  health: { label: 'Health Score', kind: 'score' },
  roams: { label: 'Roaming-Wechsel', kind: 'count' },
  channel_changes: { label: 'Kanalwechsel', kind: 'count' },
};
export const SERIES_IDS: readonly string[] = Object.keys(SERIES_INFO);

export type SectionId = 'overview' | 'radios' | 'channels' | 'timeline' | 'roaming' | 'recommendations';
export const SECTIONS: readonly { id: SectionId; title: string }[] = [
  { id: 'overview', title: 'Übersicht' },
  { id: 'radios', title: 'Radios' },
  { id: 'channels', title: 'Kanalkarte' },
  { id: 'timeline', title: 'RF-Zeitverlauf' },
  { id: 'roaming', title: 'Roaming' },
  { id: 'recommendations', title: 'Empfehlungen' },
];

export const OFF_HINT =
  'Die WLAN-Funkanalyse ist aus. Einschalten in den Integrationsoptionen: Einstellungen → Geräte & Dienste → '
  + 'OpenWrt Router → Konfigurieren → „WLAN-Funkanalyse (wifi_rf_enabled)“, für jeden Router einzeln. '
  + 'Zusätzliche Abfragen (z. B. Kanalauslastung aus hostapd) haben dort eigene Schalter.';

export const SCAN_WARNING =
  'Achtung: Ein Survey oder Scan kann den Funkbetrieb kurz stören – das Funkmodul verlässt dabei kurz seinen Kanal '
  + 'oder der Treiber blockiert bis zu 3 Sekunden. Dieses Modul startet selbst keinen Scan; ein Survey läuft nur, '
  + 'wenn er in den Integrationsoptionen eingeschaltet ist.';

export const NOT_A_SPECTRUM_ANALYZER = 'kein Spektrumanalysator: Werte stammen aus Treiberzählern';

export const OBSERVE_ONLY =
  'Dieses Modul beobachtet und empfiehlt nur. Es ändert nie etwas am WLAN; Empfehlungen setzt ein Administrator selbst um.';

// ── Small parse helpers ──────────────────────────────────────────────────

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}
function numOrNull(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function boolOrNull(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : [];
}
function objList(v: unknown): Obj[] {
  return Array.isArray(v) ? v.map(obj).filter((x): x is Obj => x !== null) : [];
}

const STATUSES: readonly string[] = ['off', 'not_ready', 'ready'];
const METRIC_STATES: readonly string[] = ['measured', 'no_data', 'unsupported', 'unreachable', 'stale'];

function status(v: unknown): RfStatus | null {
  return typeof v === 'string' && STATUSES.includes(v) ? (v as RfStatus) : null;
}
function metricState(v: unknown): MetricState | null {
  return typeof v === 'string' && METRIC_STATES.includes(v) ? (v as MetricState) : null;
}

function parseBase(o: Obj | null): Base {
  return {
    status: status(o?.status),
    reasons: strList(o?.reasons),
    generatedAt: numOrNull(o?.generated_at),
  };
}

function parseRef(v: unknown): Ref | null {
  const o = obj(v);
  const routerId = str(o?.router_id);
  const radioId = str(o?.radio_id);
  return routerId && radioId ? { routerId, radioId } : null;
}

/** A value only next to a state that carries one (measured / stale). */
export function parseMetric(v: unknown): Metric | null {
  const o = obj(v);
  if (!o) return null;
  const state = metricState(o.state);
  const value = state === 'measured' || state === 'stale' ? numOrNull(o.value) : null;
  return { value, state, source: str(o.source), measuredAt: numOrNull(o.measured_at) };
}

function parseHealth(v: unknown): Health {
  const o = obj(v);
  return {
    score: numOrNull(o?.score),
    grade: str(o?.grade),
    coverage: numOrNull(o?.coverage),
    capped: o?.capped === true,
    withheld: strList(o?.withheld),
  };
}

// ── Parsers ──────────────────────────────────────────────────────────────

function parseRouter(o: Obj): RouterRow | null {
  const routerId = str(o.router_id);
  if (!routerId) return null;
  return {
    routerId,
    enabled: boolOrNull(o.enabled),
    status: str(o.status),
    reason: str(o.reason),
    radios: numOrNull(o.radios),
    reads: strList(o.reads),
    everyNPolls: numOrNull(o.every_n_polls),
    lastPollAt: numOrNull(o.last_poll_at),
    health: parseHealth(o.health),
  };
}

export function parseOverview(v: unknown): Overview {
  const o = obj(v);
  const c = obj(o?.counts);
  const counts: Counts = {
    radios: numOrNull(c?.radios),
    clients: numOrNull(c?.clients),
    conflicts: numOrNull(c?.conflicts),
    conflictsMeasured: numOrNull(c?.conflicts_measured),
    recommendations: numOrNull(c?.recommendations),
  };
  return {
    ...parseBase(o),
    routers: objList(o?.routers).map(parseRouter).filter((r): r is RouterRow => r !== null),
    monitoringCoverage: numOrNull(o?.monitoring_coverage),
    networkHealth: parseHealth(o?.network_health),
    counts,
  };
}

function parseRadio(o: Obj): Radio | null {
  const ref = parseRef(o);
  if (!ref) return null;
  const metrics: Record<string, Metric | null> = {};
  for (const [name, m] of Object.entries(obj(o.metrics) ?? {})) metrics[name] = parseMetric(m);
  const util = obj(o.utilization);
  const sum = obj(util?.summary);
  const cl = obj(o.clients);
  const caps = obj(o.capabilities);
  const states: Record<string, MetricState | null> = {};
  for (const [name, s] of Object.entries(obj(caps?.states) ?? {})) states[name] = metricState(s);
  const sources: Radio['sources'] = {};
  for (const [kind, s] of Object.entries(obj(o.sources) ?? {})) {
    const so = obj(s);
    sources[kind] = { state: str(so?.state), reason: str(so?.reason) };
  }
  return {
    ...ref,
    band: str(o.band),
    channel: numOrNull(o.channel),
    widthMhz: numOrNull(o.width_mhz),
    centerChannel: numOrNull(o.center_channel),
    htmode: str(o.htmode),
    backhaul: boolOrNull(o.backhaul),
    country: str(o.country),
    measuredAt: numOrNull(o.measured_at),
    metrics,
    utilReason: str(util?.reason),
    utilSummary: sum
      ? { current: numOrNull(sum.current), mean: numOrNull(sum.mean), peak: numOrNull(sum.peak), coverage: numOrNull(sum.coverage) }
      : null,
    clients: {
      count: numOrNull(cl?.count),
      problem: numOrNull(cl?.problem_clients),
      flagged: numOrNull(cl?.flagged_clients),
      weak: numOrNull(cl?.weak_persistent_clients),
      signalCoverage: numOrNull(cl?.signal_coverage),
      retryCoverage: numOrNull(cl?.retry_coverage),
    },
    capabilities: { states, coverage: numOrNull(caps?.coverage) },
    health: parseHealth(o.health),
    loadStatus: str(obj(o.load)?.status),
    sources,
    roams1h: numOrNull(o.roams_1h),
  };
}

export function parseRadios(v: unknown): RadiosView {
  const o = obj(v);
  return {
    ...parseBase(o),
    radios: objList(o?.radios).map(parseRadio).filter((r): r is Radio => r !== null),
  };
}

const BAND_ORDER = ['2.4g', '5g', '6g'];

function bandRank(band: string): number {
  const i = BAND_ORDER.indexOf(band);
  return i === -1 ? BAND_ORDER.length : i;
}

function parseEntry(o: Obj): ChannelEntry | null {
  const ref = parseRef(o);
  if (!ref) return null;
  return {
    ...ref,
    channel: numOrNull(o.channel),
    widthMhz: numOrNull(o.width_mhz),
    centerChannel: numOrNull(o.center_channel),
    backhaul: boolOrNull(o.backhaul),
    clientCount: numOrNull(o.client_count),
    utilization: parseMetric(o.utilization),
  };
}

function parseConflict(o: Obj): Conflict {
  return {
    kind: str(o.kind),
    band: str(o.band),
    members: (Array.isArray(o.members) ? o.members : []).map(parseRef).filter((r): r is Ref => r !== null),
    status: str(o.status),
    severity: str(o.severity),
    evidence: strList(o.evidence),
  };
}

export function parseChannelMap(v: unknown): ChannelMap {
  const o = obj(v);
  const bands = Object.entries(obj(o?.bands) ?? {})
    .map(([band, list]) => ({
      band,
      entries: objList(list).map(parseEntry).filter((e): e is ChannelEntry => e !== null),
    }))
    .sort((a, b) => bandRank(a.band) - bandRank(b.band) || a.band.localeCompare(b.band));
  return { ...parseBase(o), bands, conflicts: objList(o?.conflicts).map(parseConflict) };
}

function parsePoint(o: Obj): SeriesPoint | null {
  const ts = numOrNull(o.ts);
  if (ts === null) return null;
  return { ts, mean: numOrNull(o.mean), min: numOrNull(o.min), max: numOrNull(o.max) };
}

function parseSeries(v: unknown): Series | null {
  const o = obj(v);
  if (!o) return null;
  return {
    windowS: numOrNull(o.window_s),
    resolutionS: numOrNull(o.resolution_s),
    coverage: numOrNull(o.coverage),
    points: objList(o.points).map(parsePoint).filter((p): p is SeriesPoint => p !== null),
  };
}

function parseTimelineRadio(o: Obj): TimelineRadio | null {
  const ref = parseRef(o);
  if (!ref) return null;
  const series: Record<string, Series> = {};
  for (const [name, s] of Object.entries(obj(o.series) ?? {})) {
    const parsed = parseSeries(s);
    if (parsed && name in SERIES_INFO) series[name] = parsed;
  }
  return { ...ref, series };
}

export function parseTimeline(v: unknown): Timeline {
  const o = obj(v);
  return {
    ...parseBase(o),
    window: str(o?.window),
    radios: objList(o?.radios).map(parseTimelineRadio).filter((r): r is TimelineRadio => r !== null),
  };
}

function parseEvent(o: Obj): RoamEvent {
  return {
    clientRef: (s => (s === null ? null : scrub(s)))(str(o.client_ref)),
    from: parseRef(o.from),
    to: parseRef(o.to),
    at: numOrNull(o.at),
    gapS: numOrNull(o.gap_s),
  };
}

export function parseRoaming(v: unknown): Roaming {
  const o = obj(v);
  const perRadio = objList(o?.per_radio)
    .map(p => {
      const ref = parseRef(p);
      return ref ? { ...ref, roams: numOrNull(p.roams) } : null;
    })
    .filter((p): p is Ref & { roams: number | null } => p !== null);
  return {
    ...parseBase(o),
    windowS: numOrNull(o?.window_s),
    perRadio,
    events: Array.isArray(o?.events) ? objList(o?.events).map(parseEvent) : null,
    eventsRestricted: str(o?.events_restricted),
  };
}

function parseTarget(v: unknown): Recommendation['target'] {
  const o = obj(v);
  const routerId = str(o?.router_id);
  return routerId ? { routerId, radioId: str(o?.radio_id) } : null;
}

function parseParams(v: unknown): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, x] of Object.entries(obj(v) ?? {})) {
    if (typeof x === 'string' || (typeof x === 'number' && Number.isFinite(x))) out[k] = x;
  }
  return out;
}

function parseRecommendation(o: Obj): Recommendation {
  return {
    kind: str(o.kind),
    target: parseTarget(o.target),
    scope: str(o.scope),
    problem: str(o.problem),
    evidence: strList(o.evidence),
    action: str(o.action),
    actionParams: parseParams(o.action_params),
    expectedEffect: str(o.expected_effect),
    confidence: numOrNull(o.confidence),
    risk: strList(o.risk),
    requires: strList(o.requires),
    basis: str(o.basis),
    priority: str(o.priority),
  };
}

function parseDistribution(v: unknown): Distribution | null {
  const o = obj(v);
  if (!o) return null;
  return {
    total: numOrNull(o.total),
    coverage: numOrNull(o.coverage),
    largestShare: numOrNull(o.largest_share),
    perBand: Object.entries(obj(o.per_band) ?? {})
      .map(([band, n]) => ({ band, clients: numOrNull(n) }))
      .sort((a, b) => bandRank(a.band) - bandRank(b.band)),
    findings: objList(o.findings).map(f => ({ kind: str(f.kind), severity: str(f.severity) })),
  };
}

export function parseRecommendations(v: unknown): Recommendations {
  const o = obj(v);
  const load: LoadAp[] = objList(obj(o?.load)?.aps)
    .map(a => {
      const routerId = str(a.router_id);
      return routerId ? { routerId, status: str(a.status), confidence: numOrNull(a.confidence) } : null;
    })
    .filter((a): a is LoadAp => a !== null);
  return {
    ...parseBase(o),
    recommendations: objList(o?.recommendations).map(parseRecommendation),
    load,
    distribution: parseDistribution(o?.distribution),
  };
}

// ── Privacy ──────────────────────────────────────────────────────────────

const MAC_SEP_RE = /\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b/g;
const MAC_DOT_RE = /\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b/g;

/** Any MAC-like text (also a BSSID) becomes "[MAC]" before it is shown. */
export function scrub(text: string): string {
  return text.replace(MAC_SEP_RE, '[MAC]').replace(MAC_DOT_RE, '[MAC]');
}

// ── Numbers and time (unknown is a dash, never 0) ────────────────────────

/** German number with `digits` decimals; "—" when unknown. */
export function fmtNum(v: number | null | undefined, digits = 0): string {
  return v == null || !Number.isFinite(v) ? DASH : num(v, digits);
}

/** A 0..1 share as whole percent; "—" when unknown. */
export function fmtShare(v: number | null | undefined): string {
  return v == null || !Number.isFinite(v) ? DASH : `${fmtNum(v * 100, 0)} %`;
}

export function fmtValue(v: number, kind: ValueKind): string {
  switch (kind) {
    case 'pct': return `${fmtNum(v, 1)} %`;
    case 'dbm': return `${fmtNum(v, 0)} dBm`;
    case 'per_packet': return `${fmtNum(v, 2)} je Paket`;
    case 'score': return fmtNum(v, 0);
    default: return fmtNum(v, 0);
  }
}

/** Epoch seconds as local date and time; unknown is "—". */
export function formatTs(ts: number | null | undefined): string {
  if (ts == null || !Number.isFinite(ts) || ts <= 0) return DASH;
  const d = new Date(ts * 1000);
  if (Number.isNaN(d.getTime())) return DASH;
  return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

export function formatTime(ts: number | null | undefined): string {
  if (ts == null || !Number.isFinite(ts) || ts <= 0) return DASH;
  return new Date(ts * 1000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
}

// ── Labels ───────────────────────────────────────────────────────────────

const STATE_TEXT: Record<MetricState, string> = {
  measured: 'gemessen',
  no_data: 'keine Daten',
  unsupported: 'nicht unterstützt',
  unreachable: 'nicht erreichbar',
  stale: 'veraltet',
};

/** German text of a capability state; null is "nicht bewertet" (its read is off). */
export function stateText(state: MetricState | null | undefined): string {
  return state ? STATE_TEXT[state] : 'nicht bewertet';
}

export const REASON_TEXT: Record<string, string> = {
  // module (rf_center)
  no_core: 'der Enterprise Core läuft nicht',
  module_key_missing: 'der Schlüssel des Moduls fehlt (Enterprise Core noch nicht verbunden)',
  router_id_missing: 'einem Router fehlt die Router-Kennung',
  no_poll_data: 'noch keine Abfrage ausgewertet',
  collector_error: 'Fehler beim Lesen am Router',
  round_timeout: 'die Abfrage hat zu lange gedauert',
  radio_evaluation: 'die Auswertung eines Funkmoduls ist fehlgeschlagen',
  router_restart: 'der Router wurde neu gestartet',
  no_evaluation: 'noch keine Auswertung',
  // router state and reads (rf_center / rf_collector)
  ok: 'liefert Daten',
  no_data: 'noch keine Daten',
  not_ready: 'nicht bereit',
  source_unreachable: 'Quelle nicht erreichbar',
  error: 'Fehler',
  option_off: 'Abfrage in den Optionen aus',
  capability_unavailable: 'der Router erlaubt die Abfrage nicht (ACL)',
  paused: 'pausiert (Last oder SSH-Rückfall)',
  // utilization (rf_utilization.UnknownReason)
  no_previous: 'erst ein Messpunkt',
  radio_mismatch: 'Messpunkte gehören zu verschiedenen Funkmodulen',
  source_mismatch: 'Messpunkte aus verschiedenen Quellen',
  time_not_advancing: 'Zähler laufen nicht weiter',
  gap_too_large: 'Lücke zwischen den Messpunkten zu groß',
  uptime_mismatch: 'Laufzeit des Routers passt nicht zur Messzeit',
  channel_changed: 'der Kanal wurde gewechselt',
  counter_reset: 'Zähler zurückgesetzt',
  missing_field: 'Feld fehlt in der Antwort',
  active_too_small: 'Messzeit zu kurz',
  implausible: 'unplausibler Wert',
};

/** German text of a reason token; an unknown token is shown as itself (scrubbed). */
export function reasonText(token: string | null | undefined): string {
  if (!token) return DASH;
  return REASON_TEXT[token] ?? scrub(token);
}

const BAND_LABEL: Record<string, string> = { '2.4g': '2,4 GHz', '5g': '5 GHz', '6g': '6 GHz' };

export function bandLabel(band: string | null | undefined): string {
  if (!band) return 'Band unbekannt';
  return BAND_LABEL[band] ?? scrub(band);
}

export const METRIC_LABEL: Record<string, string> = {
  channel: 'Kanal', width: 'Kanalbreite', txpower: 'Sendeleistung', txpower_max: 'max. Sendeleistung',
  noise: 'Rauschen', busy_time: 'Belegt-Zeit', active_time: 'Aktiv-Zeit', rx_time: 'Empfangszeit (Survey)',
  tx_time: 'Sendezeit (Survey)', utilization: 'Kanalauslastung', client_airtime: 'Airtime je Client',
  clients: 'Clients', rssi: 'Signal (RSSI)', rate: 'Datenrate', retries: 'Wiederholungen', failed: 'Fehlgeschlagen',
  connected_time: 'Verbindungsdauer', freqlist: 'Kanalliste', country: 'Land', scan: 'Scan (Nachbarnetze)',
};

/** Metrics whose source is a survey or a scan: the scan warning sits next to them. */
export const SCAN_METRICS: readonly string[] = ['rx_time', 'tx_time', 'scan'];

/** "Router 111111" from a Core router id; the radio is the UCI radio name. */
export function routerLabel(routerId: string): string {
  const m = /^rtr_([0-9a-f]{6})/.exec(routerId);
  return m ? `Router ${m[1]}` : `Router ${scrub(routerId).slice(0, 12)}`;
}

export function radioLabel(ref: Ref): string {
  return `${routerLabel(ref.routerId)} · ${scrub(ref.radioId)}`;
}

// ── Status, health, metrics ──────────────────────────────────────────────

export interface StatusView {
  label: string;
  tone: Tone;
  reasons: string[];
}

export function statusView(s: RfStatus | null, reasons: readonly string[]): StatusView {
  const texts = reasons.map(reasonText);
  switch (s) {
    case 'ready': return { label: 'bereit', tone: 'info', reasons: texts };
    case 'not_ready': return { label: 'nicht bereit', tone: 'warn', reasons: texts };
    case 'off': return { label: 'aus', tone: 'muted', reasons: texts };
    default: return { label: 'unbekannt', tone: 'muted', reasons: texts };
  }
}

const GRADE_TEXT: Record<string, string> = {
  excellent: 'sehr gut', good: 'gut', fair: 'mäßig', poor: 'schlecht', unknown: 'unbekannt',
};

/** Below this coverage a known score is no all-clear (shown neutral). */
export const MIN_HEALTH_COVERAGE = 0.5;

export interface HealthView {
  /** The score as text; null when there is no rating. */
  value: string | null;
  text: string;
  tone: Tone;
  note: string;
}

export function healthView(h: Health, s: RfStatus | null): HealthView {
  const why = h.withheld.map(reasonText).join(' · ');
  if (s !== 'ready') {
    const label = statusView(s, []).label;
    return { value: null, text: `${DASH} ${label}`, tone: 'muted', note: why || 'Ohne Auswertung gibt es keine Bewertung.' };
  }
  if (h.score === null) {
    return {
      value: null, text: `${DASH} keine Bewertung`, tone: 'muted',
      note: why || 'Zu wenig Messwerte für eine Bewertung.',
    };
  }
  const value = fmtNum(h.score, 0);
  const notes = [`Abdeckung ${fmtShare(h.coverage)}`];
  const low = h.coverage === null || h.coverage < MIN_HEALTH_COVERAGE;
  if (low) notes.push('geringe Abdeckung, nur eingeschränkt aussagekräftig');
  if (h.capped) notes.push('gedeckelt, weil Messwerte fehlen');
  const grade = h.grade ?? 'unknown';
  let tone: Tone = 'muted';
  if (grade === 'poor') tone = 'critical';
  else if (grade === 'fair') tone = 'warn';
  else if (grade === 'good' || grade === 'excellent') tone = low || h.capped ? 'info' : 'ok';
  return { value, text: `${value} / 100 (${GRADE_TEXT[grade] ?? scrub(grade)})`, tone, note: notes.join(' · ') };
}

export interface MetricView {
  known: boolean;
  text: string;
  /** State token behind an unknown value (no_data, unsupported, …, not_assessed); null when known. */
  reason: string | null;
  reasonText: string | null;
  tone: Tone;
}

export function metricView(m: Metric | null | undefined, kind: ValueKind): MetricView {
  if (!m) {
    return { known: false, text: `${DASH} nicht bewertet`, reason: 'not_assessed', reasonText: 'nicht bewertet (Abfrage aus)', tone: 'muted' };
  }
  if (m.state === 'measured' && m.value !== null) {
    return { known: true, text: fmtValue(m.value, kind), reason: null, reasonText: null, tone: 'info' };
  }
  if (m.state === 'stale') {
    const last = m.value !== null ? ` (zuletzt ${fmtValue(m.value, kind)})` : '';
    return { known: false, text: `${DASH} veraltet${last}`, reason: 'stale', reasonText: STATE_TEXT.stale, tone: 'muted' };
  }
  const reason = m.state && m.state !== 'measured' ? m.state : 'no_data';
  const rt = m.state ? STATE_TEXT[reason as MetricState] : 'unbekannt';
  return { known: false, text: `${DASH} ${rt}`, reason, reasonText: rt, tone: 'muted' };
}

/** A count that may be unknown: "—" with a reason, never 0. */
export function countText(v: number | null, why = 'keine Daten'): string {
  return v === null ? `${DASH} ${why}` : fmtNum(v, 0);
}

// ── Errors ───────────────────────────────────────────────────────────────

/** A failed request: status and code only, never the server message. */
export class WifiApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly details: { field?: string; reason?: string };

  constructor(status: number | null, code: string, details: { field?: string; reason?: string } = {}) {
    super(`wifi api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'WifiApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type ErrorKind = 'forbidden' | 'unavailable' | 'network' | 'invalid' | 'session' | 'other';

export interface ErrorInfo {
  kind: ErrorKind;
  message: string;
  retry: boolean;
}

const NETWORK = 'WiFi Intelligence ist nicht erreichbar: keine Verbindung zu Home Assistant. Bitte erneut versuchen.';

export function errorInfo(err: unknown): ErrorInfo {
  if (!(err instanceof WifiApiError)) {
    const name = (err as { name?: unknown } | null)?.name;
    if (err instanceof TypeError || name === 'AbortError' || name === 'NetworkError') {
      return { kind: 'network', message: NETWORK, retry: true };
    }
    return { kind: 'other', message: 'Unerwarteter Fehler im Panel.', retry: true };
  }
  switch (err.status) {
    case null:
      return { kind: 'network', message: NETWORK, retry: true };
    case 400:
      return { kind: 'invalid', message: 'Die Anfrage wurde vom Server nicht akzeptiert.', retry: false };
    case 401:
      return { kind: 'session', message: 'Die Sitzung ist abgelaufen. Bitte die Seite neu laden.', retry: false };
    case 403:
      return {
        kind: 'forbidden',
        message: err.details.reason === 'refused'
          ? 'Admin nötig: Der Enterprise Core hat die Freigabe abgelehnt.'
          : 'Admin nötig: Diese Ansicht ist Administratoren vorbehalten.',
        retry: false,
      };
    case 410:
      return { kind: 'unavailable', message: 'WiFi Intelligence ist nicht verfügbar: die Integration ist nicht geladen.', retry: true };
    case 503:
      return {
        kind: 'unavailable',
        message: err.code === 'no_core'
          ? 'WiFi Intelligence ist nicht verfügbar: der Enterprise Core läuft nicht.'
          : 'WiFi Intelligence ist nicht verfügbar: das Modul läuft gerade nicht.',
        retry: true,
      };
    default:
      return { kind: 'other', message: 'Die Anfrage ist fehlgeschlagen.', retry: err.status >= 500 };
  }
}

// ── Polling ──────────────────────────────────────────────────────────────

/** The poll interval, never below POLL_MIN_MS. */
export function pollDelay(ms: number): number {
  return Number.isFinite(ms) ? Math.max(ms, POLL_MIN_MS) : POLL_MIN_MS;
}

/** Fetch only while visible, and only when the last fetch is old enough. */
export function shouldFetch(a: { visible: boolean; lastMs: number | null; nowMs: number; intervalMs: number }): boolean {
  if (!a.visible) return false;
  return a.lastMs === null || a.nowMs - a.lastMs >= pollDelay(a.intervalMs);
}

// ── Timeline ─────────────────────────────────────────────────────────────

const ROUTER_ID_RE = /^rtr_[0-9a-f]{32}$/;
const RADIO_ID_RE = /^[A-Za-z0-9._:@-]{1,128}$/;

export function isRouterId(v: unknown): v is string {
  return typeof v === 'string' && ROUTER_ID_RE.test(v);
}
export function isRadioId(v: unknown): v is string {
  return typeof v === 'string' && RADIO_ID_RE.test(v) && !v.includes('..');
}

/** Query string of the timeline route; anything off the fixed lists is refused before a request. */
export function timelineQuery(q: TimelineQuery): string {
  const bad = (field: string) => new WifiApiError(400, 'invalid_request', { field });
  if (!WINDOWS.includes(q.window)) throw bad('window');
  const params = new URLSearchParams({ window: q.window });
  if (q.radioId != null) {
    if (!isRadioId(q.radioId)) throw bad('radio_id');
    params.set('radio_id', q.radioId);
  }
  if (q.routerId != null) {
    if (!isRouterId(q.routerId)) throw bad('router_id');
    params.set('router_id', q.routerId);
  }
  if (q.series != null) {
    if (!SERIES_IDS.includes(q.series)) throw bad('series');
    params.set('series', q.series);
  }
  return params.toString();
}

export interface LinePath {
  known: boolean;
  /** Polyline point lists ("x,y x,y"), one per run without a gap. */
  segments: string[];
  /** Single points between two gaps. */
  dots: { x: number; y: number }[];
  min: number | null;
  max: number | null;
}

const r1 = (v: number) => Math.round(v * 10) / 10;

/** Scale the points into a width × height box; a null mean is a gap, never 0. */
export function linePath(points: readonly { ts: number; mean: number | null }[], width: number, height: number): LinePath {
  const known = points.filter((p): p is { ts: number; mean: number } => p.mean !== null);
  if (known.length === 0 || points.length === 0) return { known: false, segments: [], dots: [], min: null, max: null };
  const min = Math.min(...known.map(p => p.mean));
  const max = Math.max(...known.map(p => p.mean));
  const t0 = points[0].ts;
  const t1 = points[points.length - 1].ts;
  const x = (ts: number) => r1(t1 === t0 ? width / 2 : ((ts - t0) / (t1 - t0)) * width);
  const y = (v: number) => r1(max === min ? height / 2 : height - ((v - min) / (max - min)) * height);
  const segments: string[] = [];
  const dots: { x: number; y: number }[] = [];
  let run: { x: number; y: number }[] = [];
  const flush = () => {
    if (run.length === 1) dots.push(run[0]);
    else if (run.length > 1) segments.push(run.map(p => `${p.x},${p.y}`).join(' '));
    run = [];
  };
  for (const p of points) {
    if (p.mean === null) flush();
    else run.push({ x: x(p.ts), y: y(p.mean) });
  }
  flush();
  return { known: true, segments, dots, min, max };
}

// ── Channel map ──────────────────────────────────────────────────────────

export interface ChannelRow {
  channel: number | null;
  own: { key: string; label: string; width: string; clients: string; backhaul: boolean; util: MetricView }[];
  /** Foreign networks: a count when measured, else "—" with the reason (never an SSID). */
  foreign: { known: boolean; text: string };
}

export interface BandRows {
  band: string;
  label: string;
  channels: ChannelRow[];
}

const SCAN_STATE_RANK: MetricState[] = ['measured', 'stale', 'no_data', 'unreachable', 'unsupported'];

/**
 * Channels per band with the own radios. The backend sends no count of
 * foreign networks (no scan in this release); the scan capability of the
 * radios on the channel says why it is unknown.
 */
export function channelRows(map: ChannelMap, radios: RadiosView | null): BandRows[] {
  const scanOf = new Map<string, MetricState | null>();
  for (const r of radios?.radios ?? []) scanOf.set(`${r.routerId}/${r.radioId}`, r.capabilities.states.scan ?? null);
  return map.bands.map(({ band, entries }) => {
    const byChannel = new Map<number | null, ChannelEntry[]>();
    for (const e of entries) byChannel.set(e.channel, [...(byChannel.get(e.channel) ?? []), e]);
    const channels = [...byChannel.entries()]
      .sort(([a], [b]) => (a ?? Infinity) - (b ?? Infinity))
      .map(([channel, list]): ChannelRow => {
        const states = list.map(e => scanOf.get(`${e.routerId}/${e.radioId}`) ?? null);
        const best = SCAN_STATE_RANK.find(s => states.includes(s)) ?? null;
        return {
          channel,
          own: list.map(e => ({
            key: `${e.routerId}/${e.radioId}`,
            label: radioLabel(e),
            width: e.widthMhz === null ? `${DASH} Breite unbekannt` : `${fmtNum(e.widthMhz)} MHz`,
            clients: countText(e.clientCount),
            backhaul: e.backhaul === true,
            util: metricView(e.utilization, 'pct'),
          })),
          foreign: { known: false, text: `${DASH} ${best === 'measured' ? 'keine Daten' : stateText(best)}` },
        };
      });
    return { band, label: bandLabel(band), channels };
  });
}

export const CONFLICT_KIND_TEXT: Record<string, string> = {
  co_channel: 'gleicher Kanal',
  adjacent_overlap: 'überlappende Kanäle',
  non_standard_24: '2,4 GHz außerhalb von 1/6/11',
  wide_channel_24: 'breiter Kanal auf 2,4 GHz',
  uneven_distribution: 'ungleiche Kanalverteilung',
};
export const CONFLICT_STATUS_TEXT: Record<string, string> = {
  potential: 'möglich (nur Kanalplan)',
  measured: 'gemessen bestätigt',
  acceptable: 'laut Messung unkritisch',
};

// ── Recommendations ──────────────────────────────────────────────────────

const PROBLEM_TEXT: Record<string, string> = {
  sustained_high_utilization: 'Die Kanalauslastung ist dauerhaft hoch.',
  potential_overlap: 'Laut Kanalplan überlappt das Funkmodul möglicherweise mit einem anderen.',
  wide_channel_overlap: 'Der breite Kanal überlappt andere Funkmodule.',
  cell_too_large_suspected: 'Die Funkzelle ist vermutlich zu groß (Clients bleiben hängen).',
  coverage_too_weak_suspected: 'Die Abdeckung ist vermutlich zu schwach.',
  ap_overloaded: 'Der Access Point ist überlastet.',
  ap_load_elevated: 'Der Access Point ist stark belastet.',
  load_hints_without_utilization: 'Es gibt Lasthinweise, aber keine gemessene Kanalauslastung.',
  band_imbalance: 'Die Clients sind ungleich auf die Bänder verteilt.',
  uneven_client_distribution: 'Die Clients sind ungleich auf die Access Points verteilt.',
};

const BASIS_TEXT: Record<string, string> = {
  lower_observed_utilization: 'Auf dem vorgeschlagenen Kanal wurde weniger Auslastung gemessen.',
  fewer_managed_radios_on_channel: 'Auf dem vorgeschlagenen Kanal laufen weniger eigene Funkmodule (nur Planung, keine Messung).',
  channel_plan: 'Nur aus dem Kanalplan abgeleitet.',
};

const EFFECT_TEXT: Record<string, string> = {
  none_without_admin_review: 'keine, solange niemand prüft',
  enables_channel_recommendation: 'ermöglicht eine Kanalempfehlung',
  lower_channel_utilization: 'geringere Kanalauslastung erwartet',
  unknown_no_comparison_data: 'unbekannt (keine Vergleichsdaten)',
  less_overlap: 'weniger Überlappung',
  fewer_sticky_clients: 'weniger hängende Clients',
  better_downlink_for_weak_clients: 'besserer Empfang für schwache Clients',
};

const RISK_TEXT: Record<string, string> = {
  clients_reconnect_on_change: 'Clients verbinden sich beim Wechsel neu',
  dfs_radar_may_force_change: 'DFS: ein Radar kann einen Kanalwechsel erzwingen',
  dfs_cac_outage: 'DFS: Funkpause während der Kanalprüfung (CAC)',
  uplink_loss_on_change: 'die WLAN-Verbindung zwischen Routern kann beim Wechsel abreißen',
  ap_power_does_not_fix_client_uplink: 'mehr Sendeleistung am AP verbessert nicht den Rückweg der Clients',
  coverage_gaps_possible: 'Abdeckungslücken möglich',
  more_co_channel_interference: 'mehr Störungen auf demselben Kanal',
  lower_peak_throughput: 'geringerer Spitzendurchsatz',
  possible_uplink_parent: 'könnte Gegenstelle einer WLAN-Verbindung zwischen Routern sein',
};

const REQUIRES_TEXT: Record<string, string> = {
  freqlist: 'Kanalliste des Funkmoduls',
  per_channel_utilization: 'Auslastung je Kanal zum Vergleich',
  utilization: 'gemessene Kanalauslastung',
};

const PRIORITY_TEXT: Record<string, { label: string; tone: Tone }> = {
  normal: { label: 'normal', tone: 'warn' },
  low: { label: 'niedrig', tone: 'info' },
};

function param(p: Record<string, string | number>, key: string): string | null {
  const v = p[key];
  if (typeof v === 'number') return fmtNum(v, 0);
  return typeof v === 'string' ? scrub(v) : null;
}

function actionText(action: string | null, p: Record<string, string | number>): string {
  const width = param(p, 'width_mhz');
  switch (action) {
    case 'change_channel': {
      const ch = param(p, 'channel');
      return ch ? `Kanal ${ch}${width ? ` (${width} MHz)` : ''} prüfen und bei Bedarf selbst einstellen` : 'Anderen Kanal prüfen';
    }
    case 'review_channel_plan': return 'Kanalplan prüfen';
    case 'review_backhaul_channel': return 'Kanal der WLAN-Verbindung zwischen Routern prüfen';
    case 'collect_channel_list': return 'Kanalliste erheben (Option „Kanal- und Sendeleistungsgrenzen beim Start“)';
    case 'change_width': return width ? `Kanalbreite ${width} MHz prüfen` : 'Kleinere Kanalbreite prüfen';
    case 'review_backhaul_width': return 'Kanalbreite der WLAN-Verbindung zwischen Routern prüfen';
    case 'adjust_tx_power': {
      const dbm = param(p, 'dbm');
      const dir = p.direction === 'lower' ? 'senken' : p.direction === 'raise' ? 'erhöhen' : 'anpassen';
      return `Sendeleistung ${dir} prüfen${dbm ? ` (etwa ${dbm} dBm)` : ''}`;
    }
    case 'review_backhaul_tx_power': return 'Sendeleistung der WLAN-Verbindung zwischen Routern prüfen';
    case 'review_ap_placement': return 'Standort des Access Points prüfen';
    case 'review_ap_load': return 'Last des Access Points prüfen';
    case 'collect_utilization': return 'Kanalauslastung erheben (Option „Kanalauslastung aus hostapd“)';
    case 'review_band_settings': return 'Band-Einstellungen prüfen';
    case 'review_client_distribution': return 'Verteilung der Clients prüfen';
    default: return action ? scrub(action) : 'Empfehlung ohne Code';
  }
}

export interface RecommendationViewT {
  title: string;
  reason: string;
  effect: string;
  evidence: string[];
  level: string;
  levelTone: Tone;
  confidence: string;
  risks: string[];
  requires: string[];
  target: string;
}

export function recommendationView(rec: Recommendation): RecommendationViewT {
  const problem = rec.problem ? PROBLEM_TEXT[rec.problem] ?? scrub(rec.problem) : 'Grund nicht angegeben.';
  const basis = rec.basis ? BASIS_TEXT[rec.basis] ?? scrub(rec.basis) : null;
  const prio = rec.priority ? PRIORITY_TEXT[rec.priority] : undefined;
  let target = 'ganzes Netz';
  if (rec.target) {
    target = rec.target.radioId ? radioLabel({ routerId: rec.target.routerId, radioId: rec.target.radioId }) : routerLabel(rec.target.routerId);
  }
  return {
    title: actionText(rec.action, rec.actionParams),
    reason: basis ? `${problem} ${basis}` : problem,
    effect: rec.expectedEffect ? EFFECT_TEXT[rec.expectedEffect] ?? scrub(rec.expectedEffect) : `${DASH} nicht angegeben`,
    evidence: rec.evidence.map(scrub),
    level: prio?.label ?? (rec.priority ? scrub(rec.priority) : 'unbekannt'),
    levelTone: prio?.tone ?? 'muted',
    confidence: rec.confidence === null ? `Sicherheit ${DASH} unbekannt` : `Sicherheit ${fmtNum(rec.confidence * 100, 0)} %`,
    risks: rec.risk.map(r => RISK_TEXT[r] ?? scrub(r)),
    requires: rec.requires.map(r => REQUIRES_TEXT[r] ?? scrub(r)),
    target,
  };
}

export const LOAD_TEXT: Record<string, { label: string; tone: Tone }> = {
  ok: { label: 'unauffällig', tone: 'ok' },
  elevated: { label: 'erhöht', tone: 'warn' },
  overloaded: { label: 'überlastet', tone: 'critical' },
  unknown: { label: `${DASH} unbekannt`, tone: 'muted' },
};

export function loadView(status: string | null): { label: string; tone: Tone } {
  return (status && LOAD_TEXT[status]) || LOAD_TEXT.unknown;
}

// ── Roaming ──────────────────────────────────────────────────────────────

export interface SumView {
  text: string;
  /** Some radios had no value: the sum is a lower bound. */
  partial: boolean;
}

function sumOf(values: (number | null)[]): SumView {
  const known = values.filter((v): v is number => v !== null);
  if (known.length === 0) return { text: `${DASH} keine Daten`, partial: false };
  return { text: fmtNum(known.reduce((a, b) => a + b, 0), 0), partial: known.length < values.length };
}

export function roamingSummary(view: RadiosView): { roams: SumView; problemClients: SumView; flagged: SumView; weak: SumView } {
  const r = view.radios;
  return {
    roams: sumOf(r.map(x => x.roams1h)),
    problemClients: sumOf(r.map(x => x.clients.problem)),
    flagged: sumOf(r.map(x => x.clients.flagged)),
    weak: sumOf(r.map(x => x.clients.weak)),
  };
}

// ── Roaming details: admin approval per panel session ────────────────────

/**
 * idle → confirm (dialog with an explicit tick) → loading (the one GET that
 * makes the backend ask the Core guard) → approved; a 403 ends in refused
 * ("Admin nötig"), any other error in failed. Nothing is fetched before the
 * tick and the confirm click.
 */
export type ApprovalStep = 'idle' | 'confirm' | 'loading' | 'approved' | 'refused' | 'failed';

export interface ApprovalState {
  step: ApprovalStep;
  ack: boolean;
  error: unknown;
}

export type ApprovalEvent =
  | { type: 'open' }
  | { type: 'ack'; value: boolean }
  | { type: 'cancel' }
  | { type: 'submit' }
  | { type: 'loaded' }
  | { type: 'failed'; error: unknown }
  | { type: 'reset' };

export const APPROVAL_INIT: ApprovalState = { step: 'idle', ack: false, error: null };

export function approvalReduce(s: ApprovalState, e: ApprovalEvent): ApprovalState {
  switch (e.type) {
    case 'open':
      return s.step === 'idle' || s.step === 'refused' || s.step === 'failed' ? { step: 'confirm', ack: false, error: null } : s;
    case 'ack':
      return s.step === 'confirm' ? { ...s, ack: e.value } : s;
    case 'cancel':
      return s.step === 'confirm' ? APPROVAL_INIT : s;
    case 'submit':
      return s.step === 'confirm' && s.ack ? { ...s, step: 'loading' } : s;
    case 'loaded':
      return s.step === 'loading' || s.step === 'approved' ? { step: 'approved', ack: true, error: null } : s;
    case 'failed':
      if (s.step !== 'loading' && s.step !== 'approved') return s;
      return { step: errorInfo(e.error).kind === 'forbidden' ? 'refused' : 'failed', ack: false, error: e.error };
    case 'reset':
      return APPROVAL_INIT;
    default:
      return s;
  }
}

/** Details may be requested: only an approved state of an admin session. */
export function mayLoadDetails(admin: boolean, s: ApprovalState): boolean {
  return admin && (s.step === 'loading' || s.step === 'approved');
}

// ── Overview counts ──────────────────────────────────────────────────────

/**
 * The backend sends 0 conflicts / recommendations / clients when no radio
 * was evaluated; without a radio those are unknown, not 0.
 */
export function overviewCounts(o: Overview): { name: string; text: string; known: boolean }[] {
  const evaluated = o.counts.radios !== null && o.counts.radios > 0;
  const c = (name: string, v: number | null, needsRadios = true) => {
    const known = v !== null && (!needsRadios || evaluated);
    return { name, text: known ? fmtNum(v, 0) : `${DASH} keine Daten`, known };
  };
  return [
    c('Ausgewertete Radios', o.counts.radios, false),
    c('Clients', o.counts.clients),
    c('Kanalkonflikte', o.counts.conflicts),
    c('davon gemessen', o.counts.conflictsMeasured),
    c('Empfehlungen', o.counts.recommendations),
  ];
}
