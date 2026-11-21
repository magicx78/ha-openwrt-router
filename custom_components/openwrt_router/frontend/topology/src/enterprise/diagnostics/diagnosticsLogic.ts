/**
 * diagnosticsLogic.ts — pure logic of the Network Diagnostics tab.
 *
 * Parsers (server JSON -> view types), German texts per code / token, state
 * and tone mapping, score / coverage display, error and Retry-After mapping,
 * the history table rows, the manual-run and settings-form helpers. No React,
 * no DOM, no network: node --test imports it.
 *
 * Hard rules kept here:
 *  - Unknown is never healthy: a missing / null / wrongly typed value stays
 *    null and is shown as "unbekannt" / "k. A." with the muted tone, never as
 *    0, "gesund" or green. A stage that is not delivered is unknown. Two
 *    address families that disagree show the worse state (unknown beats
 *    healthy).
 *  - Targets are IDs from the settings' target list; this module never
 *    builds a run from a host or an address.
 *  - Free text of the server is never shown: error messages are dropped,
 *    errors map from status / code; unknown tokens are shown as unknown.
 */

import { routerLabel } from '../wifi/wifiLogic.ts';
import type {
  ChainStage,
  Finding,
  Fleet,
  GatewayView,
  HistorySeries,
  HistoryView,
  LastRun,
  LoadView,
  ModuleState,
  Overview,
  PointScore,
  PointView,
  RunResult,
  RunResultEntry,
  Settings,
  SettingsDraft,
  SettingsTarget,
  SettingsUpdate,
  SettingsView,
  StageId,
  StageState,
  TargetStatus,
  Tone,
  WindowSummary,
} from './diagnosticsTypes';

// ── Constants ────────────────────────────────────────────────────────────

export const TAB_ID = 'diagnostics';
export const TAB_TITLE = 'Netzwerkdiagnose';
export const TAB_TITLE_EN = 'Network Diagnostics';

/** Mirrors DIAG_MAX_TARGETS (const.py). */
export const MAX_RUN_TARGETS = 16;
/** Mirrors DIAG_MIN/MAX_INTERVAL_SECONDS (const.py). */
export const INTERVAL_MIN_S = 60;
export const INTERVAL_MAX_S = 86400;
/** Below this coverage (percent) a score is low-confidence (diag_score.MIN_COVERAGE). */
export const MIN_COVERAGE_PCT = 50;

const DEFAULT_WINDOWS = ['1h', '24h', '7d', '30d'];
const TARGET_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const RETRY_AFTER_MAX_S = 86_400;

export const STAGE_ORDER: readonly StageId[] = ['router', 'gateway', 'wan', 'internet', 'dns'];
export const STAGE_LABEL: Record<string, string> = {
  router: 'Router', gateway: 'Gateway', wan: 'WAN', internet: 'Internet', dns: 'DNS',
};

// ── Small parse helpers ──────────────────────────────────────────────────

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function bool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : [];
}
function objList(v: unknown): Obj[] {
  return Array.isArray(v) ? v.map(obj).filter((x): x is Obj => x !== null) : [];
}

/** Look a token up in a label map; an unknown token is shown as itself. */
export function label(map: Record<string, string>, key: string | null | undefined): string {
  if (!key) return '–';
  return map[key] ?? key;
}

// ── Number / time formatting (missing is text, never 0) ──────────────────

/** Shown for a value that was not measured (never 0). */
export const NO_VALUE = 'k. A.';

function dec(v: number): string {
  return String(Math.round(v * 10) / 10).replace('.', ',');
}
export function formatMs(v: unknown): string {
  const n = num(v);
  return n === null ? NO_VALUE : `${dec(n)} ms`;
}
export function formatPct(v: unknown): string {
  const n = num(v);
  return n === null ? NO_VALUE : `${dec(n)} %`;
}
/** A 0..1 share as percent. */
export function formatCoverage(v: unknown): string {
  const n = num(v);
  return n === null ? NO_VALUE : `${Math.round(n * 100)} %`;
}
export function formatCount(v: unknown): string {
  const n = num(v);
  return n === null ? NO_VALUE : String(Math.round(n));
}

/** Epoch seconds as local date and time; null / invalid = "unbekannt". */
export function formatTs(ts: unknown): string {
  const n = num(ts);
  if (n === null || n <= 0) return 'unbekannt';
  const d = new Date(n * 1000);
  if (Number.isNaN(d.getTime())) return 'unbekannt';
  return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

/** "vor 5 Minuten" for epoch seconds `ts` at `nowMs`; null when unknown. */
export function formatAge(ts: unknown, nowMs: number): string | null {
  const n = num(ts);
  if (n === null || n <= 0) return null;
  const s = Math.max(0, Math.round(nowMs / 1000 - n));
  if (s < 60) return 'gerade eben';
  if (s < 3600) return `vor ${Math.floor(s / 60)} Min.`;
  if (s < 86_400) return `vor ${Math.floor(s / 3600)} Std.`;
  return `vor ${Math.floor(s / 86_400)} Tagen`;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Wait time in plain words (rounded up). */
export function formatWait(seconds: number): string {
  const s = Math.max(1, Math.ceil(seconds));
  if (s < 60) return plural(s, 'Sekunde', 'Sekunden');
  if (s < 3600) return plural(Math.ceil(s / 60), 'Minute', 'Minuten');
  return plural(Math.ceil(s / 3600), 'Stunde', 'Stunden');
}

/** Retry-After as whole seconds; anything but a plain non-negative integer is null. */
export function parseRetryAfter(header: string | null | undefined): number | null {
  if (typeof header !== 'string' || !/^\s*\d{1,7}\s*$/.test(header)) return null;
  const n = Number(header.trim());
  return n <= RETRY_AFTER_MAX_S ? n : null;
}

// ── Error ────────────────────────────────────────────────────────────────

export interface DiagErrorDetails {
  field?: string;
  reason?: string;
  state?: string;
  /** Seconds from the Retry-After header (429). */
  retryAfter?: number | null;
}

/** A failed diagnostics request. Carries status and code only, never the server message. */
export class DiagApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly details: DiagErrorDetails;

  constructor(status: number | null, code: string, details: DiagErrorDetails = {}) {
    super(`diagnostics api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'DiagApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type ErrorKind =
  | 'forbidden' | 'disabled' | 'busy' | 'conflict' | 'refused' | 'rate_limited' | 'gone'
  | 'unavailable' | 'not_found' | 'invalid' | 'too_large' | 'session' | 'network' | 'other';

export interface ErrorInfo {
  kind: ErrorKind;
  message: string;
  retry: boolean;
  /** Seconds to wait (429 only; null when the server gave no usable Retry-After). */
  waitSeconds: number | null;
}

export const ERROR_TEXT: Record<string, string> = {
  invalid_request: 'Die Eingabe wurde vom Server nicht akzeptiert.',
  body_too_large: 'Die Eingabe ist zu groß.',
  authorization_denied: 'Das dürfen nur Administratoren.',
  integration_not_loaded: 'Die Integration ist nicht geladen.',
  not_running: 'Die Netzwerkdiagnose läuft nicht.',
  disabled: 'Die Netzwerkdiagnose ist ausgeschaltet. Ein Administrator kann sie unter „Einstellungen“ einschalten.',
  unknown_target: 'Dieses Ziel ist nicht bekannt.',
  unknown_router: 'Dieser Router ist nicht bekannt.',
  busy: 'Es läuft bereits eine Diagnose. Bitte warten, bis sie fertig ist.',
  conflict: 'Die Anfrage passt nicht zum aktuellen Zustand. Bitte aktualisieren und erneut versuchen.',
  not_available: 'Im Moment nicht verfügbar.',
  no_core: 'Der Enterprise Core läuft nicht.',
  internal: 'Der Server konnte die Anfrage nicht verarbeiten.',
};

/** Reason tokens of a target (`target.<code>` or a module code). */
export const TARGET_REASON_TEXT: Record<string, string> = {
  ok: 'nutzbar',
  not_confirmed: 'noch nicht bestätigt',
  invalid_kind: 'Zieltyp hier nicht erlaubt',
  unknown_target: 'nicht bekannt',
  icmp_not_available_on_ha: 'Ping (ICMP) ist von Home Assistant aus nicht möglich',
  not_global: 'Adresse nicht zulässig (nicht öffentlich)',
  not_internal_name: 'Name nicht im internen Bereich',
  internal_name: 'Name nicht im erlaubten Bereich',
  registry_full: 'Zielliste ist voll',
  duplicate_id: 'Kennung doppelt vergeben',
};

function targetReason(reason: string | null | undefined): string | null {
  if (!reason) return null;
  const key = reason.startsWith('target.') ? reason.slice('target.'.length) : reason;
  return TARGET_REASON_TEXT[key] ?? null;
}

/** Text of a target's reason; an unknown token is "unbekannt", never echoed. */
export function targetReasonText(reason: string | null | undefined): string {
  return targetReason(reason) ?? 'unbekannt';
}

export function errorInfo(err: unknown): ErrorInfo {
  const base = { waitSeconds: null as number | null };
  if (!(err instanceof DiagApiError)) {
    const name = (err as { name?: unknown } | null)?.name;
    if (err instanceof TypeError || name === 'AbortError' || name === 'NetworkError') {
      return { kind: 'network', message: 'Keine Verbindung zu Home Assistant. Bitte erneut versuchen.', retry: true, ...base };
    }
    return { kind: 'other', message: 'Unerwarteter Fehler im Panel.', retry: true, ...base };
  }
  const known = ERROR_TEXT[err.code];
  switch (err.status) {
    case 400:
      return { kind: 'invalid', message: known ?? ERROR_TEXT.invalid_request, retry: false, ...base };
    case 401:
      return { kind: 'session', message: 'Die Sitzung ist abgelaufen. Bitte die Seite neu laden.', retry: false, ...base };
    case 403:
      return { kind: 'forbidden', message: known ?? ERROR_TEXT.authorization_denied, retry: false, ...base };
    case 404:
      return { kind: 'not_found', message: known ?? 'Nicht gefunden.', retry: false, ...base };
    case 409:
      if (err.code === 'busy') return { kind: 'busy', message: ERROR_TEXT.busy, retry: true, ...base };
      if (err.code === 'disabled' || err.details.state === 'off') {
        return { kind: 'disabled', message: ERROR_TEXT.disabled, retry: false, ...base };
      }
      return { kind: 'conflict', message: known ?? ERROR_TEXT.conflict, retry: false, ...base };
    case 410:
      return { kind: 'gone', message: ERROR_TEXT.integration_not_loaded, retry: true, ...base };
    case 413:
      return { kind: 'too_large', message: ERROR_TEXT.body_too_large, retry: false, ...base };
    case 422: {
      const why = targetReason(err.details.reason);
      return {
        kind: 'refused',
        message: why ? `Die Diagnose wurde abgelehnt: Ziel ${why}.` : 'Die Diagnose wurde abgelehnt.',
        retry: false, ...base,
      };
    }
    case 429: {
      const wait = num(err.details.retryAfter ?? null);
      return {
        kind: 'rate_limited',
        message: wait !== null
          ? `Zu viele Diagnosen in kurzer Zeit. Bitte in ${formatWait(wait)} erneut versuchen.`
          : 'Zu viele Diagnosen in kurzer Zeit. Bitte später erneut versuchen.',
        retry: true,
        waitSeconds: wait,
      };
    }
    case 503:
      return { kind: 'unavailable', message: known ?? ERROR_TEXT.not_running, retry: true, ...base };
    default:
      return { kind: 'other', message: known ?? 'Die Anfrage ist fehlgeschlagen.', retry: err.status === null || err.status >= 500, ...base };
  }
}

// ── Tones: states, stages, findings ──────────────────────────────────────

const STAGE_STATES: readonly string[] = ['healthy', 'degraded', 'failed', 'unknown', 'not_applicable'];

const STAGE_VIEW: Record<StageState, { tone: Tone; text: string }> = {
  healthy: { tone: 'ok', text: 'gesund' },
  degraded: { tone: 'warn', text: 'beeinträchtigt' },
  failed: { tone: 'critical', text: 'ausgefallen' },
  unknown: { tone: 'muted', text: 'unbekannt (nicht gemessen)' },
  not_applicable: { tone: 'muted', text: 'nicht zutreffend' },
};

/** Anything but an exact known state is unknown. */
function normState(state: unknown): StageState {
  return typeof state === 'string' && STAGE_STATES.includes(state) ? (state as StageState) : 'unknown';
}

export function stageTone(state: unknown): Tone {
  return STAGE_VIEW[normState(state)].tone;
}

export function stageView(state: unknown): { state: StageState; tone: Tone; text: string } {
  const s = normState(state);
  return { state: s, ...STAGE_VIEW[s] };
}

export interface Chip {
  stage: StageId;
  label: string;
  state: StageState;
  tone: Tone;
  text: string;
  /** Per-family / evidence detail; null when there is nothing to add. */
  detail: string | null;
}

const FAMILY_LABEL: Record<string, string> = { ipv4: 'IPv4', ipv6: 'IPv6' };
const STATE_RANK: Record<StageState, number> = { failed: 4, degraded: 3, unknown: 2, healthy: 1, not_applicable: 0 };

/** A delivered state, with "healthy" demoted to unknown when nothing backs it. */
function effectiveState(e: ChainStage): StageState {
  const s = normState(e.state);
  if (s === 'healthy' && e.basis !== 'direct' && e.basis !== 'indirect') return 'unknown';
  return s;
}

function chipFor(stage: StageId, entries: ChainStage[]): Chip {
  const states = entries.map(effectiveState);
  let state: StageState = 'unknown';
  if (states.length > 0) {
    const applicable = states.filter(s => s !== 'not_applicable');
    state = applicable.length === 0
      ? 'not_applicable'
      : applicable.reduce((a, b) => (STATE_RANK[b] > STATE_RANK[a] ? b : a));
  }
  const view = stageView(state);
  const indirect = entries.some(e => e.basis === 'indirect');
  let detail: string | null = null;
  if (entries.length > 1) {
    detail = entries
      .map((e, i) => `${label(FAMILY_LABEL, e.family) === '–' ? '?' : label(FAMILY_LABEL, e.family)}: ${stageView(states[i]).text}${e.basis === 'indirect' ? ' (indirekt)' : ''}`)
      .join(' · ');
  } else if (indirect) {
    detail = 'indirekt gemessen';
  }
  return { stage: stage, label: STAGE_LABEL[stage], ...view, detail };
}

/** Always five chips (Router, Gateway, WAN, Internet, DNS); a missing stage is unknown. */
export function chainChips(chain: unknown): Chip[] {
  const entries = Array.isArray(chain) ? (chain as ChainStage[]) : [];
  return STAGE_ORDER.map(stage => chipFor(stage, entries.filter(e => e && e.stage === stage)));
}

export const POINT_STATE: Record<string, { label: string; tone: Tone }> = {
  ok: { label: 'Kein Fehler erkannt', tone: 'ok' },
  partial: { label: 'Teilweise gemessen', tone: 'info' },
  problem: { label: 'Problem erkannt', tone: 'critical' },
  settling: { label: 'Stabilisiert sich nach Neustart', tone: 'info' },
  unknown: { label: 'Unbekannt', tone: 'muted' },
};

export const CLASS_TEXT: Record<string, string> = {
  no_fault_detected: 'Kein Fehler erkannt',
  insufficient_data: 'Zu wenig Daten für eine Aussage',
  partially_measured: 'Nur teilweise gemessen',
  router_offline: 'Router nicht erreichbar',
  management_unreachable: 'Router-Verwaltung (rpcd/uhttpd) nicht erreichbar',
  lan_problem: 'Problem im LAN',
  gateway_problem: 'Problem beim Gateway',
  routing_problem: 'Problem bei der Routenwahl (Standardroute)',
  wan_problem: 'Problem an der WAN-Verbindung',
  dns_problem: 'Internetzugang eingeschränkt (DNS-Problem)',
  internet_access_restricted: 'Internetzugang eingeschränkt (DNS-Problem)',
  single_external_service_unreachable: 'Ein einzelner externer Dienst ist nicht erreichbar',
  ipv4_only_disturbance: 'Störung nur bei IPv4',
  ipv6_only_disturbance: 'Störung nur bei IPv6',
  possible_firewall_restriction: 'Mögliche Firewall-Einschränkung',
  icmp_unanswered: 'Ping (ICMP) wird nicht beantwortet',
  gateway_changed: 'Das Gateway hat sich geändert',
  dns_server_changed: 'Der DNS-Server hat sich geändert',
};

const RECOMMENDATION_TEXT: Record<string, string> = {
  enable_more_measurements: 'Mehr Messziele einrichten, damit eine Aussage möglich wird.',
  check_router_power_and_uplink: 'Stromversorgung und Uplink des Routers prüfen.',
  check_rpcd_and_uhttpd: 'rpcd und uhttpd auf dem Router prüfen.',
  check_lan_interface_and_cabling: 'LAN-Schnittstelle und Verkabelung prüfen.',
  check_gateway_and_uplink: 'Gateway und Uplink prüfen.',
  check_default_route: 'Standardroute prüfen.',
  check_wan_connection_and_provider: 'WAN-Verbindung und Anbieter prüfen.',
  check_dns_resolver_and_upstream_dns: 'DNS-Auflösung und vorgelagerte DNS-Server prüfen.',
  check_reference_target: 'Das Messziel selbst prüfen (anderes Ziel zum Vergleich einrichten).',
  check_ipv4_configuration: 'IPv4-Konfiguration prüfen.',
  check_ipv6_configuration: 'IPv6-Konfiguration prüfen.',
  check_firewall_icmp_rules: 'Firewall-Regeln für ICMP prüfen.',
  add_tcp_or_dns_check: 'Zusätzlich ein TCP- oder DNS-Messziel einrichten.',
  review_gateway_change: 'Prüfen, ob die Gateway-Änderung beabsichtigt war.',
  review_dns_server_change: 'Prüfen, ob die DNS-Änderung beabsichtigt war.',
};

export const CAUSE_TEXT: Record<string, string> = {
  confirmed: 'bestätigt',
  probable: 'wahrscheinlich',
  possible: 'möglich',
  unknown: 'unbekannt',
};

export const REASON_TEXT: Record<string, string> = {
  disabled: 'ausgeschaltet',
  closed: 'beendet',
  core_unavailable: 'Enterprise Core nicht verfügbar',
  events_not_registered: 'Ereignisse des Cores nicht angemeldet',
  module_key_missing: 'Schlüssel des Enterprise Core fehlt',
  engine_unavailable: 'Auswertung nicht verfügbar',
  scheduler_not_running: 'Planer läuft nicht',
  no_data_yet: 'noch keine Daten',
  stale: 'Daten veraltet',
  poll_failed: 'Abfrage fehlgeschlagen',
  interface_dump_missing: 'Schnittstellendaten fehlen',
  router_id_unknown: 'Router-Kennung unbekannt',
  no_confirmed_target: 'kein bestätigtes Messziel',
  no_measurement_yet: 'noch keine Messung',
  no_executor: 'Router-Messungen nicht verfügbar',
  not_measured: 'nicht gemessen',
  ...CLASS_TEXT,
};

export function reasonTexts(reasons: readonly string[]): string[] {
  return reasons.map(r => label(REASON_TEXT, r));
}

export interface PointStateView {
  label: string;
  tone: Tone;
  reasonText: string | null;
}

export function pointStateView(p: { state?: string | null; reason?: string | null } | null | undefined): PointStateView {
  const known = p && p.state ? POINT_STATE[p.state] : undefined;
  const base = known ?? POINT_STATE.unknown;
  const reason = p?.reason ?? null;
  return { label: base.label, tone: base.tone, reasonText: reason ? label(REASON_TEXT, reason) : null };
}

export interface FindingView {
  text: string;
  tone: Tone;
  /** "bestätigt" / ... ; null for "no fault" (there is no cause to classify). */
  causeText: string | null;
  causeTone: Tone;
  recommendation: string | null;
  unmeasuredText: string | null;
}

function findingTone(f: Finding): Tone {
  const c = f.classification ?? '';
  if (!(c in CLASS_TEXT)) return 'muted';
  if (c === 'no_fault_detected') return f.severity === 'ok' ? 'ok' : 'info';
  if (c === 'insufficient_data') return 'muted';
  if (c === 'partially_measured') return 'info';
  switch (f.severity) {
    case 'critical': return 'critical';
    case 'warning': return 'warn';
    case 'info': return 'info';
    case 'ok': return 'info';
    default: return 'muted';
  }
}

export function findingView(f: Finding | null | undefined): FindingView | null {
  if (!f) return null;
  const text = (f.summary && CLASS_TEXT[f.summary])
    || (f.classification && CLASS_TEXT[f.classification])
    || f.classification || f.summary || 'unbekannt';
  const cause = f.causeClass && CAUSE_TEXT[f.causeClass] ? f.causeClass : 'unknown';
  const n = f.unmeasuredCount;
  return {
    text,
    tone: findingTone(f),
    causeText: f.classification === 'no_fault_detected' ? null : CAUSE_TEXT[cause],
    causeTone: cause === 'unknown' ? 'muted' : 'info',
    recommendation: f.recommendation ? RECOMMENDATION_TEXT[f.recommendation] ?? null : null,
    unmeasuredText: n !== null && n > 0 ? `${plural(n, 'Messpunkt', 'Messpunkte')} nicht gemessen` : null,
  };
}

// ── Module state, score ──────────────────────────────────────────────────

export interface ModuleView {
  label: string;
  tone: Tone;
  reasons: string[];
}

export function moduleView(state: ModuleState | undefined, reasons: readonly string[]): ModuleView {
  const texts = reasonTexts(reasons);
  switch (state) {
    case 'off': return { label: 'Aus', tone: 'muted', reasons: texts };
    case 'not_ready': return { label: 'Nicht bereit', tone: 'warn', reasons: texts };
    case 'ready': return { label: 'Bereit', tone: 'ok', reasons: texts };
    default: return { label: 'Unbekannt', tone: 'muted', reasons: texts };
  }
}

export interface ScoreView {
  /** The rounded score, or null (no rating). */
  value: string | null;
  text: string;
  tone: Tone;
  coverageText: string;
  low: boolean;
  note: string | null;
}

export function scoreView(f: { score: number | null; coveragePct: number | null; lowConfidence: boolean | null } | null | undefined): ScoreView {
  const score = f ? num(f.score) : null;
  const pct = f ? num(f.coveragePct) : null;
  const coverageText = pct === null ? 'Abdeckung unbekannt' : `Abdeckung ${formatPct(pct)}`;
  if (score === null) {
    return {
      value: null, text: 'keine Bewertung möglich', tone: 'muted', coverageText, low: true,
      note: 'Es liegen noch keine ausreichenden Messwerte vor.',
    };
  }
  const low = f?.lowConfidence !== false || pct === null || pct < MIN_COVERAGE_PCT;
  const value = String(Math.round(Math.min(100, Math.max(0, score))));
  let tone: Tone = 'critical';
  if (low) tone = 'info';
  else if (score >= 80) tone = 'ok';
  else if (score >= 50) tone = 'warn';
  return {
    value, text: `${value} von 100`, tone, coverageText, low,
    note: low ? 'Geringe Aussagekraft: die Abdeckung der Messungen ist niedrig oder die Beobachtungszeit kurz.' : null,
  };
}

/** Score of one point (coverage 0..1) in the same display form. */
export function pointScoreView(s: PointScore | null | undefined): ScoreView {
  return scoreView(s ? { score: s.score, coveragePct: s.coverage === null ? null : s.coverage * 100, lowConfidence: s.lowConfidence } : null);
}

// ── Parsers ──────────────────────────────────────────────────────────────

function parseState(v: unknown): ModuleState {
  return v === 'off' || v === 'not_ready' || v === 'ready' ? v : null;
}

function parseFinding(v: unknown): Finding | null {
  const o = obj(v);
  if (!o) return null;
  const unmeasured = Array.isArray(o.unmeasured) ? o.unmeasured.length : null;
  return {
    classification: str(o.classification),
    severity: str(o.severity),
    causeClass: str(o.cause_class),
    stage: str(o.stage),
    family: str(o.family),
    summary: str(o.summary),
    recommendation: str(o.recommendation),
    unmeasuredCount: num(o.unmeasured_count) ?? unmeasured,
  };
}

function parseChain(v: unknown): ChainStage[] | null {
  if (!Array.isArray(v)) return null;
  return objList(v).map(o => ({ stage: str(o.stage), family: str(o.family), state: str(o.state), basis: str(o.basis) }));
}

function parsePointScore(v: unknown): PointScore | null {
  const o = obj(v);
  if (!o) return null;
  return { score: num(o.score), coverage: num(o.coverage), lowConfidence: bool(o.low_confidence) };
}

function parseGateway(v: unknown): GatewayView | null {
  const o = obj(v);
  return o ? { reachable: bool(o.state), reason: str(o.reason) } : null;
}

function parsePoint(id: string, kind: 'ha' | 'router', v: unknown): PointView | null {
  const o = obj(v);
  if (!o) return null;
  return {
    id, kind,
    state: str(o.state),
    reason: str(o.reason),
    settling: o.settling === true,
    finding: parseFinding(o.finding),
    chain: parseChain(o.chain),
    score: parsePointScore(o.score),
    restarts24h: num(o.restarts_24h),
    downInterfaces: num(o.down_interfaces),
    gateway: parseGateway(o.gateway),
  };
}

function parseFleet(v: unknown): Fleet | null {
  const o = obj(v);
  if (!o) return null;
  const ratio = num(o.score_coverage);
  return {
    score: num(o.score),
    coveragePct: num(o.coverage) ?? (ratio === null ? null : Math.round(ratio * 100)),
    lowConfidence: bool(o.low_confidence),
    routers: num(o.routers),
    routersScored: num(o.routers_scored),
    routersUnknown: num(o.routers_unknown),
    haState: str(o.ha_state),
    findingsActive: num(o.findings_active),
    haLatencyMs: num(o.ha_latency_ms),
    haLossPct: num(o.ha_loss_pct),
    dnsMs: num(o.dns_ms),
  };
}

function parseLastRun(v: unknown): LastRun | null {
  const o = obj(v);
  return o ? { ts: num(o.ts), probes: num(o.probes) } : null;
}

export function parseOverview(raw: unknown): Overview {
  const o = obj(raw) ?? {};
  const routers = obj(o.routers);
  return {
    state: parseState(o.state),
    reasons: strList(o.reasons),
    enabled: bool(o.enabled),
    fleet: parseFleet(o.fleet),
    routers: routers
      ? Object.keys(routers).sort().map(id => parsePoint(id, 'router', routers[id])).filter((p): p is PointView => p !== null)
      : [],
    ha: parsePoint('ha', 'ha', o.ha),
    lastRun: parseLastRun(o.last_run),
  };
}

function parseSummary(v: unknown): WindowSummary | null {
  const o = obj(v);
  if (!o) return null;
  return {
    answered: num(o.answered), lost: num(o.lost), gaps: num(o.gaps), expected: num(o.expected),
    coverage: num(o.coverage), meanMs: num(o.mean_ms), jitterMs: num(o.jitter_ms), lossPct: num(o.loss_pct),
  };
}

function parseSeries(o: Obj): HistorySeries | null {
  const point = str(o.point);
  const targetId = str(o.target_id);
  if (!point || !targetId) return null;
  const w = obj(o.windows) ?? {};
  const windows: Record<string, WindowSummary | null> = {};
  for (const name of Object.keys(w)) windows[name] = parseSummary(w[name]);
  return { point, targetId, kind: str(o.kind), family: str(o.family), windows };
}

export function parseHistory(raw: unknown): HistoryView {
  const o = obj(raw) ?? {};
  const names = strList(o.windows);
  return {
    state: parseState(o.state),
    reasons: strList(o.reasons),
    windows: names.length > 0 ? names : DEFAULT_WINDOWS,
    series: Array.isArray(o.series)
      ? objList(o.series).map(parseSeries).filter((s): s is HistorySeries => s !== null)
      : null,
    gaps: num(o.gaps),
  };
}

export interface HistoryRow {
  window: string;
  hasData: boolean;
  latency: string;
  jitter: string;
  loss: string;
  gaps: string;
  coverage: string;
}

/** One row per window; a missing window or a window without answers shows "k. A.", never 0. */
export function historyRows(series: HistorySeries, windows: readonly string[] = DEFAULT_WINDOWS): HistoryRow[] {
  return windows.map(name => {
    const s = series.windows[name] ?? null;
    return {
      window: name,
      hasData: s !== null && (s.answered ?? 0) + (s.lost ?? 0) > 0,
      latency: formatMs(s?.meanMs),
      jitter: formatMs(s?.jitterMs),
      loss: formatPct(s?.lossPct),
      gaps: formatCount(s?.gaps),
      coverage: formatCoverage(s?.coverage),
    };
  });
}

/** Display name of a measurement point: the same short router name as the
 * other Enterprise tabs ("Router aaaa11"), never the full router id (1.49.3). */
export function pointName(point: string): string {
  return point === 'ha' ? 'Home Assistant' : routerLabel(point);
}

/** Series grouped by measurement point ('ha' first, then routers by id). */
export function groupByPoint(series: readonly HistorySeries[]): Array<{ point: string; series: HistorySeries[] }> {
  const map = new Map<string, HistorySeries[]>();
  for (const s of series) map.set(s.point, [...(map.get(s.point) ?? []), s]);
  return [...map.entries()]
    .sort(([a], [b]) => (a === 'ha' ? -1 : b === 'ha' ? 1 : a.localeCompare(b)))
    .map(([point, list]) => ({ point, series: list }));
}

function parseSettingsTarget(o: Obj): SettingsTarget | null {
  const id = str(o.id);
  return id ? { id, kind: str(o.kind), scope: str(o.scope), confirmed: bool(o.confirmed), port: num(o.port) } : null;
}

function parseTargetStatus(o: Obj): TargetStatus | null {
  const id = str(o.id);
  return id
    ? { id, kind: str(o.kind), scope: str(o.scope), confirmed: o.confirmed === true, usable: o.usable === true, reason: str(o.reason) }
    : null;
}

function parseSettings(v: unknown): Settings {
  const o = obj(v) ?? {};
  return {
    enabled: bool(o.enabled),
    periodic: bool(o.periodic),
    intervalS: num(o.interval_s),
    haResolverInternal: bool(o.ha_resolver_internal),
    dnsQueryName: str(o.dns_query_name),
    httpPath: str(o.http_path),
    internalNetworkCount: Array.isArray(o.internal_networks) ? o.internal_networks.length : null,
    localDomainCount: Array.isArray(o.local_domains) ? o.local_domains.length : null,
    targets: objList(o.targets).map(parseSettingsTarget).filter((t): t is SettingsTarget => t !== null),
  };
}

function parseLoad(v: unknown): LoadView | null {
  const ha = obj(obj(v)?.ha);
  if (!ha) return null;
  const limit = obj(ha.run_limit);
  return {
    packetsPerDay: num(ha.packets_per_day),
    roundsPerDay: num(ha.rounds_per_day),
    runLimitMax: num(limit?.max_runs),
    runLimitWindowS: num(limit?.window_s),
  };
}

export function parseSettingsView(raw: unknown): SettingsView {
  const o = obj(raw) ?? {};
  return {
    state: parseState(o.state),
    reasons: strList(o.reasons),
    settings: parseSettings(o.settings),
    targets: objList(o.targets).map(parseTargetStatus).filter((t): t is TargetStatus => t !== null),
    load: parseLoad(o.load),
  };
}

function parseRunEntry(o: Obj): RunResultEntry | null {
  const targetId = str(o.target_id);
  return targetId
    ? { targetId, kind: str(o.kind), family: str(o.family), outcome: str(o.outcome), rttMs: num(o.rtt_ms) }
    : null;
}

export function parseRunResult(raw: unknown): RunResult {
  const o = obj(raw) ?? {};
  return {
    status: str(o.status),
    probes: num(o.probes),
    refused: objList(o.refused)
      .map(r => ({ id: str(r.id), reason: str(r.reason) }))
      .filter((r): r is { id: string; reason: string | null } => r.id !== null),
    results: objList(o.results).map(parseRunEntry).filter((r): r is RunResultEntry => r !== null),
    finding: parseFinding(o.finding),
  };
}

// ── Admin gating ─────────────────────────────────────────────────────────

export type SectionId = 'overview' | 'history' | 'run' | 'settings';

export interface Controls {
  run: boolean;
  settings: boolean;
  sections: Array<{ id: SectionId; title: string }>;
}

const SECTION_TITLE: Record<SectionId, string> = {
  overview: 'Übersicht', history: 'Verlauf', run: 'Manuelle Diagnose', settings: 'Einstellungen',
};

/** Run and settings controls exist for administrators only (a strict `true`). */
export function controlsFor(isAdmin: unknown): Controls {
  const admin = isAdmin === true;
  const ids: SectionId[] = admin ? ['overview', 'history', 'run', 'settings'] : ['overview', 'history'];
  return { run: admin, settings: admin, sections: ids.map(id => ({ id, title: SECTION_TITLE[id] })) };
}

// ── Manual run: IDs only ─────────────────────────────────────────────────

/** Targets a run may use: configured, confirmed or internal, and not ICMP. */
export function usableTargets(targets: readonly TargetStatus[]): TargetStatus[] {
  return targets.filter(t => t.usable && t.kind !== 'icmp');
}

/**
 * The run body from the selection. Only IDs that are in the settings' target
 * list AND usable pass; a host, an address or any other text is refused.
 */
export function buildRunBody(selected: readonly string[], targets: readonly TargetStatus[]): { ids: string[]; error: string | null } {
  const ids = [...new Set(selected)];
  if (ids.length === 0) return { ids: [], error: 'Bitte mindestens ein Ziel auswählen.' };
  if (ids.length > MAX_RUN_TARGETS) return { ids: [], error: `Höchstens ${MAX_RUN_TARGETS} Ziele pro Diagnose.` };
  const allowed = new Set(usableTargets(targets).map(t => t.id));
  if (!ids.every(id => TARGET_ID_RE.test(id) && allowed.has(id))) {
    return { ids: [], error: 'Es können nur Ziele aus der Liste gewählt werden.' };
  }
  return { ids, error: null };
}

export function isTargetId(v: unknown): v is string {
  return typeof v === 'string' && TARGET_ID_RE.test(v);
}

export const OUTCOME_VIEW: Record<string, { text: string; tone: Tone }> = {
  ok: { text: 'erfolgreich', tone: 'ok' },
  nxdomain: { text: 'Name nicht gefunden (Antwort kam an)', tone: 'info' },
  failed: { text: 'fehlgeschlagen', tone: 'critical' },
  timeout: { text: 'keine Antwort (Zeitüberschreitung)', tone: 'critical' },
  servfail: { text: 'Server-Fehler', tone: 'critical' },
  refused: { text: 'abgelehnt', tone: 'warn' },
  error: { text: 'Messfehler', tone: 'warn' },
  skipped: { text: 'übersprungen (nicht gemessen)', tone: 'muted' },
};

export function outcomeView(outcome: string | null | undefined): { text: string; tone: Tone } {
  return (outcome ? OUTCOME_VIEW[outcome] : undefined) ?? { text: 'unbekannt', tone: 'muted' };
}

/** Round-trip time, only for outcomes that got an answer; otherwise "k. A.". */
export function rttText(entry: RunResultEntry): string {
  return entry.outcome === 'ok' || entry.outcome === 'nxdomain' ? formatMs(entry.rttMs) : NO_VALUE;
}

const RUN_STATUS: Record<string, { text: string; tone: Tone }> = {
  success: { text: 'Diagnose abgeschlossen', tone: 'info' },
  failure: { text: 'Diagnose fehlgeschlagen', tone: 'critical' },
  timeout: { text: 'Diagnose: Zeitüberschreitung', tone: 'warn' },
  cancelled: { text: 'Diagnose abgebrochen', tone: 'warn' },
  skipped_maintenance: { text: 'Diagnose übersprungen (Wartung)', tone: 'muted' },
};

export function runStatusView(status: string | null | undefined): { text: string; tone: Tone } {
  return (status ? RUN_STATUS[status] : undefined) ?? { text: 'Ergebnis unbekannt', tone: 'muted' };
}

// ── Settings form ────────────────────────────────────────────────────────

export function draftFromSettings(s: Settings): SettingsDraft {
  return {
    enabled: s.enabled === true,
    periodic: s.periodic === true,
    intervalS: s.intervalS === null ? '' : String(s.intervalS),
    haResolverInternal: s.haResolverInternal === true,
  };
}

/**
 * Only changed fields; only keys the backend accepts and this panel edits
 * (hosts, targets and the scope lists are never sent from here).
 */
export function buildSettingsUpdate(s: Settings, d: SettingsDraft): { update: SettingsUpdate; error: string | null } {
  const update: SettingsUpdate = {};
  if ((s.enabled === true) !== d.enabled) update.enabled = d.enabled;
  if ((s.periodic === true) !== d.periodic) update.periodic = d.periodic;
  if ((s.haResolverInternal === true) !== d.haResolverInternal) update.ha_resolver_internal = d.haResolverInternal;
  if (d.intervalS !== (s.intervalS === null ? '' : String(s.intervalS))) {
    const text = d.intervalS.trim();
    const n = /^\d{1,6}$/.test(text) ? Number(text) : NaN;
    if (!(n >= INTERVAL_MIN_S && n <= INTERVAL_MAX_S)) {
      return { update: {}, error: `Das Intervall muss eine ganze Zahl von ${INTERVAL_MIN_S} bis ${INTERVAL_MAX_S} Sekunden sein.` };
    }
    update.interval_s = n;
  }
  return { update, error: null };
}
