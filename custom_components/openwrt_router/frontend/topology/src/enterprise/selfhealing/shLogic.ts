/**
 * shLogic.ts — pure logic of the "Self-Healing" tab (read only, 1.53.0):
 * parsers of the five GET routes of heal_views.py, the error mapping, the
 * texts of codes and the small view helpers. No React, no network.
 *
 * Rule "truth or unknown": a value the server did not send, or sent in an
 * unexpected form, is null and shown as "unbekannt" (with the reason where
 * there is one), never as 0, "aus" or OK. A code without a German text is
 * shown as the raw code.
 */

import { DASH, POLL_MIN_MS, routerLabel, shouldFetch } from '../wifi/wifiLogic.ts';
import {
  ACTION_TEXT, ACTOR_TEXT, APPROVAL_TEXT, CAUSE_LEVEL_TEXT, CAUSE_STATUS_TEXT, CAUSE_TEXT, CHECK_TEXT, COMPONENT_TEXT,
  DISRUPTION_TEXT, FACT_TEXT, FAMILY_TEXT, IMPACT_TEXT, INCIDENT_TEXT, MODE_TEXT, OUTCOME_TEXT, PERMISSION_TEXT,
  PLAYBOOK_TEXT, REASON_TEXT, ROLLBACK_MECHANISM_TEXT, ROLLBACK_STATUS_TEXT, STATE_TEXT, VERIFICATION_TEXT,
} from './shTexts.ts';
import type {
  ActionList, ActionRow, Candidate, Cause, Change, Check, Contribution, Counts, Decision, Detail, Explanation, Facts,
  Factor, Flags, Gate, HistoryEntry, Hold, Impact, Overview, Plan, Policy, RecordDetail, Risk, RouterRow, RouterSetting,
  Rule, Settings,
} from './shTypes';

export { DASH, POLL_MIN_MS };

// ── Constants ────────────────────────────────────────────────────────────

export const TAB_ID = 'selfhealing';
export const TAB_TITLE = 'Self-Healing';
/** After Network Diagnostics (30), before WiFi Intelligence (40). */
export const TAB_ORDER = 35;

export const UNKNOWN = 'unbekannt';

/** The line at the top of the tab, in every state (also loading, error and off). */
export const OBSERVE_TITLE = 'Nur beobachten – diese Version ändert nie etwas an einem Router.';
export const OBSERVE_TEXT =
  'Self-Healing zeichnet in 1.53.0 Vorfälle auf, analysiert sie und zeigt, was es vorschlagen würde und warum. '
  + 'Es führt nichts aus, ruft keinen Router auf und ändert keine Konfiguration. Freigeben und Ausführen kommen frühestens mit 1.54.0; '
  + 'dieser Tab hat deshalb keine Knöpfe, die etwas ändern.';
export const ROLLBACK_LINE = 'Automatischer Rollback: auf dieser Plattform nicht verfügbar.';
export const OFF_TITLE = 'Self-Healing ist ausgeschaltet.';
export const OFF_HOW =
  'Einstellungen → Geräte & Dienste → OpenWrt Router → einen Router → Konfigurieren → „Self-Healing für alle Router“ einschalten. Der Schalter gilt für alle Router; gespeicherte Datensätze bleiben erhalten.';
export const NOT_RUNNING_TEXT = 'Self-Healing läuft gerade nicht (ausgeschaltet oder noch nicht gestartet).';
export const LOADING_TEXT = 'Self-Healing wird geladen …';
export const EMPTY_TITLE = 'Noch nichts beobachtet.';
export const EMPTY_TEXT =
  'Sobald Network Intelligence auf einem Router einen Wurzelvorfall meldet, legt Self-Healing hier einen Datensatz an und zeigt, was es vorschlagen würde. Bis dahin gibt es nichts zu zeigen – das ist kein Fehler.';
export const MASKED_TEXT =
  'Router, Vorfälle, Datensätze und Erklärungen sehen nur Administratoren. Hier stehen nur die Zahlen.';
export const NO_CANDIDATE_TEXT =
  'Der Server nennt keinen Kandidaten: Der Datensatz bewertet nur (nur lesend), eine Reparaturaktion schlägt in dieser Version keine Quelle vor.';
export const CANDIDATE_LABEL = 'Kandidat – nicht ausgeführt';
export const CANDIDATE_NOTE =
  'Nur zur Erklärung: So würde die Richtlinie über diese Aktion entscheiden. Sie ist nicht die Entscheidung des Datensatzes und wird in dieser Version nie ausgeführt.';
export const BLOCKED_RISKY_UNKNOWN =
  'Keine der lesenden Routen liefert diese Zahl in 1.53.0 (Vorabprüfungen sind nicht angebunden).';

export const RISK_TEXT: Readonly<Record<number, string>> = {
  0: 'Risiko 0 – nur lesend',
  1: 'Risiko 1 – niedrig',
  2: 'Risiko 2 – mittel',
  3: 'Risiko 3 – hoch',
};

/** Open states of a record (everything that is not terminal). */
export const OPEN_STATES: readonly string[] = [
  'detected', 'analyzed', 'proposed', 'preflight', 'waiting_approval', 'approved', 'executing', 'verifying', 'failed',
  'rollback_pending', 'rolling_back',
];
export const ALL_STATES: readonly string[] = [
  ...OPEN_STATES, 'resolved', 'rejected', 'cancelled', 'rolled_back', 'escalated', 'manual_recovery_required',
];

export const ROUTER_ID_RE = /^rtr_[0-9a-f]{32}$/;
export const ACTION_ID_RE = /^rem_[0-9a-f]{32}$/;
/** Codes the server sends (states, reasons, incident types …): never free text. */
const CODE_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

// ── Errors ───────────────────────────────────────────────────────────────

export class ShApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly details: { field?: string; reason?: string };

  constructor(status: number | null, code: string, details: { field?: string; reason?: string } = {}) {
    super(`self-healing api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'ShApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type ErrorKind = 'failed' | 'forbidden' | 'gone' | 'off' | 'missing' | 'invalid';
export interface ErrorInfo {
  kind: ErrorKind;
  message: string;
  retry: boolean;
}

/** What a failed request means. `of`: the overview (the tab's first answer) or one record. */
export function errorInfo(err: unknown, of: 'overview' | 'list' | 'record' = 'overview'): ErrorInfo {
  const failed = of === 'record'
    ? 'Der Datensatz konnte nicht geladen werden. Was angezeigt war, ist eventuell nicht mehr aktuell.'
    : 'Self-Healing konnte nicht geladen werden. Es wird nichts als „in Ordnung“ angezeigt, solange keine Antwort da ist.';
  if (!(err instanceof ShApiError)) return { kind: 'failed', message: failed, retry: true };
  switch (err.status) {
    case 401:
      return { kind: 'forbidden', message: 'Die Anmeldung ist abgelaufen. Bitte die Seite neu laden.', retry: false };
    case 403:
      return {
        kind: 'forbidden',
        message: of === 'overview'
          ? 'Nur für Administratoren. Ein Administrator kann das Panel in den Optionen („Topologie-Panel allen Benutzern anzeigen“) freigeben; dann sind die Zahlen für alle sichtbar.'
          : 'Nur für Administratoren.',
        retry: false,
      };
    case 404:
      if (err.code === 'unknown_action') {
        return { kind: 'missing', message: 'Diesen Datensatz gibt es nicht mehr (aufgeräumt oder der Speicher wurde neu angelegt).', retry: false };
      }
      // no route: the module was off when Home Assistant started (routes are registered with the first start)
      return { kind: 'off', message: NOT_RUNNING_TEXT, retry: true };
    case 410:
      return { kind: 'gone', message: 'Die Integration wurde entladen.', retry: false };
    case 503:
      if (err.code === 'not_running') return { kind: 'off', message: NOT_RUNNING_TEXT, retry: true };
      return { kind: 'failed', message: failed, retry: true };
    case 400: {
      const field = err.details.field && CODE_RE.test(err.details.field) ? err.details.field : null;
      return { kind: 'invalid', message: `Ungültige Anfrage${field ? ` (Feld ${field})` : ''}.`, retry: false };
    }
    default:
      return { kind: 'failed', message: failed, retry: true };
  }
}

// ── Reading values (unknown stays null) ─────────────────────────────────

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function int(v: unknown): number | null {
  const n = num(v);
  return n !== null && Number.isInteger(n) ? n : null;
}
function bool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}
/** A code of the server (short, no spaces); anything else is unknown. */
function code(v: unknown): string | null {
  return typeof v === 'string' && CODE_RE.test(v) ? v : null;
}
function codes(v: unknown): string[] {
  return arr(v).map(code).filter((c): c is string => c !== null);
}
function routerId(v: unknown): string | null {
  return typeof v === 'string' && ROUTER_ID_RE.test(v) ? v : null;
}
function actionId(v: unknown): string | null {
  return typeof v === 'string' && ACTION_ID_RE.test(v) ? v : null;
}

export function parseHold(v: unknown): Hold | null {
  const h = obj(v);
  if (!h) return null;
  return {
    reason: code(h.reason),
    fleet: bool(h.fleet),
    noEnd: bool(h.no_end),
    remainingS: num(h.remaining_s),
    actionId: actionId(h.action_id),
  };
}

function parseRouter(v: unknown): RouterRow | null {
  const r = obj(v);
  const id = r ? routerId(r.router_id) : null;
  if (!r || !id) return null;
  return {
    routerId: id,
    loaded: bool(r.loaded),
    configuredMode: code(r.configured_mode),
    effectiveMode: code(r.effective_mode),
    held: bool(r.held),
    hold: parseHold(r.hold),
    open: int(r.open),
  };
}

function parseCounts(v: unknown): Counts {
  const c = obj(v) ?? {};
  const by = obj(c.by_state) ?? {};
  const byState: Record<string, number> = {};
  for (const [k, n] of Object.entries(by)) {
    const value = int(n);
    if (code(k) && value !== null && value >= 0) byState[k] = value;
  }
  return { total: int(c.total), open: int(c.open), byState, routers: int(c.routers), routersHeld: int(c.routers_held) };
}

export function parseOverview(body: unknown): Overview {
  const b = obj(body) ?? {};
  const f = obj(b.fleet) ?? {};
  const routers = Array.isArray(b.routers)
    ? b.routers.map(parseRouter).filter((r): r is RouterRow => r !== null)
    : null;
  return {
    status: code(b.status),
    generatedAt: num(b.generated_at),
    releaseMode: code(b.release_mode),
    writePath: bool(b.write_path),
    automaticRollback: code(b.automatic_rollback),
    fleet: {
      paused: bool(f.paused),
      held: bool(f.held),
      pauseReason: code(f.pause_reason),
      pauseRemainingS: num(f.pause_remaining_s),
      hold: parseHold(f.hold),
    },
    counts: parseCounts(b.counts),
    lastActivity: num(b.last_activity),
    routers,
    pendingIncidents: int(b.pending_incidents),
  };
}

function parseFlags(v: unknown): Flags {
  const f = obj(v) ?? {};
  return {
    interrupted: bool(f.interrupted),
    inMaintenance: bool(f.in_maintenance),
    acknowledgedByAdmin: bool(f.acknowledged_by_admin),
    holdReleased: bool(f.hold_released),
  };
}

function parseRow(v: unknown): ActionRow | null {
  const a = obj(v);
  const id = a ? actionId(a.action_id) : null;
  if (!a || !id) return null;
  const decision = obj(a.decision);
  return {
    actionId: id,
    routerId: routerId(a.router_id),
    state: code(a.state),
    terminal: bool(a.terminal),
    createdAt: num(a.created_at),
    updatedAt: num(a.updated_at),
    actionType: code(a.action_type),
    incidentId: code(a.incident_id),
    incidentType: code(a.incident_type),
    incidentReopen: int(a.incident_reopen),
    // the list sends cause_code/cause_level and the outcome; the detail sends objects
    causeCode: code(a.cause_code) ?? code(obj(a.cause)?.code),
    causeLevel: code(a.cause_level) ?? code(obj(a.cause)?.level),
    decision: code(a.decision) ?? (decision ? code(decision.outcome) : null),
    riskClass: int(a.risk_class) ?? int(obj(a.risk)?.risk_class),
    flags: parseFlags(a.flags),
  };
}

export function parseActions(body: unknown): ActionList {
  const b = obj(body) ?? {};
  return {
    generatedAt: num(b.generated_at),
    total: int(b.total),
    limit: int(b.limit),
    offset: int(b.offset),
    actions: arr(b.actions).map(parseRow).filter((r): r is ActionRow => r !== null),
  };
}

function parseDecision(v: unknown): Decision | null {
  const d = obj(v);
  if (!d) return null;
  return {
    outcome: code(d.outcome),
    score: num(d.score),
    factors: arr(d.factors).map((x): Factor => {
      const f = obj(x) ?? {};
      return { factor: code(f.factor), value: num(f.value), reason: code(f.reason) };
    }),
    why: code(d.why),
    whyNot: code(d.why_not),
  };
}

function parseRisk(v: unknown): Risk | null {
  const r = obj(v);
  if (!r) return null;
  return { riskClass: int(r.risk_class), reasons: codes(r.reasons) };
}

function parseCause(v: unknown): Cause | null {
  const c = obj(v);
  if (!c) return null;
  return {
    code: code(c.code), status: code(c.status), level: code(c.level), confidence: num(c.confidence),
    sourceFamilies: codes(c.source_families),
  };
}

function parseChecks(v: unknown): Check[] | null {
  if (!Array.isArray(v)) return null;
  return v.map((x): Check => {
    const c = obj(x) ?? {};
    return { check: code(c.check), outcome: code(c.outcome), reason: code(c.reason) };
  });
}

function parseChanges(v: unknown): Change[] {
  return arr(v).map((x): Change => {
    const c = obj(x) ?? {};
    return { kind: code(c.kind), target: code(c.target), effect: code(c.effect) };
  });
}

function parseImpact(v: unknown): Impact | null {
  const i = obj(v);
  if (!i) return null;
  const out: Record<string, number | string | null> = {};
  for (const [k, x] of Object.entries(i)) {
    if (!code(k)) continue;
    if (Array.isArray(x)) out[k] = x.length; // dependants: router ids -> their number (never the ids)
    else out[k] = num(x) ?? code(x);
  }
  return out;
}

export function parseDetail(body: unknown): Detail {
  const b = obj(body) ?? {};
  const a = obj(b.action) ?? {};
  const row = parseRow(a) ?? {
    actionId: '', routerId: null, state: null, terminal: null, createdAt: null, updatedAt: null, actionType: null,
    incidentId: null, incidentType: null, incidentReopen: null, causeCode: null, causeLevel: null, decision: null,
    riskClass: null, flags: parseFlags(null),
  };
  const backup = obj(a.backup_ref);
  const verification = obj(a.verification);
  const rollback = obj(a.rollback);
  const execution = obj(a.execution);
  const action: RecordDetail = {
    ...row,
    cause: parseCause(a.cause),
    decisionDetail: parseDecision(a.decision),
    risk: parseRisk(a.risk),
    history: arr(a.history).map((x): HistoryEntry => {
      const h = obj(x) ?? {};
      return { fromState: code(h.from_state), toState: code(h.to_state), ts: num(h.ts), actor: code(h.actor), reason: code(h.reason) };
    }),
    preflight: parseChecks(a.preflight),
    approvalStatus: code(obj(a.approval)?.status),
    backupVersionId: backup ? code(backup.version_id) : null,
    backupReason: backup ? code(backup.reason) : null,
    expectedImpact: parseImpact(a.expected_impact),
    verificationResult: verification ? code(verification.result) : null,
    verificationChecks: verification ? parseChecks(verification.checks) : null,
    rollbackMechanism: rollback ? code(rollback.mechanism) : null,
    rollbackStatement: rollback ? code(rollback.statement) : null,
    rollbackStatus: rollback ? code(rollback.status) : null,
    executionAttempt: execution ? int(execution.attempt_no) : null,
    callResult: execution ? code(execution.call_result) : null,
    components: arr(a.components).map(x => {
      const c = obj(x) ?? {};
      return { kind: code(c.kind), name: code(c.name) };
    }),
    plannedChanges: parseChanges(a.planned_changes),
    prerequisites: codes(a.prerequisites),
    playbookId: code(a.playbook_id),
    playbookVersion: int(a.playbook_version),
  };
  return { generatedAt: num(b.generated_at), action, routerHold: parseHold(b.router_hold), effectiveMode: code(b.effective_mode) };
}

function parseGate(v: unknown): Gate | null {
  const g = obj(v);
  if (!g) return null;
  return {
    permission: code(g.permission), effectiveMode: code(g.effective_mode), reasons: codes(g.reasons),
    allowlisted: bool(g.allowlisted), inRelease: bool(g.in_release), executableNow: bool(g.executable_now),
  };
}

function parseFacts(v: unknown): Facts | null {
  const f = obj(v);
  if (!f) return null;
  return { known: codes(f.known), unknown: codes(f.unknown) };
}

function parsePolicy(v: unknown): Policy | null {
  const p = obj(v);
  if (!p) return null;
  const score = obj(p.score);
  const risk = obj(p.risk);
  const rules = arr(p.rules).map(x => obj(x) ?? {});
  const rec = rules.find(r => r.code === 'recovery_statement');
  const recDetail = rec ? obj(rec.detail) : null;
  return {
    actionType: code(p.action_type),
    outcome: code(p.outcome),
    why: code(p.why),
    whyNot: code(p.why_not),
    refusal: code(p.refusal),
    writes: bool(p.writes),
    impact: parseImpact(p.impact),
    scoreTotal: score ? num(score.total) : null,
    contributions: arr(score?.contributions).map((x): Contribution => {
      const c = obj(x) ?? {};
      return { factor: code(c.factor), points: num(c.points), reason: code(c.reason) };
    }),
    riskClass: risk ? int(risk.risk_class) : null,
    riskReasons: risk ? codes(risk.reasons) : [],
    riskMissing: risk ? codes(risk.missing) : [],
    riskAssessed: risk ? bool(risk.assessed) : null,
    rules: rules.map((r): Rule => ({ code: code(r.code), outcome: code(r.outcome), blocking: bool(r.blocking) })),
    recovery: recDetail ? { rollback: code(recDetail.rollback), statement: code(recDetail.statement) } : null,
  };
}

function parseCandidate(v: unknown): Candidate | null {
  const c = obj(v);
  // only what the server labels as a candidate (heal_engine PolicyDecider._candidate)
  if (!c || c.label !== 'candidate') return null;
  return {
    actionType: code(c.action_type),
    playbookId: code(c.playbook_id),
    playbookVersion: int(c.playbook_version),
    outcome: code(c.outcome),
    error: code(c.error),
    policy: parsePolicy(c.policy),
    gate: parseGate(c.gate),
    facts: parseFacts(c.facts),
    plannedChanges: parseChanges(c.planned_changes),
  };
}

function parseExplanation(v: unknown): Explanation | null {
  const e = obj(v);
  if (!e) return null;
  return { policy: parsePolicy(e.policy), gate: parseGate(e.gate), facts: parseFacts(e.facts), candidate: parseCandidate(e.candidate) };
}

export function parsePlans(body: unknown): Plan[] {
  const b = obj(body) ?? {};
  return arr(b.plans).map((x): Plan => {
    const p = obj(x) ?? {};
    return {
      actionId: actionId(p.action_id),
      state: code(p.state),
      executable: bool(p.executable),
      blockers: codes(p.blockers),
      decision: parseDecision(p.decision),
      risk: parseRisk(p.risk),
      proposedActionType: code(p.proposed_action_type),
      plannedChanges: parseChanges(p.planned_changes),
      explanation: parseExplanation(p.explanation),
    };
  });
}

export function parseSettings(body: unknown): Settings {
  const b = obj(body) ?? {};
  const s = obj(b.settings) ?? {};
  const fixed = obj(b.limits) ?? {};
  const limits: Record<string, number> = {};
  for (const [k, v] of Object.entries(obj(s.limits) ?? {})) {
    const n = num(v);
    if (code(k) && n !== null) limits[k] = n;
  }
  const routers: Record<string, RouterSetting> = {};
  for (const [rid, v] of Object.entries(obj(s.routers) ?? {})) {
    const r = obj(v);
    if (!routerId(rid) || !r) continue;
    routers[rid] = {
      mode: code(r.mode),
      allowlist: arr(r.allowlist).map(x => {
        const e = obj(x) ?? {};
        return { actionType: code(e.action_type), maxRisk: int(e.max_risk) };
      }),
    };
  }
  return {
    generatedAt: num(b.generated_at),
    moduleSwitch: bool(b.module_switch),
    enabled: bool(s.enabled),
    limits,
    retentionS: num(fixed.terminal_retention_s),
    maxActions: int(fixed.max_actions),
    routers,
  };
}

// ── Texts of codes ───────────────────────────────────────────────────────

/** The German text of a reason code; an unknown code is shown raw, never hidden. */
export function reasonText(c: string | null | undefined): string {
  if (!c) return UNKNOWN;
  return REASON_TEXT[c] ?? c;
}

function label(table: Readonly<Record<string, string>>, c: string | null | undefined): string {
  if (!c) return UNKNOWN;
  return table[c] ?? c;
}

export const stateText = (c: string | null | undefined) => label(STATE_TEXT, c);
export const modeText = (c: string | null | undefined) => label(MODE_TEXT, c);
export const outcomeText = (c: string | null | undefined) => label(OUTCOME_TEXT, c);
export const actorText = (c: string | null | undefined) => label(ACTOR_TEXT, c);
export const permissionText = (c: string | null | undefined) => label(PERMISSION_TEXT, c);
export const actionText = (c: string | null | undefined) => label(ACTION_TEXT, c);
export const playbookText = (c: string | null | undefined) => label(PLAYBOOK_TEXT, c);
export const incidentText = (c: string | null | undefined) => label(INCIDENT_TEXT, c);
export const factText = (c: string | null | undefined) => label(FACT_TEXT, c);
export const familyText = (c: string | null | undefined) => label(FAMILY_TEXT, c);
export const componentText = (c: string | null | undefined) => label(COMPONENT_TEXT, c);
export const checkText = (c: string | null | undefined) => label(CHECK_TEXT, c);
export const approvalText = (c: string | null | undefined) => label(APPROVAL_TEXT, c);
export const verificationText = (c: string | null | undefined) => label(VERIFICATION_TEXT, c);
export const rollbackStatusText = (c: string | null | undefined) => label(ROLLBACK_STATUS_TEXT, c);
export const rollbackMechanismText = (c: string | null | undefined) => label(ROLLBACK_MECHANISM_TEXT, c);
export const causeLevelText = (c: string | null | undefined) => label(CAUSE_LEVEL_TEXT, c);
export const causeStatusText = (c: string | null | undefined) => label(CAUSE_STATUS_TEXT, c);

/** A cause code of Network Intelligence; none at all says so. */
export function causeText(c: string | null | undefined): string {
  if (!c) return 'keine Ursache gemeldet';
  return CAUSE_TEXT[c] ?? c;
}

/** A router by the panel's label for Core router ids ("Router 111111"; the routes send no names). */
export function routerText(id: string | null | undefined): string {
  return id ? routerLabel(id) : 'Router unbekannt';
}

export type Tone = 'info' | 'warn' | 'critical' | 'muted' | 'ok';

export function riskView(cls: number | null | undefined): { label: string; tone: Tone } {
  if (cls === null || cls === undefined || !(cls in RISK_TEXT)) return { label: 'Risiko unbekannt', tone: 'muted' };
  return { label: RISK_TEXT[cls], tone: cls === 0 ? 'info' : cls === 1 ? 'info' : cls === 2 ? 'warn' : 'critical' };
}

export function stateView(state: string | null | undefined): { label: string; tone: Tone } {
  const text = stateText(state);
  switch (state) {
    case 'resolved': return { label: text, tone: 'ok' };
    case 'failed': case 'escalated': case 'manual_recovery_required': case 'rolled_back': return { label: text, tone: 'critical' };
    case 'waiting_approval': case 'verifying': case 'executing': case 'rollback_pending': case 'rolling_back':
      return { label: text, tone: 'warn' };
    case 'cancelled': case 'rejected': return { label: text, tone: 'muted' };
    case 'detected': case 'analyzed': case 'proposed': case 'preflight': case 'approved': return { label: text, tone: 'info' };
    default: return { label: text, tone: 'muted' };
  }
}

export function outcomeView(outcome: string | null | undefined): { label: string; tone: Tone } {
  const text = outcomeText(outcome);
  switch (outcome) {
    case 'recommended': return { label: text, tone: 'info' };
    case 'requires_approval': return { label: text, tone: 'warn' };
    case 'not_safe': return { label: text, tone: 'critical' };
    default: return { label: text, tone: 'muted' };
  }
}

/** Yes, no, or unknown (never "no" for a missing value). */
export function yesNo(v: boolean | null | undefined): string {
  return v === true ? 'ja' : v === false ? 'nein' : UNKNOWN;
}

export function countText(n: number | null | undefined): string {
  return n === null || n === undefined ? UNKNOWN : String(n);
}

// ── Time ─────────────────────────────────────────────────────────────────

const pad = (n: number) => String(n).padStart(2, '0');

/** "TT.MM.JJJJ, HH:MM:SS" local; unknown says so. */
export function timeText(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || !Number.isFinite(ts) || ts <= 0) return UNKNOWN;
  const d = new Date(ts * 1000);
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function isoUtc(ts: number | null | undefined): string | undefined {
  if (ts === null || ts === undefined || !Number.isFinite(ts) || ts <= 0) return undefined;
  return new Date(ts * 1000).toISOString();
}

export function standText(ts: number | null | undefined): string {
  return `Stand ${timeText(ts)}`;
}

/** A span of seconds in words ("45 min", "3 h 5 min", "2 Tage"). */
export function durationText(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s) || s < 0) return UNKNOWN;
  if (s < 60) return `${Math.round(s)} s`;
  const min = Math.round(s / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 48) return min % 60 ? `${h} h ${min % 60} min` : `${h} h`;
  return `${Math.round(h / 24)} Tage`;
}

// ── Holds, pause, modes ──────────────────────────────────────────────────

export function holdEndText(hold: Hold): string {
  if (hold.noEnd === true) return 'ohne Ende – nur ein Administrator hebt sie auf';
  if (hold.remainingS !== null) return `endet in ${durationText(hold.remainingS)}`;
  return 'Ende unbekannt';
}

/** "<reason> – <end>" of a hold. */
export function holdText(hold: Hold): string {
  return `${reasonText(hold.reason)} – ${holdEndText(hold)}`;
}

/** Why the effective mode differs from the configured one (only what the server says). */
export function modeWhy(r: RouterRow, ov: Overview): string | null {
  if (r.configuredMode === null || r.effectiveMode === null || r.configuredMode === r.effectiveMode) return null;
  const why: string[] = [];
  if (ov.status === 'module_disabled') why.push('Modul ausgeschaltet');
  if (r.held === true) why.push('Router gesperrt');
  if (ov.fleet.paused === true) why.push('Flotte pausiert');
  if (ov.fleet.held === true) why.push('Flotte gesperrt');
  return why.length ? why.join(', ') : 'Grund vom Server nicht genannt';
}

// ── Overview tiles (from the state counts; unknown when a state is missing) ──

export interface Tile {
  id: string;
  label: string;
  value: number | null;
  /** Shown under the number (unknown values carry their reason). */
  note: string;
}

function sumOf(byState: Readonly<Record<string, number>>, states: readonly string[]): number | null {
  let sum = 0;
  for (const s of states) {
    if (!(s in byState)) return null;
    sum += byState[s];
  }
  return sum;
}

export function tiles(ov: Overview): Tile[] {
  const by = ov.counts.byState;
  const missing = 'Zahl vom Server nicht geliefert';
  const t = (id: string, lbl: string, states: readonly string[], note: string): Tile => {
    const value = sumOf(by, states);
    return { id, label: lbl, value, note: value === null ? missing : note };
  };
  return [
    { id: 'open', label: 'Offene Datensätze', value: ov.counts.open, note: ov.counts.open === null ? missing : 'noch nicht abgeschlossen' },
    t('active', 'Laufende Reparaturen', ['executing', 'verifying', 'rollback_pending', 'rolling_back'], 'werden ausgeführt oder nachgeprüft'),
    t('waiting', 'Wartende Freigaben', ['waiting_approval'], 'warten auf einen Administrator'),
    t('resolved', 'Erfolgreiche Reparaturen', ['resolved'], 'behoben und nachgeprüft'),
    t('failed', 'Fehlgeschlagene Reparaturen', ['failed', 'escalated', 'manual_recovery_required', 'rolled_back'], 'fehlgeschlagen, eskaliert oder von Hand'),
    t('closed', 'Ohne Aktion abgeschlossen', ['cancelled', 'rejected'], 'Vorfall vorbei oder abgelehnt'),
    { id: 'blocked', label: 'Blockierte riskante Aktionen', value: null, note: BLOCKED_RISKY_UNKNOWN },
  ];
}

/** The states with a count above zero, in the model's order (the rest is listed as 0 in one line). */
export function stateCounts(ov: Overview): { state: string; n: number }[] {
  return ALL_STATES.filter(s => (ov.counts.byState[s] ?? 0) > 0).map(s => ({ state: s, n: ov.counts.byState[s] }));
}

// ── Records: filters and the list ────────────────────────────────────────

export type ListFilter = 'open' | 'closed' | 'all';

export interface ListFilters {
  show: ListFilter;
  routerId: string | null;
}

export const DEFAULT_LIST_FILTERS: ListFilters = { show: 'all', routerId: null };

export function isOpen(row: ActionRow): boolean | null {
  if (row.terminal !== null) return !row.terminal;
  return row.state ? OPEN_STATES.includes(row.state) : null;
}

export function filterRows(rows: readonly ActionRow[], f: ListFilters): ActionRow[] {
  return rows.filter(r => {
    if (f.routerId && r.routerId !== f.routerId) return false;
    if (f.show === 'all') return true;
    const open = isOpen(r);
    return f.show === 'open' ? open === true : open === false;
  });
}

export function routerIdsOf(rows: readonly ActionRow[], ov: Overview | null): string[] {
  const ids = new Set<string>();
  for (const r of ov?.routers ?? []) ids.add(r.routerId);
  for (const r of rows) if (r.routerId) ids.add(r.routerId);
  return [...ids].sort((a, b) => routerText(a).localeCompare(routerText(b), 'de') || a.localeCompare(b));
}

/** "Die neuesten 200 von 340." when the server holds more than it sent. */
export function cutText(list: ActionList): string | null {
  if (list.total === null || list.total <= list.actions.length) return null;
  return `Angezeigt werden die neuesten ${list.actions.length} von ${list.total} Datensätzen.`;
}

// ── Explanation helpers ──────────────────────────────────────────────────

/** Score 0..1 of a record or plan as "17 von 100". */
export function scoreText(score: number | null | undefined): string {
  if (score === null || score === undefined || !Number.isFinite(score)) return UNKNOWN;
  return `${Math.round(score * 100)} von 100`;
}

export function pointsText(points: number | null | undefined): string {
  if (points === null || points === undefined || !Number.isFinite(points)) return UNKNOWN;
  return points > 0 ? `+${points}` : String(points);
}

/** "dnsmasq · Dienst · Dienst neu starten". */
export function changeText(c: Change): string {
  return [componentText(c.kind), c.target ?? UNKNOWN, actionText(c.effect)].join(' · ');
}

export function impactLines(impact: Impact | null): { key: string; label: string; value: string }[] {
  if (!impact) return [];
  return Object.entries(impact).map(([k, v]) => {
    let value: string;
    if (v === null) value = UNKNOWN;
    else if (k === 'est_outage_s' && typeof v === 'number') value = durationText(v);
    else if (k === 'disruption' && typeof v === 'string') value = DISRUPTION_TEXT[v] ?? v;
    else value = String(v);
    return { key: k, label: IMPACT_TEXT[k] ?? k, value };
  });
}

/** Codes of a decision line in the order they explain it (why, why not, refusal). */
export function whyCodes(d: { why: string | null; whyNot: string | null; refusal?: string | null }): string[] {
  return [d.why, d.whyNot, d.refusal ?? null].filter((c): c is string => !!c);
}

// ── Polling ──────────────────────────────────────────────────────────────

/** At most every 60 s (the other tabs' rule), only while the page is visible; never while off or forbidden. */
export function shouldPoll(a: { visible: boolean; lastMs: number | null; nowMs: number; stopped: boolean }): boolean {
  if (a.stopped) return false;
  return shouldFetch({ visible: a.visible, lastMs: a.lastMs, nowMs: a.nowMs, intervalMs: POLL_MIN_MS });
}
