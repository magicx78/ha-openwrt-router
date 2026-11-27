/**
 * shTypes.ts — the "Self-Healing" tab's view of the five GET routes of
 * heal_views.py (/api/openwrt_router/enterprise/selfhealing/v1/…). Every
 * value the server may leave out or send in an unexpected form is `null`
 * here ("unknown"), never a guessed default; codes stay raw strings (the
 * texts come from shTexts.ts).
 */

export interface ShHass {
  callApi<T>(method: 'GET', path: string): Promise<T>;
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<unknown>;
  };
  user?: { is_admin?: boolean };
}

/** A hold of a router or of the fleet (no wall times: seconds left on the safety clock). */
export interface Hold {
  reason: string | null;
  fleet: boolean | null;
  /** Only an administrator ends it. */
  noEnd: boolean | null;
  remainingS: number | null;
  actionId: string | null;
}

export interface RouterRow {
  routerId: string;
  loaded: boolean | null;
  configuredMode: string | null;
  effectiveMode: string | null;
  held: boolean | null;
  hold: Hold | null;
  open: number | null;
}

export interface Counts {
  total: number | null;
  open: number | null;
  /** Every state the server listed; a missing state is unknown, not 0. */
  byState: Readonly<Record<string, number>>;
  routers: number | null;
  routersHeld: number | null;
}

export interface Overview {
  /** 'on', 'module_disabled', or what else the server says (raw). */
  status: string | null;
  generatedAt: number | null;
  releaseMode: string | null;
  writePath: boolean | null;
  automaticRollback: string | null;
  fleet: {
    paused: boolean | null;
    held: boolean | null;
    pauseReason: string | null;
    pauseRemainingS: number | null;
    hold: Hold | null;
  };
  counts: Counts;
  lastActivity: number | null;
  /** null: the server sent no router list (the masked brief for non-admins). */
  routers: RouterRow[] | null;
  pendingIncidents: number | null;
}

export interface Flags {
  interrupted: boolean | null;
  inMaintenance: boolean | null;
  acknowledgedByAdmin: boolean | null;
  holdReleased: boolean | null;
}

/** One row of GET …/actions. */
export interface ActionRow {
  actionId: string;
  routerId: string | null;
  state: string | null;
  terminal: boolean | null;
  createdAt: number | null;
  updatedAt: number | null;
  actionType: string | null;
  incidentId: string | null;
  incidentType: string | null;
  incidentReopen: number | null;
  causeCode: string | null;
  causeLevel: string | null;
  decision: string | null;
  riskClass: number | null;
  flags: Flags;
}

export interface ActionList {
  generatedAt: number | null;
  total: number | null;
  limit: number | null;
  offset: number | null;
  actions: ActionRow[];
}

export interface HistoryEntry {
  fromState: string | null;
  toState: string | null;
  ts: number | null;
  actor: string | null;
  reason: string | null;
}

export interface Factor {
  factor: string | null;
  value: number | null;
  reason: string | null;
}

export interface Decision {
  outcome: string | null;
  score: number | null;
  factors: Factor[];
  why: string | null;
  whyNot: string | null;
}

export interface Risk {
  riskClass: number | null;
  reasons: string[];
}

export interface Cause {
  code: string | null;
  status: string | null;
  level: string | null;
  confidence: number | null;
  sourceFamilies: string[];
}

export interface Check {
  check: string | null;
  outcome: string | null;
  reason: string | null;
}

export interface Change {
  kind: string | null;
  target: string | null;
  effect: string | null;
}

export type Impact = Readonly<Record<string, number | string | null>>;

/** GET …/actions/{id}: the record (a part the server did not send is null). */
export interface RecordDetail extends ActionRow {
  cause: Cause | null;
  decisionDetail: Decision | null;
  risk: Risk | null;
  history: HistoryEntry[];
  preflight: Check[] | null;
  approvalStatus: string | null;
  backupVersionId: string | null;
  backupReason: string | null;
  expectedImpact: Impact | null;
  verificationResult: string | null;
  verificationChecks: Check[] | null;
  rollbackMechanism: string | null;
  rollbackStatement: string | null;
  rollbackStatus: string | null;
  executionAttempt: number | null;
  callResult: string | null;
  components: { kind: string | null; name: string | null }[];
  plannedChanges: Change[];
  prerequisites: string[];
  playbookId: string | null;
  playbookVersion: number | null;
}

export interface Detail {
  generatedAt: number | null;
  action: RecordDetail;
  routerHold: Hold | null;
  effectiveMode: string | null;
}

export interface Gate {
  permission: string | null;
  effectiveMode: string | null;
  reasons: string[];
  allowlisted: boolean | null;
  inRelease: boolean | null;
  executableNow: boolean | null;
}

export interface Contribution {
  factor: string | null;
  points: number | null;
  reason: string | null;
}

export interface Rule {
  code: string | null;
  outcome: string | null;
  blocking: boolean | null;
}

export interface Policy {
  actionType: string | null;
  outcome: string | null;
  why: string | null;
  whyNot: string | null;
  refusal: string | null;
  writes: boolean | null;
  impact: Impact | null;
  scoreTotal: number | null;
  contributions: Contribution[];
  riskClass: number | null;
  riskReasons: string[];
  riskMissing: string[];
  riskAssessed: boolean | null;
  rules: Rule[];
  /** The recovery statement rule (`recovery_statement`): rollback kind and statement code. */
  recovery: { rollback: string | null; statement: string | null } | null;
}

export interface Facts {
  known: string[];
  unknown: string[];
}

/** A facts source's candidate: decided, explained, NEVER executed (label "candidate"). */
export interface Candidate {
  actionType: string | null;
  playbookId: string | null;
  playbookVersion: number | null;
  outcome: string | null;
  /** `candidate_failed`: the evaluation of the candidate failed. */
  error: string | null;
  policy: Policy | null;
  gate: Gate | null;
  facts: Facts | null;
  plannedChanges: Change[];
}

export interface Explanation {
  policy: Policy | null;
  gate: Gate | null;
  facts: Facts | null;
  candidate: Candidate | null;
}

/** One entry of GET …/plans (what would be proposed and what would block). */
export interface Plan {
  actionId: string | null;
  state: string | null;
  executable: boolean | null;
  blockers: string[];
  decision: Decision | null;
  risk: Risk | null;
  proposedActionType: string | null;
  plannedChanges: Change[];
  explanation: Explanation | null;
}

export interface RouterSetting {
  mode: string | null;
  allowlist: { actionType: string | null; maxRisk: number | null }[];
}

export interface Settings {
  generatedAt: number | null;
  moduleSwitch: boolean | null;
  enabled: boolean | null;
  limits: Readonly<Record<string, number>>;
  retentionS: number | null;
  maxActions: number | null;
  routers: Readonly<Record<string, RouterSetting>>;
}

/** The tab's only network access: GET requests to the read routes of heal_views.py. */
export interface ShApi {
  overview(): Promise<Overview>;
  actions(): Promise<ActionList>;
  action(actionId: string): Promise<Detail>;
  /** The plan of one record (null: the server listed none for it). */
  plan(actionId: string): Promise<Plan | null>;
  settings(): Promise<Settings>;
}
