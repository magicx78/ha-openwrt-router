/**
 * diagnosticsTypes.ts — shapes of the Network Diagnostics panel.
 *
 * The server (diag_views.py / diag_runtime.py) sends snake_case JSON;
 * diagnosticsLogic.ts parses it defensively into these camelCase view types
 * (unknown fields ignored, a missing or wrongly typed field becomes null /
 * empty, never a made-up 0 or "healthy"). Type-only module: no runtime code
 * (node --test strips it).
 *
 * Times are epoch SECONDS, as the backend sends them.
 */

/** Minimal hass the client needs (structurally the panel's HassLike). */
export interface DiagHass {
  callApi<T>(method: 'GET' | 'POST', path: string, parameters?: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean };
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<void>;
  };
}

/** Module state; null = the server sent something this panel does not know. */
export type ModuleState = 'off' | 'not_ready' | 'ready' | null;

export type StageId = 'router' | 'gateway' | 'wan' | 'internet' | 'dns';
export type StageState = 'healthy' | 'degraded' | 'failed' | 'unknown' | 'not_applicable';
export type Tone = 'ok' | 'info' | 'warn' | 'critical' | 'muted';

/** One delivered chain entry (a stage per address family). */
export interface ChainStage {
  stage: string | null;
  family: string | null;
  state: string | null;
  basis: string | null;
}

export interface Finding {
  classification: string | null;
  severity: string | null;
  /** confirmed / probable / possible / unknown, as delivered. */
  causeClass: string | null;
  stage: string | null;
  family: string | null;
  summary: string | null;
  recommendation: string | null;
  unmeasuredCount: number | null;
}

export interface PointScore {
  score: number | null;
  /** 0..1 */
  coverage: number | null;
  lowConfidence: boolean | null;
}

export interface GatewayView {
  /** true / false only from a direct measurement; null = not measured. */
  reachable: boolean | null;
  reason: string | null;
}

/** One measurement point: Home Assistant or a router. */
export interface PointView {
  /** 'ha' or the router id as delivered (pseudonymous). */
  id: string;
  kind: 'ha' | 'router';
  /** ok / partial / problem / unknown / settling; null = unknown to the panel. */
  state: string | null;
  reason: string | null;
  settling: boolean;
  finding: Finding | null;
  chain: ChainStage[] | null;
  score: PointScore | null;
  restarts24h: number | null;
  downInterfaces: number | null;
  gateway: GatewayView | null;
}

export interface Fleet {
  score: number | null;
  /** 0..100 percent; null = unknown. */
  coveragePct: number | null;
  lowConfidence: boolean | null;
  routers: number | null;
  routersScored: number | null;
  routersUnknown: number | null;
  haState: string | null;
  findingsActive: number | null;
  haLatencyMs: number | null;
  haLossPct: number | null;
  dnsMs: number | null;
}

export interface LastRun {
  ts: number | null;
  probes: number | null;
}

export interface Overview {
  state: ModuleState;
  reasons: string[];
  enabled: boolean | null;
  fleet: Fleet | null;
  routers: PointView[];
  ha: PointView | null;
  lastRun: LastRun | null;
}

export interface WindowSummary {
  answered: number | null;
  lost: number | null;
  gaps: number | null;
  expected: number | null;
  /** 0..1 */
  coverage: number | null;
  meanMs: number | null;
  jitterMs: number | null;
  lossPct: number | null;
}

export interface HistorySeries {
  point: string;
  targetId: string;
  kind: string | null;
  family: string | null;
  /** window name -> summary; a missing window or null summary = no data. */
  windows: Record<string, WindowSummary | null>;
}

export interface HistoryView {
  state: ModuleState;
  reasons: string[];
  windows: string[];
  /** null = module off (no series delivered). */
  series: HistorySeries[] | null;
  gaps: number | null;
}

export interface SettingsTarget {
  id: string;
  kind: string | null;
  scope: string | null;
  confirmed: boolean | null;
  port: number | null;
}

/** Status of a configured target (what a run may use). */
export interface TargetStatus {
  id: string;
  kind: string | null;
  scope: string | null;
  confirmed: boolean;
  usable: boolean;
  reason: string | null;
}

export interface Settings {
  enabled: boolean | null;
  periodic: boolean | null;
  intervalS: number | null;
  haResolverInternal: boolean | null;
  dnsQueryName: string | null;
  httpPath: string | null;
  internalNetworkCount: number | null;
  localDomainCount: number | null;
  targets: SettingsTarget[];
}

export interface LoadView {
  packetsPerDay: number | null;
  roundsPerDay: number | null;
  runLimitMax: number | null;
  runLimitWindowS: number | null;
}

export interface SettingsView {
  state: ModuleState;
  reasons: string[];
  settings: Settings;
  targets: TargetStatus[];
  load: LoadView | null;
}

/** The only fields the backend accepts that this panel edits. */
export interface SettingsUpdate {
  enabled?: boolean;
  periodic?: boolean;
  interval_s?: number;
  ha_resolver_internal?: boolean;
}

export interface SettingsDraft {
  enabled: boolean;
  periodic: boolean;
  intervalS: string;
  haResolverInternal: boolean;
}

export interface RunResultEntry {
  targetId: string;
  kind: string | null;
  family: string | null;
  outcome: string | null;
  rttMs: number | null;
}

export interface RunRefusal {
  id: string;
  reason: string | null;
}

export interface RunResult {
  /** success / failure / timeout / cancelled / skipped_maintenance */
  status: string | null;
  probes: number | null;
  refused: RunRefusal[];
  results: RunResultEntry[];
  finding: Finding | null;
}

export interface DiagApi {
  overview(): Promise<Overview>;
  history(): Promise<HistoryView>;
  settings(): Promise<SettingsView>;
  updateSettings(update: SettingsUpdate): Promise<SettingsView>;
  run(targetIds: string[]): Promise<RunResult>;
}
