/**
 * wifiTypes.ts — view types of the WiFi Intelligence tab.
 *
 * Parsed from the GET routes under /api/openwrt_router/enterprise/wifi/
 * (rf_output.py, schema 1). Only the fields the views show are kept: no
 * SSID, BSSID, MAC or interface name ever enters these types. A missing or
 * wrongly typed value is null, never 0.
 */

export type RfStatus = 'off' | 'not_ready' | 'ready';
export type MetricState = 'measured' | 'no_data' | 'unsupported' | 'unreachable' | 'stale';
export type Tone = 'ok' | 'info' | 'warn' | 'critical' | 'muted';

export interface Base {
  status: RfStatus | null;
  reasons: string[];
  generatedAt: number | null;
}

export interface Metric {
  value: number | null;
  state: MetricState | null;
  source: string | null;
  measuredAt: number | null;
}

export interface Health {
  score: number | null;
  grade: string | null;
  coverage: number | null;
  capped: boolean;
  withheld: string[];
}

export interface Ref {
  routerId: string;
  radioId: string;
}

export interface RouterRow {
  routerId: string;
  enabled: boolean | null;
  status: string | null;
  reason: string | null;
  radios: number | null;
  reads: string[];
  everyNPolls: number | null;
  lastPollAt: number | null;
  health: Health;
}

export interface Counts {
  radios: number | null;
  clients: number | null;
  conflicts: number | null;
  conflictsMeasured: number | null;
  recommendations: number | null;
}

export interface Overview extends Base {
  routers: RouterRow[];
  monitoringCoverage: number | null;
  networkHealth: Health;
  counts: Counts;
}

export interface RadioClients {
  count: number | null;
  problem: number | null;
  flagged: number | null;
  weak: number | null;
  signalCoverage: number | null;
  retryCoverage: number | null;
}

export interface UtilSummary {
  current: number | null;
  mean: number | null;
  peak: number | null;
  coverage: number | null;
}

export interface Radio extends Ref {
  band: string | null;
  channel: number | null;
  widthMhz: number | null;
  centerChannel: number | null;
  htmode: string | null;
  backhaul: boolean | null;
  country: string | null;
  measuredAt: number | null;
  metrics: Record<string, Metric | null>;
  utilReason: string | null;
  utilSummary: UtilSummary | null;
  clients: RadioClients;
  capabilities: { states: Record<string, MetricState | null>; coverage: number | null };
  health: Health;
  loadStatus: string | null;
  sources: Record<string, { state: string | null; reason: string | null }>;
  roams1h: number | null;
}

export interface RadiosView extends Base {
  radios: Radio[];
}

export interface ChannelEntry extends Ref {
  channel: number | null;
  widthMhz: number | null;
  centerChannel: number | null;
  backhaul: boolean | null;
  clientCount: number | null;
  utilization: Metric | null;
}

export interface Conflict {
  kind: string | null;
  band: string | null;
  members: Ref[];
  status: string | null;
  severity: string | null;
  evidence: string[];
}

export interface ChannelMap extends Base {
  bands: { band: string; entries: ChannelEntry[] }[];
  conflicts: Conflict[];
}

export interface SeriesPoint {
  ts: number;
  mean: number | null;
  min: number | null;
  max: number | null;
}

export interface Series {
  windowS: number | null;
  resolutionS: number | null;
  coverage: number | null;
  points: SeriesPoint[];
}

export interface TimelineRadio extends Ref {
  series: Record<string, Series>;
}

export interface Timeline extends Base {
  window: string | null;
  radios: TimelineRadio[];
}

export interface RoamEvent {
  clientRef: string | null;
  from: Ref | null;
  to: Ref | null;
  at: number | null;
  gapS: number | null;
}

export interface Roaming extends Base {
  windowS: number | null;
  perRadio: (Ref & { roams: number | null })[];
  /** null while restricted (no admin approval) or off / not ready. */
  events: RoamEvent[] | null;
  eventsRestricted: string | null;
}

export interface Recommendation {
  kind: string | null;
  target: { routerId: string; radioId: string | null } | null;
  scope: string | null;
  problem: string | null;
  evidence: string[];
  action: string | null;
  actionParams: Record<string, string | number>;
  expectedEffect: string | null;
  confidence: number | null;
  risk: string[];
  requires: string[];
  basis: string | null;
  priority: string | null;
}

export interface LoadAp {
  routerId: string;
  status: string | null;
  confidence: number | null;
}

export interface Distribution {
  total: number | null;
  coverage: number | null;
  largestShare: number | null;
  perBand: { band: string; clients: number | null }[];
  findings: { kind: string | null; severity: string | null }[];
}

export interface Recommendations extends Base {
  recommendations: Recommendation[];
  load: LoadAp[];
  distribution: Distribution | null;
}

export interface TimelineQuery {
  window: string;
  series?: string | null;
  radioId?: string | null;
  routerId?: string | null;
}

export interface WifiApi {
  overview(): Promise<Overview>;
  radios(): Promise<RadiosView>;
  channelMap(): Promise<ChannelMap>;
  recommendations(): Promise<Recommendations>;
  timeline(query: TimelineQuery): Promise<Timeline>;
  /** Sensitive for admins: the backend asks the Core guard once per HA login. */
  roaming(): Promise<Roaming>;
}

/** The part of Home Assistant's frontend object the client needs. */
export interface WifiHass {
  /** The tab only reads: GET is the one method it ever uses. */
  callApi<T>(method: 'GET', path: string, parameters?: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean };
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<void>;
  };
}
