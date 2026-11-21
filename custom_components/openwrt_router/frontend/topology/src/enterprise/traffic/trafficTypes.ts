/**
 * trafficTypes.ts — view types of the Traffic Analytics tab.
 *
 * These are the parsed shapes of /api/openwrt_topology/traffic/* (see
 * traffic_output.py): only what the views show. Ids are pseudonyms
 * (rtr_ / tpt_ / cli_); the backend never sends a MAC or host name. Every
 * number that may be unknown is `number | null`: null is shown as "—"
 * with its reason, never as 0.
 */

export type TrafficStatus = 'off' | 'not_ready' | 'ready';
export type CoverageLevel = 'full' | 'partial' | 'estimated' | 'unavailable' | 'unknown';
export type Tone = 'ok' | 'info' | 'warn' | 'critical' | 'muted';

export interface Base {
  status: TrafficStatus | null;
  reasons: string[];
  generatedAt: number | null;
}

/** A source of data and why it is (not) delivering. */
export interface SourceState {
  name: string;
  state: string | null;
  reason: string | null;
}

export interface CoverageSummary {
  points: number | null;
  full: number | null;
  partial: number | null;
  estimated: number | null;
  unavailable: number | null;
  unknown: number | null;
  fullShare: number | null;
  reasons: { code: string; count: number }[];
}

/** Current rate of one measuring point. */
export interface RateRow {
  pointId: string;
  routerId: string | null;
  scope: string;
  device: string | null;
  vlanId: number | null;
  rxBps: number | null;
  txBps: number | null;
  downBps: number | null;
  upBps: number | null;
  /** Why download/upload cannot be named (rx/tx are then shown as is). */
  directionReason: string | null;
  quality: string | null;
  coverage: CoverageLevel | null;
  coverageReason: string | null;
  wallS: number | null;
}

export interface InterfaceRow extends RateRow {
  linkMbps: number | null;
  duplex: string | null;
  utilizationPct: number | null;
  utilizationReason: string | null;
}

export interface WanTotal {
  rxBps: number | null;
  txBps: number | null;
  coverage: CoverageLevel | null;
  reasons: string[];
  contributing: number | null;
  omitted: number | null;
  routers: number | null;
  refused: string | null;
}

/** Sum of one point over a window (bytes, averages and peaks). */
export interface WindowSummary {
  pointId: string;
  routerId: string | null;
  scope: string | null;
  state: string | null;
  reason: string | null;
  rxBytes: number | null;
  txBytes: number | null;
  avgRxBps: number | null;
  avgTxBps: number | null;
  peakRxBps: number | null;
  peakTxBps: number | null;
  download: 'rx' | 'tx' | null;
  upload: 'rx' | 'tx' | null;
  timeCoverage: number | null;
  coverage: CoverageLevel | null;
  reasons: string[];
}

export interface TalkerRow {
  rank: number | null;
  pointId: string;
  scope: string;
  routerId: string | null;
  clientRef: string | null;
  device: string | null;
  vlanId: number | null;
  counter: string | null;
  value: number | null;
  observedBytes: number | null;
  peakBps: number | null;
  measuringArea: string | null;
  coverage: CoverageLevel | null;
  coverageReasons: string[];
  timeCoverage: number | null;
  sharePct: number | null;
  shareReason: string | null;
  lastActive: number | null;
}

export interface TalkerList extends Base {
  kind: string | null;
  scope: string | null;
  window: string | null;
  direction: string | null;
  /** bytes (window), bps (current) or episodes (peaks). */
  metric: string | null;
  state: string | null;
  reason: string | null;
  partial: boolean;
  partialReasons: string[];
  rows: TalkerRow[];
  considered: number | null;
  omitted: { code: string; count: number }[];
}

export interface AnomalyFamily {
  family: string;
  state: string | null;
  reason: string | null;
}

export interface AnomalySummary {
  open: number | null;
  ended: number | null;
  suppressed: number | null;
  families: AnomalyFamily[];
}

export interface RouterRow {
  routerId: string;
  devices: number | null;
  stations: number | null;
  conntrackCount: number | null;
}

export interface VlanRow {
  routerId: string | null;
  vlanId: number | null;
  measured: number;
  rxBps: number | null;
  txBps: number | null;
  rxBytes: number | null;
  txBytes: number | null;
  coverage: CoverageLevel | null;
  coverageReasons: string[];
  directionReason: string | null;
  configuredPorts: number;
  interVlan: SourceState;
  wanRelated: SourceState;
  activeClients: number | null;
  activeClientsBasis: string | null;
  unavailable: { field: string; reason: string }[];
}

export interface HistoryInfo {
  profile: string | null;
  fineBytes: number | null;
  coarseBytes: number | null;
  dayBoundary: string | null;
}

export interface Overview extends Base {
  coverage: CoverageSummary | null;
  wan: RateRow[];
  wanTotal: WanTotal | null;
  wan24h: WindowSummary[];
  talkersTop: TalkerList | null;
  anomalies: AnomalySummary | null;
  interfaces: InterfaceRow[];
  vlans: VlanRow[];
  flowSources: SourceState[];
  correlationSources: SourceState[];
  routers: RouterRow[];
  drops: { code: string; count: number }[];
  history: HistoryInfo | null;
}

export interface PointRow {
  pointId: string;
  routerId: string | null;
  scope: string;
  device: string | null;
  vlanId: number | null;
  coverage: CoverageLevel | null;
  quality: string | null;
  lastSeen: number | null;
}

export interface PointList extends Base {
  points: PointRow[];
  total: number | null;
  truncated: boolean;
}

export interface SeriesBucket {
  ts: number;
  rxBytes: number | null;
  txBytes: number | null;
  rxPeakBps: number | null;
  txPeakBps: number | null;
  coverage: number | null;
}

export interface Series extends Base {
  pointId: string | null;
  window: string | null;
  state: string | null;
  reason: string | null;
  windowReasons: string[];
  resolutionS: number | null;
  summary: WindowSummary | null;
  /** Buckets are UTC days (label them in local time and say so). */
  utcDays: boolean;
  buckets: SeriesBucket[];
}

export interface ClientRow {
  clientRef: string;
  link: string | null;
  identity: string | null;
  routerId: string | null;
  locationSource: string | null;
  downBps: number | null;
  upBps: number | null;
  downBytes: number | null;
  upBytes: number | null;
  coveredS: number | null;
  vlanId: number | null;
  coverage: CoverageLevel | null;
  coverageReasons: string[];
  wanAttribution: SourceState;
  roamingGaps: number | null;
  interruptions: number | null;
  lastSeen: number | null;
  unavailable: { field: string; reason: string }[];
}

export interface ClientList extends Base {
  clients: ClientRow[];
  total: number | null;
  truncated: boolean;
}

export interface VlanList extends Base {
  vlans: VlanRow[];
}

export interface CapacityDirection {
  counter: string;
  meaning: string | null;
  avgBps: number | null;
  peakBps: number | null;
  p95Bps: number | null;
  avgPct: number | null;
  peakPct: number | null;
  p95Pct: number | null;
  unavailable: { field: string; reason: string }[];
}

export interface Trend {
  state: string | null;
  reason: string | null;
  basisDays: number | null;
  slopePctPerWeek: number | null;
  daysToNearCapacity: number | null;
  daysReason: string | null;
  confidence: number | null;
}

export interface CapacityRow {
  pointId: string;
  scope: string;
  routerId: string | null;
  device: string | null;
  vlanId: number | null;
  linkMbps: number | null;
  duplex: string | null;
  uplink: boolean | null;
  windowS: number | null;
  timeCoverage: number | null;
  p95Estimated: boolean;
  directions: CapacityDirection[];
  sharedP95Pct: number | null;
  nearCapacityDays: number | null;
  state: string | null;
  reasons: string[];
  trend: Trend | null;
}

export interface CapacityList extends Base {
  rows: CapacityRow[];
}

export interface Observation {
  indicator: string;
  family: string | null;
  elevated: boolean;
  value: number | null;
  unit: string | null;
  threshold: number | null;
}

export interface Finding {
  findingId: string;
  routerId: string | null;
  pointId: string | null;
  scope: string | null;
  assessment: string;
  observations: Observation[];
  possibleCauses: string[];
  recommendations: string[];
  recommendationWithheld: string | null;
  confidence: number | null;
  unmeasured: { field: string; reason: string }[];
  windowS: number | null;
  start: number | null;
  end: number | null;
}

export interface Recommendations extends Base {
  verdict: string | null;
  findings: Finding[];
  sources: SourceState[];
  pointsEvaluated: number | null;
  pointsInsufficient: number | null;
}

export interface AnomalyRow {
  candidateId: string;
  pointId: string | null;
  routerId: string | null;
  clientRef: string | null;
  kind: string;
  observed: number | null;
  baselineMedian: number | null;
  threshold: number | null;
  windowS: number | null;
  confidence: number | null;
  coverage: CoverageLevel | null;
  started: number | null;
  lastSeen: number | null;
  state: string | null;
  suppressedReason: string | null;
}

export interface AnomalyList extends Base {
  rows: AnomalyRow[];
  total: number | null;
  families: AnomalyFamily[];
  incidentEngine: SourceState;
}

/** One flow of the external collector (pseudonyms only, Phase K). */
export interface FlowRow {
  routerId: string | null;
  clientRef: string | null;
  vlanId: number | null;
  proto: string | null;
  src: string | null;
  dst: string | null;
  srcPort: number | null;
  dstPort: number | null;
  start: number | null;
  end: number | null;
  bytes: number | null;
  packets: number | null;
  direction: string | null;
  kind: string | null;
}

export interface FlowsView extends Base {
  source: SourceState;
  notes: string[];
  sources: SourceState[];
  rows: FlowRow[];
  complete: boolean | null;
}

export interface TalkerQuery {
  kind: string;
  scope: string;
  window: string;
  direction: string;
  limit: number;
}

export interface SeriesQuery {
  pointId: string;
  window: string;
}

export interface TrafficApi {
  overview(): Promise<Overview>;
  points(): Promise<PointList>;
  series(q: SeriesQuery): Promise<Series>;
  talkers(q: TalkerQuery): Promise<TalkerList>;
  clients(): Promise<ClientList>;
  vlans(): Promise<VlanList>;
  capacity(): Promise<CapacityList>;
  anomalies(): Promise<AnomalyList>;
  recommendations(): Promise<Recommendations>;
  /** Administrators only (403 otherwise). */
  flows(): Promise<FlowsView>;
}

export interface TrafficHass {
  /** The tab only reads: GET is the one method it ever uses. */
  callApi<T>(method: 'GET', path: string, parameters?: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean };
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<void>;
  };
}
