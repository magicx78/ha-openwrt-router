/**
 * tmTypes.ts — view types of the "Zeitreise" tab (Network Time Machine,
 * Phases A–F). The server answers are `v: 1` of GET
 * /api/openwrt_router/enterprise/timemachine/timeline, …/sessions, …/state,
 * …/compare and …/export (docs/time-machine.md).
 */

export type Severity = 'info' | 'warning' | 'critical';
export type EndState = 'open' | 'closed' | 'unknown';

/** One end of a roam or uplink change (names only from the server). */
export interface Peer {
  routerId: string | null;
  routerName: string | null;
}
export type Tone = 'info' | 'warn' | 'critical' | 'muted';

/** Where a mark comes from (`ref`, docs/time-machine.md §5.3); ids checked by the parser. */
export interface Ref {
  module: string;
  type: string | null;
  id: string | null;
  versionId: string | null;
}

/** An Enterprise tab to open, and the object to select there (§23). */
export interface JumpTarget {
  tab: string;
  objectType: string | null;
  objectId: string | null;
  versionId: string | null;
  /** The router of the entry (the Configuration tab opens that router). */
  routerId: string | null;
}

export interface Mark {
  id: string;
  /** Epoch seconds, UTC. */
  ts: number;
  source: string;
  kind: string;
  group: string;
  severity: Severity;
  routerId: string | null;
  routerName: string | null;
  fleet: boolean;
  titleKey: string;
  /** Only the Security Center sends a text (masked by the server). */
  text: string | null;
  /** Numbers only. */
  params: Record<string, number>;
  derived: boolean;
  // additive (1.51.0, own index): null / false on the Phase A sources
  /** The code of the mark (e.g. the error type of an outage). */
  code: string | null;
  /** End of an interval (epoch seconds); null while open or for a point. */
  end: number | null;
  endState: EndState | null;
  /** Client pseudonym `tmc_` + 16 hex (administrators only). */
  client: string | null;
  /** Current name from Client Stability (server only, administrators only). */
  clientName: string | null;
  peers: { before: Peer | null; after: Peer | null } | null;
  /** An interval that began before the window and reaches into it. */
  spansIn: boolean;
  /** The source record (1.52.0: the jump target is derived from it and `kind`). */
  ref: Ref | null;
}

export interface SourceInfo {
  id: string;
  state: string;
  reason: string | null;
  count: number;
  /** Oldest mark of this source on this page (after the rights filter). */
  oldest: number | null;
  truncated: boolean;
  /** Where a cut read goes on: 'next_page', 'unreachable' or null (not cut). */
  cut: string | null;
  /** Marks dropped as doubles of another source (1.51.0). */
  duplicates: number;
}

export interface Timeline {
  status: string;
  generatedAt: number | null;
  from: number | null;
  until: number | null;
  marks: Mark[];
  sources: SourceInfo[];
  omittedClientMarks: number;
  truncated: boolean;
  /** Where the next older page starts (`cursor`), null at the end (1.51.0). */
  nextCursor: string | null;
  /** Intervals that began before `from` and reach into the window; only on a first page (`spans=1`). */
  spanning: Mark[];
  /** More of them than the server sends (200). */
  spanningTruncated: boolean;
}

/** One client session of GET …/sessions (administrators only). */
export interface Session {
  id: string;
  client: string | null;
  clientName: string | null;
  routerId: string | null;
  routerName: string | null;
  /** Start, epoch seconds (the list is ordered and paged on it). */
  ts: number;
  end: number | null;
  endState: EndState | null;
  /** 2.4, 5 or 6 (GHz); null when unknown. */
  band: number | null;
  params: Record<string, number>;
  derived: boolean;
}

export interface SessionsAnswer {
  /** ok | off | clients_off | unavailable */
  status: string;
  reason: string | null;
  generatedAt: number | null;
  from: number | null;
  until: number | null;
  recording: boolean;
  sessions: Session[];
  truncated: boolean;
  nextCursor: string | null;
}

export interface SessionFilters {
  window: string;
  routerId: string | null;
  client: string | null;
}

export interface SessionQuery {
  from: number;
  until: number;
  client: string | null;
  routerId: string | null;
  /** Older pages: the previous answer's next_cursor, same window and filters. */
  cursor: string | null;
}

/** A fixed window (epoch seconds), set only by a jump from "Zustand" or "Vergleich". */
export interface CustomWindow {
  from: number;
  until: number;
}

/** What the filter bar asks the server for (the group chips filter locally). */
export interface Filters {
  /** One of WINDOWS, or 'custom' (then `custom` holds the window). */
  window: string;
  /** Sources switched off by the user (all on by default). */
  sourcesOff: readonly string[];
  severity: 'all' | 'warning' | 'critical';
  routerId: string | null;
  /** 1.52.0: the window of 'custom' (null otherwise). */
  custom: CustomWindow | null;
  /** 1.52.0: a client pseudonym `tmc_…` (administrators only). */
  client: string | null;
}

export interface TimelineQuery {
  from: number;
  until: number;
  sources: readonly string[] | null;
  minSeverity: Severity | null;
  routerId: string | null;
  /** First page and refreshes: ask for the intervals reaching into the window (`spans=1`). */
  spans: boolean;
  /** Older pages: the previous answer's next_cursor, same window and filters, no spans. */
  cursor: string | null;
  /** 1.52.0: client pseudonym (administrators only; never sent otherwise). */
  client: string | null;
}

// ── State at a moment (GET …/state, 1.52.0) ──────────────────────────────

/** One reconstructed value: a reason means "unknown", and then the value is never shown. */
export interface Known<T> {
  value: T | null;
  derived: boolean;
  reason: string | null;
  /** `lan_down` on "not reachable" (the router answered, its LAN did not). */
  cause: string | null;
}

export interface UplinkValue {
  routerId: string | null;
  routerName: string | null;
}

export interface RadioItem {
  key: string;
  band: string | null;
  channel: number | null;
  width: number | null;
  /** up | down | unknown */
  state: string;
  reason: string | null;
}

export interface Part {
  /** ok | partial | unknown | off | unreadable */
  state: string;
  reason: string | null;
}

export interface TrafficWan {
  state: string;
  avgRxBps: number | null;
  avgTxBps: number | null;
  timeCoverage: number | null;
}

export interface UtilizationRadio {
  band: string | null;
  state: string;
  mean: number | null;
  maximum: number | null;
}

export interface RouterState {
  routerId: string;
  routerName: string | null;
  reachable: Known<boolean>;
  role: Known<string>;
  uplink: Known<UplinkValue>;
  radios: Part & { derived: boolean; items: RadioItem[] };
  traffic: Part & { hour: number | null; wan: TrafficWan[] };
  utilization: Part & { hour: number | null; radios: UtilizationRadio[] };
}

export interface IncidentItem {
  id: string | null;
  type: string | null;
  severity: Severity;
  routerId: string | null;
  routerName: string | null;
  fleet: boolean;
  since: number | null;
  /** Comparison only: when it was opened or resolved between the two moments. */
  at: number | null;
  state: string;
  reason: string | null;
  target: JumpTarget | null;
}

export interface ConfigItem {
  routerId: string | null;
  routerName: string | null;
  versionId: string | null;
  createdAt: number | null;
  code: string | null;
  target: JumpTarget | null;
}

export interface ClientItem {
  id: string;
  client: string | null;
  clientName: string | null;
  routerId: string | null;
  routerName: string | null;
  start: number | null;
  band: number | null;
  derived: boolean;
}

export interface ClientsPart extends Part {
  items: ClientItem[];
  perRouter: { routerId: string; routerName: string | null; clients: number }[];
  total: number;
  truncated: boolean;
  nextCursor: string | null;
}

export interface StateAnswer {
  /** ok | off | unavailable */
  status: string;
  reason: string | null;
  generatedAt: number | null;
  at: number | null;
  known: boolean;
  unknownReason: string | null;
  routers: RouterState[];
  routersTruncated: boolean;
  intervals: Mark[];
  intervalsTotal: number;
  intervalsTruncated: boolean;
  incidents: (Part & { items: IncidentItem[]; total: number; truncated: boolean }) | null;
  config: (Part & { items: ConfigItem[] }) | null;
  clients: ClientsPart | null;
}

export interface StateQuery {
  at: number;
  routerId: string | null;
  /** Administrators only: the next page of the client list. */
  clientsCursor: string | null;
}

// ── Comparison (GET …/compare, 1.52.0) ───────────────────────────────────

export interface Change<T> {
  from: T | null;
  to: T | null;
  /** changed | same | unknown */
  state: string;
}

export interface RadioChange {
  key: string | null;
  band: string | null;
  from: { channel: number | null; width: number | null; state: string } | null;
  to: { channel: number | null; width: number | null; state: string } | null;
  state: string;
  reason: string | null;
}

export interface RouterChange {
  routerId: string;
  routerName: string | null;
  reachable: Change<boolean>;
  role: Change<string>;
  uplink: Change<UplinkValue>;
  radios: RadioChange[];
  clients: { from: number; to: number; delta: number } | null;
}

export interface CompareAnswer {
  status: string;
  reason: string | null;
  generatedAt: number | null;
  t1: number | null;
  t2: number | null;
  before: StateAnswer | null;
  after: StateAnswer | null;
  routers: RouterChange[];
  marks: { count: number; byGroup: Record<string, number> };
  incidents: Part & { opened: IncidentItem[]; resolved: IncidentItem[]; truncated: boolean };
  configVersions: Part & { items: ConfigItem[]; total: number; truncated: boolean };
  /**
   * Entries of the other timeline sources with t1 ≤ ts < t2 (review F; null
   * when the server sent none: then it is unknown whether anything happened).
   */
  otherSources: OtherSources | null;
}

export interface OtherSources {
  /** ok | unreadable | off */
  state: string;
  reason: string | null;
  count: number;
  truncated: boolean;
  /** Source ids that could not be read. */
  unreadable: string[];
}

export interface CompareQuery {
  t1: number;
  t2: number;
  routerId: string | null;
}

// ── Export (GET …/export, 1.52.0, administrators only) ───────────────────

export interface ExportFile {
  /** The answer as the server sent it (saved as a file, never shown). */
  blob: Blob;
  /** `ok`, `partial`, `off` or `unavailable` (with `reason`); a file without a mark is never saved. */
  status: string;
  reason: string | null;
  marks: number;
  /** Intervals that began before the window and reach into it (`spanning`). */
  spanning: number;
  truncated: boolean;
  nextCursor: string | null;
  /** Client marks of the whole window left out of the file (the same on every page). */
  omittedClientMarks: number;
}

export interface TmHass {
  callApi<T>(method: 'GET', path: string, parameters?: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean };
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<void>;
  };
}

export interface TmApi {
  timeline(q: TimelineQuery): Promise<Timeline>;
  sessions(q: SessionQuery): Promise<SessionsAnswer>;
  state?(q: StateQuery): Promise<StateAnswer>;
  compare?(q: CompareQuery): Promise<CompareAnswer>;
  exportFile?(q: TimelineQuery): Promise<ExportFile>;
}
