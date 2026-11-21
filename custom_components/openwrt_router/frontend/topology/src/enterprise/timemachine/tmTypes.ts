/**
 * tmTypes.ts — view types of the "Zeitreise" tab (Network Time Machine,
 * Phases A–C). The server answers are `v: 1` of GET
 * /api/openwrt_router/enterprise/timemachine/timeline and …/sessions
 * (docs/time-machine.md).
 */

export type Severity = 'info' | 'warning' | 'critical';
export type EndState = 'open' | 'closed' | 'unknown';

/** One end of a roam or uplink change (names only from the server). */
export interface Peer {
  routerId: string | null;
  routerName: string | null;
}
export type Tone = 'info' | 'warn' | 'critical' | 'muted';

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

/** What the filter bar asks the server for (the group chips filter locally). */
export interface Filters {
  window: string;
  /** Sources switched off by the user (all on by default). */
  sourcesOff: readonly string[];
  severity: 'all' | 'warning' | 'critical';
  routerId: string | null;
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
}
