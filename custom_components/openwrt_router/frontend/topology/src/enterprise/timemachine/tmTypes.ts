/**
 * tmTypes.ts — view types of the "Zeitreise" tab (Network Time Machine,
 * Phase A). The server answer is `v: 1` of GET
 * /api/openwrt_router/enterprise/timemachine/timeline (docs/time-machine.md).
 */

export type Severity = 'info' | 'warning' | 'critical';
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
  nextUntil: number | null;
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
}
