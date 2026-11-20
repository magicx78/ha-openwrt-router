/**
 * securityTypes.ts — shapes of the Security Center panel.
 *
 * The server sends snake_case JSON; securityLogic.ts parses it defensively
 * into these camelCase view types (unknown fields ignored, a missing or
 * wrongly typed field becomes null / empty, never a made-up value such as 0
 * or "healthy"). Type-only module: no runtime code (node --test strips it).
 *
 * Times are epoch SECONDS (floats), as the backend sends them.
 */

/** Minimal hass the security client needs (structurally the panel's HassLike). */
export interface SecurityHass {
  callApi<T>(method: 'GET' | 'POST', path: string, parameters?: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean };
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<void>;
  };
}

export type SecSeverity = 'info' | 'warning' | 'critical';
export type IncidentStatus = 'open' | 'resolved' | 'confirmed';
export type LogPath = 'off' | 'syslog' | 'collector';

export interface ScoreFactor {
  id: string;
  /** null = not assessable (never shown as 0). */
  deduction: number | null;
  weight: number | null;
  assessable: boolean;
  partial: boolean;
  limitations: string[];
  missing: string[];
}

export interface Score {
  /** null = no rating possible. */
  score: number | null;
  coverage: number | null;
  cap: number | null;
  reason: string | null;
  factors: ScoreFactor[];
  routers: number | null;
}

export interface Coverage {
  value: number | null;
  available: string[];
  stale: string[];
  missing: string[];
}

export interface Incident {
  id: string;
  type: string | null;
  detector: string | null;
  category: string | null;
  severity: string | null;
  assessment: string | null;
  status: string | null;
  routerId: string | null;
  /** Pseudonym (`cli_…`) or mask; null when the incident has no device. */
  clientRef: string | null;
  hasClient: boolean;
  /** Plain MAC, administrators only. */
  client: string | null;
  clientName: string | null;
  firstSeen: number | null;
  lastSeen: number | null;
  count: number | null;
  evidence: string[];
  linkedIncidentIds: string[];
  driftRefs: string[];
  title: string | null;
  hint: string | null;
  resolvedAt: number | null;
  /** The finding came from log lines (firewall / DNS via syslog), which can be forged. */
  fromLogs: boolean;
}

export interface TimelineEntry {
  ts: number | null;
  kind: string | null;
  category: string | null;
  severity: string | null;
  routerId: string | null;
  clientRef: string | null;
  hasClient: boolean;
  client: string | null;
  incidentId: string | null;
  type: string | null;
  driftId: string | null;
  linked: string[];
  text: string | null;
}

export interface Device {
  /** Plain MAC for administrators, a `cli_…` pseudonym (or the mask) for others. */
  mac: string | null;
  ip: string | null;
  hostname: string | null;
  name: string | null;
  /** Non-admins: a name exists but is withheld. */
  nameSet: boolean;
  state: string | null;
  firstSeen: number | null;
  lastSeen: number | null;
  privateMac: boolean;
  confirmed: boolean;
  /** false = the device is stored but currently not observed. */
  observed: boolean;
  indicators: string[];
}

export interface Detection {
  id: string;
  availability: string;
  reason: string[];
  missing: string[];
  limitations: string[];
  learning: boolean;
  formatUnconfirmed: boolean;
}

export interface SourceStatus {
  source: string;
  availability: string;
  reason: string | null;
  lastOk: number | null;
}

export interface Receiver {
  listening: boolean | null;
  reason: string | null;
  port: number | null;
  senders: number | null;
}

export interface LogPathView {
  setting: string | null;
  status: SourceStatus[];
  receiver: Receiver | null;
  /** Routers whose lines were recently dropped by the rate limit (detections "eingeschränkt"). */
  rateLimitedRouters: number | null;
}

/** Store limits of the hints (counters only; null = not sent). */
export interface Limits {
  incidentCap: number | null;
  incidentsCapDropped: number | null;
  /** At most this many stored hints may come from log lines (syslog receiver). */
  logIncidentQuota: number | null;
  logIncidents: number | null;
  incidentsLogQuotaDropped: number | null;
  /** At most this many stored hints may come from all other sources (Wi-Fi, drift, devices). */
  otherIncidentQuota: number | null;
  otherIncidents: number | null;
  incidentsOtherQuotaDropped: number | null;
  eventsThrottled: number | null;
}

export interface DeviceCounts {
  known: number | null;
  new: number | null;
  unrecognized: number | null;
  suspicious: number | null;
  quarantined: number | null;
}

export interface Overview {
  enabled: boolean;
  active: boolean;
  /** false = no hints are recorded (e.g. the core's module key is missing); unknown counts as false. */
  ready: boolean;
  /** Reason token while not ready (`module_key_missing`). */
  notReadyReason: string | null;
  adminView: boolean;
  score: Score;
  coverage: Coverage;
  incidents: Incident[];
  timeline: TimelineEntry[];
  devices: Device[];
  deviceCounts: DeviceCounts;
  detections: Detection[];
  logPath: LogPathView;
  /** Number of subnet->zone entries; null when the server did not say. */
  subnetZones: number | null;
  limits: Limits;
}

export interface IncidentDetail {
  adminView: boolean;
  incident: Incident;
  timeline: TimelineEntry[];
  now: number | null;
}

export interface DetectionsView {
  enabled: boolean;
  active: boolean;
  detections: Detection[];
  /** router id -> status of each of its sources */
  sources: Record<string, SourceStatus[]>;
  logPath: LogPathView;
}

export interface Settings {
  enabled: boolean;
  logPath: string | null;
  syslogPort: number | null;
  thresholdCount: number;
  zoneCount: number;
}

export interface SettingsView {
  settings: Settings;
  subnetZoneCount: number | null;
  active: boolean;
  canEdit: boolean;
  receiver: Receiver | null;
}

/** The fields of POST /settings this panel sends (thresholds/zones stay untouched). */
export interface SettingsUpdate {
  enabled?: boolean;
  log_path?: 'off' | 'syslog';
  syslog_port?: number;
}

/** Filters of the overview (all optional; unset = not sent). */
export interface OverviewFilters {
  /** Epoch seconds. */
  since?: number;
  until?: number;
  routerId?: string;
  /** MAC (admin) or `cli_…` reference. */
  client?: string;
  category?: string;
  severity?: SecSeverity;
  limit?: number;
}

export interface SecurityApi {
  overview(filters?: OverviewFilters): Promise<Overview>;
  incident(id: string): Promise<IncidentDetail>;
  detections(): Promise<DetectionsView>;
  settings(): Promise<SettingsView>;
  updateSettings(update: SettingsUpdate): Promise<SettingsView>;
  setIncidentStatus(id: string, status: IncidentStatus): Promise<Incident>;
  confirmDevice(mac: string, name?: string): Promise<void>;
  setDeviceName(mac: string, name: string | null): Promise<void>;
}
