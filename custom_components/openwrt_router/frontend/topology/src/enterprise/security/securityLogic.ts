/**
 * securityLogic.ts — pure logic of the Security Center tab.
 *
 * Parsers (server JSON -> view types), German texts per code / token, the
 * score / counts / availability view rules, the filter and settings-form
 * helpers. No React, no DOM, no network: node --test imports it.
 *
 * Hard rules kept here:
 *  - Unknown is never healthy: a missing / null / wrongly typed value stays
 *    null and is shown as "unbekannt" / "nicht verfügbar", never as 0 or green.
 *    A score of null is "keine Bewertung möglich".
 *  - Free text of the server (titles, hints, evidence, timeline text) is
 *    returned as plain strings and rendered as text only. Error messages of
 *    the server are dropped; errors are mapped from their `code` / status.
 *  - Careful wording: "Hinweis", "Indikator", "Hypothese"; never "Angriff".
 */

import type {
  Coverage,
  Detection,
  DetectionsView,
  Device,
  DeviceCounts,
  Incident,
  IncidentDetail,
  LogPathView,
  Overview,
  OverviewFilters,
  Receiver,
  Score,
  ScoreFactor,
  SecSeverity,
  Settings,
  SettingsUpdate,
  SettingsView,
  SourceStatus,
  TimelineEntry,
} from './securityTypes';

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
/** A comma-joined token list ("a,b") as an array. */
function tokens(v: unknown): string[] {
  return typeof v === 'string' ? v.split(',').map(s => s.trim()).filter(Boolean) : [];
}

/** Look a token up in a label map; an unknown token is shown as itself. */
export function label(map: Record<string, string>, key: string | null | undefined): string {
  if (!key) return '–';
  return map[key] ?? key;
}

// ── Error ────────────────────────────────────────────────────────────────

/** A failed security request. Carries status and code only, never the server message. */
export class SecurityApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly details: { field?: string; reason?: string };

  constructor(status: number | null, code: string, details: { field?: string; reason?: string } = {}) {
    super(`security api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'SecurityApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type ErrorKind =
  | 'forbidden' | 'disabled' | 'gone' | 'unavailable' | 'not_found' | 'invalid'
  | 'too_large' | 'session' | 'network' | 'other';

export interface ErrorInfo {
  kind: ErrorKind;
  message: string;
  retry: boolean;
}

export const ERROR_TEXT: Record<string, string> = {
  invalid_request: 'Die Eingabe wurde vom Server nicht akzeptiert.',
  body_too_large: 'Die Eingabe ist zu groß.',
  authorization_denied: 'Das dürfen nur Administratoren.',
  integration_not_loaded: 'Die Integration ist nicht geladen.',
  not_running: 'Das Security Center läuft nicht.',
  unknown_incident: 'Dieser Hinweis ist nicht mehr vorhanden.',
  unknown_device: 'Dieses Gerät ist nicht bekannt.',
  disabled: 'Das Security Center ist ausgeschaltet.',
  no_core: 'Der Enterprise Core läuft nicht.',
  refused: 'Die Aktion wurde abgelehnt.',
  internal: 'Der Server konnte die Anfrage nicht verarbeiten.',
};

export function errorInfo(err: unknown): ErrorInfo {
  if (!(err instanceof SecurityApiError)) {
    const name = (err as { name?: unknown } | null)?.name;
    if (err instanceof TypeError || name === 'AbortError' || name === 'NetworkError') {
      return { kind: 'network', message: 'Keine Verbindung zu Home Assistant. Bitte erneut versuchen.', retry: true };
    }
    return { kind: 'other', message: 'Unerwarteter Fehler im Panel.', retry: true };
  }
  const known = ERROR_TEXT[err.code];
  switch (err.status) {
    case 400:
      return { kind: 'invalid', message: known ?? ERROR_TEXT.invalid_request, retry: false };
    case 401:
      return { kind: 'session', message: 'Die Sitzung ist abgelaufen. Bitte die Seite neu laden.', retry: false };
    case 403:
      return { kind: 'forbidden', message: known ?? ERROR_TEXT.authorization_denied, retry: false };
    case 404:
      return { kind: 'not_found', message: known ?? 'Nicht gefunden.', retry: false };
    case 409:
      return { kind: 'disabled', message: ERROR_TEXT.disabled, retry: false };
    case 410:
      return { kind: 'gone', message: ERROR_TEXT.integration_not_loaded, retry: true };
    case 413:
      return { kind: 'too_large', message: ERROR_TEXT.body_too_large, retry: false };
    case 503:
      return { kind: 'unavailable', message: known ?? ERROR_TEXT.not_running, retry: true };
    default:
      return { kind: 'other', message: known ?? 'Die Anfrage ist fehlgeschlagen.', retry: err.status === null || err.status >= 500 };
  }
}

// ── Labels ───────────────────────────────────────────────────────────────

export const SEVERITY_LABEL: Record<string, string> = { info: 'Info', warning: 'Warnung', critical: 'Kritisch' };
export const SEVERITY_TONE: Record<string, string> = { info: 'info', warning: 'warn', critical: 'critical' };

export const CATEGORY_LABEL: Record<string, string> = {
  device: 'Gerät', wifi: 'WLAN', firewall: 'Firewall', dns: 'DNS', vlan: 'Segmentierung (VLAN)',
  admin: 'Verwaltung', config: 'Konfiguration', system: 'System',
};
export const CATEGORIES = Object.keys(CATEGORY_LABEL);

export const STATUS_LABEL: Record<string, string> = { open: 'Offen', confirmed: 'Bestätigt', resolved: 'Erledigt' };
export const STATUS_TONE: Record<string, string> = { open: 'warn', confirmed: 'info', resolved: 'muted' };
export const STATUS_HELP: Record<string, string> = {
  open: 'Der Hinweis ist neu oder wieder aufgetreten und wurde noch nicht geprüft.',
  confirmed: 'Der Hinweis wurde von einer Person geprüft und bleibt aktiv, bis er erledigt ist.',
  resolved: 'Der Hinweis ist erledigt. Er öffnet sich wieder, wenn sich der Indikator wiederholt.',
};

/** How the finding is classified. Hypothesis wording: never "Angriff". */
export const ASSESSMENT_LABEL: Record<string, string> = {
  normal: 'Unauffällig',
  noticeable: 'Auffällig (Hinweis)',
  suspicious: 'Mehrere Indikatoren (Hypothese)',
  confirmed: 'Mit Beleg bestätigt',
};

export const TIMELINE_KIND_LABEL: Record<string, string> = {
  incident_opened: 'Hinweis eröffnet',
  incident_reopened: 'Hinweis erneut aufgetreten',
  incident_resolved: 'Hinweis erledigt',
  reused: 'Bereits durch Network Intelligence abgedeckt',
  drift: 'Konfigurationsänderung erkannt',
  notice: 'Gerätehinweis',
  action: 'Manuelle Aktion',
  status: 'Status geändert',
};

export const TRUST_LABEL: Record<string, string> = {
  known: 'Bekannt',
  new: 'Neu',
  unrecognized: 'Nicht erkannt',
  suspicious: 'Mehrere Indikatoren',
  quarantined: 'Als isoliert markiert',
};
export const TRUST_TONE: Record<string, string> = {
  known: 'ok', new: 'info', unrecognized: 'warn', suspicious: 'critical', quarantined: 'critical',
};
export const TRUST_HELP: Record<string, string> = {
  known: 'Von einem Administrator bestätigt.',
  new: 'Erst kürzlich im Netz gesehen.',
  unrecognized: 'Schon länger im Netz, aber nicht bestätigt.',
  suspicious: 'Mehrere unabhängige Indikatoren; eine Hypothese, kein Beleg.',
  quarantined: 'Manuell als isoliert markiert. Das Security Center sperrt selbst nichts.',
};

export const INDICATOR_LABEL: Record<string, string> = {
  ip_churn: 'Häufiger IP-Wechsel',
  hostname_change: 'Hostname geändert',
  login_failures: 'WLAN-Anmeldefehler',
  multi_ap_auth: 'Anmeldefehler an mehreren Zugangspunkten',
  assoc_burst: 'Viele Verbindungsversuche',
  port_scan: 'Hinweis auf Port-Abfrage',
  mgmt_access: 'Zugriffsversuche auf die Router-Verwaltung',
  inter_vlan: 'Verbindungsversuche zwischen Segmenten',
  dns_anomaly: 'Auffällige DNS-Anfragen',
  traffic_anomaly: 'Auffälliger Datenverkehr',
  mac_spoof: 'MAC-Adresse möglicherweise nachgeahmt',
};

/** Detection ids (= detector ids) with their German titles. */
export const DETECTION_LABEL: Record<string, string> = {
  wifi_auth_repeat: 'Wiederholte WLAN-Anmeldefehler eines Geräts',
  wifi_auth_many_clients: 'Anmeldefehler vieler Geräte an einem Zugangspunkt',
  wifi_assoc_burst: 'Auffällig viele WLAN-Verbindungsversuche',
  wifi_deauth_cluster: 'Gehäufte WLAN-Abmeldungen',
  wifi_multi_ap_auth: 'Anmeldefehler eines Geräts an mehreren Zugangspunkten',
  fw_blocked: 'Ungewöhnlich viele blockierte Verbindungen',
  fw_port_scan_hint: 'Hinweis auf eine Port-Abfrage',
  fw_mgmt_access: 'Zugriffsversuche auf die Router-Verwaltung',
  fw_inter_vlan: 'Verbindungsversuche zwischen Netzsegmenten',
  vlan_segmentation_drift: 'Segmentierungsrelevante Konfigurationsänderung',
  dns_rate: 'Ungewöhnlich viele DNS-Anfragen',
  dns_nxdomain_cluster: 'Gehäufte DNS-Anfragen an nicht vorhandene Namen',
  dns_many_domains: 'Auffällig viele verschiedene DNS-Namen',
  dns_tunnel_hint: 'Hinweis auf ungewöhnliche DNS-Namen',
  trust_suspicious: 'Gerät mit mehreren Auffälligkeiten',
};

/** Data source keys (capability names) with German names. */
export const SOURCE_LABEL: Record<string, string> = {
  'data.logs': 'Router-Log',
  'data.hostapd_clients': 'WLAN-Clients (hostapd)',
  'data.dhcp_leases': 'DHCP-Leases',
  'data.services': 'Dienste',
  'data.iwinfo': 'WLAN-Scan',
  'data.uci': 'UCI-Konfiguration',
  'config.drift': 'Konfigurationsabweichungen (Drift)',
  'security.center.wifi_events': 'WLAN-Ereignisse',
  'security.center.ni_incidents': 'Network-Intelligence-Vorfälle',
  'security.center.client_history': 'Geräteverlauf (Client Stability)',
  'security.center.arp_table': 'ARP-Tabelle',
  'security.center.bridge_fdb': 'Bridge-Tabelle',
  'security.center.iface_counters': 'Schnittstellen-Zähler',
  'security.center.router_uptime': 'Router-Laufzeit',
  'security.center.dns_errors': 'DNS-Fehlermeldungen',
  'security.center.admin_login_log': 'Anmeldungen an der Router-Verwaltung',
  'security.center.conntrack_stats': 'Verbindungsverfolgung (Zähler)',
  'security.center.nft_counters': 'Firewall-Zähler',
  'security.center.net_snmp': 'Netzwerk-Statistik',
  'security.center.dnsmasq_metrics': 'dnsmasq-Statistik',
  'security.center.ipv6_neighbors': 'IPv6-Nachbarn',
  'security.center.firewall_log': 'Firewall-Log (Syslog)',
  'security.center.dns_query_log': 'DNS-Anfrage-Log (Syslog)',
};

/** Reason tokens of sources, detections, limitations and the syslog receiver. */
export const REASON_TEXT: Record<string, string> = {
  ok: 'in Ordnung',
  no_data_yet: 'noch keine Daten empfangen',
  not_checked: 'noch nicht geprüft',
  not_probed: 'noch nicht abgefragt',
  not_detected: 'auf dem Router nicht erkannt',
  permission_denied: 'Recht fehlt',
  transport_unsupported: 'Übertragungsweg nicht unterstützt',
  unsupported_firmware: 'Firmware nicht unterstützt',
  router_offline: 'Router nicht erreichbar',
  entry_not_loaded: 'Router-Eintrag nicht geladen',
  disabled: 'ausgeschaltet',
  no_provider: 'kein Anbieter vorhanden',
  provider_declined: 'Anbieter lehnt ab',
  determined_on_first_use: 'wird erst bei der ersten Nutzung festgestellt',
  stale: 'Daten veraltet',
  not_reported: 'vom Router nicht gemeldet',
  collector_not_available: 'Collector ist noch nicht verfügbar',
  sender_not_allowed: 'Router sendet nicht von der erwarteten Adresse',
  no_core: 'Enterprise Core läuft nicht',
  no_engine: 'Auswertung (Network Intelligence) läuft nicht',
  no_router: 'noch kein Router bekannt',
  port_in_use: 'Port ist belegt',
  address_not_available: 'Adresse nicht verfügbar',
  bind_failed: 'Port konnte nicht geöffnet werden',
  receiver_not_started: 'Empfänger nicht gestartet',
  receiver_stopped: 'Empfänger gestoppt',
  capacity: 'Speichergrenze erreicht: „nichts gesehen“ ist dann nicht belegt',
  baseline_capacity: 'Speichergrenze der Vergleichswerte erreicht',
  dest_zone_unknown: 'Zielzone unbekannt: Verbindungen zwischen Segmenten sind nicht vollständig bewertbar',
  drift_area_unknown: 'Bereich der Änderung unbekannt',
};

export const LOG_PATH_LABEL: Record<string, string> = {
  off: 'Aus (keine Logs außerhalb des Routers)',
  syslog: 'Syslog an Home Assistant',
  collector: 'Collector',
};

export const FACTOR_LABEL: Record<string, string> = {
  active_incidents: 'Aktive Hinweise',
  critical_config_changes: 'Kritische Konfigurationsänderungen',
  login_failures: 'Anmeldefehler',
  network_activity: 'Auffälligkeiten im Netzwerkverkehr',
  unknown_devices: 'Unbekannte Geräte',
  segmentation: 'Segmentierung',
  detection_coverage: 'Lücken in der Erkennung',
};

/** Data source of a finding, by its detector id (derived: the backend sends none per incident). */
export function detectorSource(detector: string | null): string | null {
  if (!detector) return null;
  if (detector.startsWith('wifi_')) return 'security.center.wifi_events';
  if (detector.startsWith('fw_')) return 'security.center.firewall_log';
  if (detector.startsWith('dns_')) return 'security.center.dns_query_log';
  if (detector.startsWith('vlan_')) return 'config.drift';
  if (detector.startsWith('trust_')) return 'security.center.client_history';
  return null;
}

/** Sources whose content is log text; log lines can be forged. */
const LOG_SOURCES: ReadonlySet<string> = new Set([
  'data.logs', 'security.center.wifi_events', 'security.center.firewall_log',
  'security.center.dns_query_log', 'security.center.dns_errors', 'security.center.admin_login_log',
]);
export function isLogSource(source: string | null): boolean {
  return source !== null && LOG_SOURCES.has(source);
}

/** Reason tokens as German text; an unknown token is shown as itself. */
export function reasonText(reasons: readonly string[]): string {
  return reasons.map(r => label(REASON_TEXT, r)).join('; ');
}

export function detectionTitle(id: string): string {
  return DETECTION_LABEL[id] ?? id;
}

export function sourceName(source: string): string {
  return SOURCE_LABEL[source] ?? source;
}

// ── Parsers ──────────────────────────────────────────────────────────────

function parseFactor(o: Obj): ScoreFactor | null {
  const id = str(o.id);
  if (!id) return null;
  const assessable = o.assessable === true;
  return {
    id,
    // not assessable: never a number, whatever the server sent
    deduction: assessable ? num(o.deduction) : null,
    weight: num(o.weight),
    assessable,
    partial: o.partial === true,
    limitations: strList(o.limitations),
    missing: strList(o.missing),
  };
}

function parseScore(v: unknown): Score {
  const o = obj(v) ?? {};
  return {
    score: num(o.score),
    coverage: num(o.coverage),
    cap: num(o.cap),
    reason: str(o.reason),
    factors: objList(o.factors).map(parseFactor).filter((f): f is ScoreFactor => f !== null),
    routers: num(o.routers),
  };
}

function parseCoverage(v: unknown): Coverage {
  const o = obj(v) ?? {};
  return {
    value: num(o.value),
    available: strList(o.available),
    stale: strList(o.stale),
    missing: strList(o.missing),
  };
}

export function parseIncident(v: unknown): Incident | null {
  const o = obj(v);
  const id = o ? str(o.id) : null;
  if (!o || !id) return null;
  return {
    id,
    type: str(o.type),
    detector: str(o.detector),
    category: str(o.category),
    severity: str(o.severity),
    assessment: str(o.assessment),
    status: str(o.status),
    routerId: str(o.router_id),
    clientRef: str(o.client_ref),
    hasClient: o.has_client === true,
    client: str(o.client),
    clientName: str(o.client_name),
    firstSeen: num(o.first_seen),
    lastSeen: num(o.last_seen),
    count: num(o.count),
    evidence: strList(o.evidence),
    linkedIncidentIds: strList(o.linked_incident_ids),
    driftRefs: strList(o.drift_refs),
    title: str(o.title),
    hint: str(o.hint),
    resolvedAt: num(o.resolved_at),
  };
}

function parseTimelineEntry(o: Obj): TimelineEntry {
  return {
    ts: num(o.ts),
    kind: str(o.kind),
    category: str(o.category),
    severity: str(o.severity),
    routerId: str(o.router_id),
    clientRef: str(o.client_ref),
    hasClient: o.has_client === true,
    client: str(o.client),
    incidentId: str(o.incident_id),
    type: str(o.type),
    driftId: str(o.drift_id),
    linked: strList(o.linked),
    text: str(o.text),
  };
}

function parseDevice(o: Obj): Device {
  return {
    mac: str(o.mac),
    ip: str(o.ip),
    hostname: str(o.hostname),
    name: str(o.name),
    nameSet: o.name_set === true,
    state: str(o.state),
    firstSeen: num(o.first_seen),
    lastSeen: num(o.last_seen),
    privateMac: o.private_mac === true,
    confirmed: o.confirmed === true,
    // Only an explicit false means "not observed"; a missing field stays unknown -> observed
    observed: o.observed !== false,
    indicators: strList(o.indicators),
  };
}

function parseCounts(v: unknown): DeviceCounts {
  const o = obj(v) ?? {};
  return {
    known: num(o.known),
    new: num(o.new),
    unrecognized: num(o.unrecognized),
    suspicious: num(o.suspicious),
    quarantined: num(o.quarantined),
  };
}

function parseDetection(o: Obj): Detection | null {
  const id = str(o.id);
  if (!id) return null;
  return {
    id,
    availability: str(o.availability) ?? 'unknown',
    reason: tokens(o.reason),
    missing: strList(o.missing),
    limitations: strList(o.limitations),
    learning: o.learning === true,
    formatUnconfirmed: o.format_unconfirmed === true,
  };
}

function parseDetections(v: unknown): Detection[] {
  return objList(v).map(parseDetection).filter((d): d is Detection => d !== null);
}

function parseSourceStatus(o: Obj): SourceStatus | null {
  const source = str(o.source);
  if (!source) return null;
  return {
    source,
    availability: str(o.availability) ?? 'unknown',
    reason: str(o.reason),
    lastOk: num(o.last_ok),
  };
}

function parseSourceList(v: unknown): SourceStatus[] {
  return objList(v).map(parseSourceStatus).filter((s): s is SourceStatus => s !== null);
}

function parseReceiver(v: unknown): Receiver | null {
  const o = obj(v);
  if (!o) return null;
  return {
    listening: bool(o.listening),
    reason: str(o.reason),
    port: num(o.port),
    senders: num(o.senders),
  };
}

function parseLogPath(v: unknown): LogPathView {
  const o = obj(v) ?? {};
  return {
    setting: str(o.setting),
    status: parseSourceList(o.status),
    receiver: parseReceiver(o.receiver),
  };
}

export function parseOverview(v: unknown): Overview {
  const o = obj(v) ?? {};
  const subnet = obj(o.subnet_map);
  return {
    enabled: o.enabled === true,
    active: o.active === true,
    adminView: o.admin_view === true,
    score: parseScore(o.score),
    coverage: parseCoverage(o.coverage),
    incidents: objList(o.incidents).map(parseIncident).filter((i): i is Incident => i !== null),
    timeline: objList(o.timeline).map(parseTimelineEntry),
    devices: objList(o.devices).map(parseDevice),
    deviceCounts: parseCounts(o.device_counts),
    detections: parseDetections(o.detections),
    logPath: parseLogPath(o.log_path),
    subnetZones: subnet ? num(subnet.subnets) : null,
  };
}

export function parseIncidentDetail(v: unknown): IncidentDetail | null {
  const o = obj(v);
  const incident = o ? parseIncident(o.incident) : null;
  if (!o || !incident) return null;
  return {
    adminView: o.admin_view === true,
    incident,
    timeline: objList(o.timeline).map(parseTimelineEntry),
    now: num(o.now),
  };
}

export function parseDetectionsView(v: unknown): DetectionsView {
  const o = obj(v) ?? {};
  const sources: Record<string, SourceStatus[]> = {};
  const raw = obj(o.sources) ?? {};
  for (const [rid, list] of Object.entries(raw)) sources[rid] = parseSourceList(Object.values(obj(list) ?? {}));
  return {
    enabled: o.enabled === true,
    active: o.active === true,
    detections: parseDetections(o.detections),
    sources,
    logPath: parseLogPath(o.log_path),
  };
}

export function parseSettingsView(v: unknown): SettingsView {
  const o = obj(v) ?? {};
  const s = obj(o.settings) ?? {};
  const settings: Settings = {
    enabled: s.enabled === true,
    logPath: str(s.log_path),
    syslogPort: num(s.syslog_port),
    keepDnsNames: s.keep_dns_names === true,
    thresholdCount: Object.keys(obj(s.thresholds) ?? {}).length,
    zoneCount: Object.keys(obj(s.subnet_zones) ?? {}).length,
  };
  return {
    settings,
    subnetZoneCount: num(o.subnet_zone_count),
    active: o.active === true,
    canEdit: o.can_edit === true,
    receiver: parseReceiver(o.receiver),
  };
}

// ── Score, counts, availability ──────────────────────────────────────────

export type Tone = 'ok' | 'info' | 'warn' | 'critical' | 'muted';

export interface ScoreView {
  known: boolean;
  value: number | null;
  tone: Tone;
  headline: string;
  note: string | null;
}

/**
 * Score card text and tone. null -> "keine Bewertung möglich" (muted, never
 * green). Green only with full coverage; below it the score is capped by the
 * backend and shown neutral (blue) at best.
 */
export function scoreView(score: Score): ScoreView {
  if (score.score === null) {
    return {
      known: false, value: null, tone: 'muted', headline: 'Keine Bewertung möglich',
      note: 'Es gibt noch nicht genug nutzbare Datenquellen. Das heißt nicht, dass alles in Ordnung ist.',
    };
  }
  const full = score.coverage !== null && score.coverage >= 100;
  // Against the cap: a score that reaches the best value the backend allows
  // for this coverage has no deductions (blue while coverage is partial).
  const top = Math.min(80, score.cap ?? 100);
  const tone: Tone = score.score >= top ? (full ? 'ok' : 'info') : score.score >= 50 ? 'warn' : 'critical';
  let note: string | null = null;
  if (!full) {
    note = score.cap !== null && score.cap < 100
      ? `Höchstens ${score.cap} von 100, solange die Überwachung unvollständig ist.`
      : 'Die Überwachung ist unvollständig; der Wert ist nur eingeschränkt aussagekräftig.';
  }
  return { known: true, value: score.score, tone, headline: String(score.score), note };
}

/** The backend's English reason string as German text (null if not recognised). */
export function scoreReasonText(reason: string | null): string | null {
  if (!reason) return null;
  if (reason === 'complete') return 'Alle erwarteten Datenquellen liefern.';
  let m = /^capped at (\d+): partial coverage/.exec(reason);
  if (m) return `Auf ${m[1]} begrenzt: nicht alle erwarteten Datenquellen liefern.`;
  m = /^capped at (\d+): a factor is not assessable/.exec(reason);
  if (m) return `Auf ${m[1]} begrenzt: mindestens ein Faktor ist nicht bewertbar.`;
  if (reason.startsWith('unknown')) return 'Keine nutzbare Datenquelle.';
  return null;
}

function fmt(n: number): string {
  return n.toLocaleString('de-DE', { maximumFractionDigits: 1 });
}

/** One factor row: not assessable is never shown as 0 / "no deduction". */
export function factorText(f: ScoreFactor): { text: string; tone: Tone } {
  if (!f.assessable) return { text: 'nicht bewertbar', tone: 'muted' };
  if (f.deduction === null) return { text: 'unbekannt', tone: 'muted' };
  if (f.deduction <= 0) {
    return f.partial
      ? { text: 'kein Abzug, aber nur eingeschränkt bewertet', tone: 'info' }
      : { text: 'kein Abzug', tone: 'ok' };
  }
  const of = f.weight !== null ? ` von ${fmt(f.weight)}` : '';
  return { text: `−${fmt(f.deduction)}${of} Punkte`, tone: f.deduction >= (f.weight ?? Infinity) ? 'critical' : 'warn' };
}

export function isActiveIncident(i: Incident): boolean {
  // An unknown status is kept visible (counted as active), never dropped.
  return i.status !== 'resolved';
}

export function incidentCounts(incidents: readonly Incident[]): { active: number; critical: number } {
  const active = incidents.filter(isActiveIncident);
  return { active: active.length, critical: active.filter(i => i.severity === 'critical').length };
}

/** Devices that are not "known" (null when the server sent no counts at all). */
export function unknownDeviceCount(c: DeviceCounts): number | null {
  const parts = [c.new, c.unrecognized, c.suspicious, c.quarantined];
  if (parts.every(p => p === null) && c.known === null) return null;
  return parts.reduce<number>((sum, p) => sum + (p ?? 0), 0);
}

export function flaggedDeviceCount(c: DeviceCounts): number | null {
  if (c.suspicious === null && c.quarantined === null) return null;
  return (c.suspicious ?? 0) + (c.quarantined ?? 0);
}

/** Device data is only trustworthy while a source that delivers devices is available. */
export function devicesObserved(cov: Coverage): boolean {
  const sources = ['data.hostapd_clients', 'security.center.client_history'];
  return sources.some(s => cov.available.includes(s));
}

export const DETECTION_AVAILABILITY_LABEL: Record<string, string> = {
  available: 'Verfügbar', limited: 'Eingeschränkt', not_available: 'Nicht verfügbar',
};
export const DETECTION_AVAILABILITY_TONE: Record<string, Tone> = {
  available: 'ok', limited: 'warn', not_available: 'muted',
};
export const SOURCE_AVAILABILITY_LABEL: Record<string, string> = {
  available: 'Verfügbar', stale: 'Veraltet', not_available: 'Nicht verfügbar',
};
export const SOURCE_AVAILABILITY_TONE: Record<string, Tone> = {
  available: 'ok', stale: 'warn', not_available: 'muted',
};

export function detectionLabel(d: Detection): string {
  return DETECTION_AVAILABILITY_LABEL[d.availability] ?? 'Unbekannt';
}
export function detectionTone(d: Detection): Tone {
  return DETECTION_AVAILABILITY_TONE[d.availability] ?? 'muted';
}

/** Limitation tokens of a detection plus the two flags, as German lines. */
export function detectionNotes(d: Detection): string[] {
  const out = d.limitations.map(l => label(REASON_TEXT, l));
  if (d.learning) out.push('Vergleichswerte werden noch gelernt; frühe Ergebnisse sind unsicherer.');
  if (d.formatUnconfirmed) out.push('Format unbestätigt: das Log-Format dieser Erkennung wurde noch nicht an echten Router-Logs bestätigt.');
  return out;
}

// ── Devices ──────────────────────────────────────────────────────────────

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;

/** A real MAC (administrators); pseudonyms (`cli_…`) and the mask are not. */
export function isRealMac(v: string | null): boolean {
  return v !== null && MAC_RE.test(v);
}

const TRUST_ORDER: Record<string, number> = { suspicious: 0, quarantined: 1, unrecognized: 2, new: 3, known: 4 };

export function sortDevices(devices: readonly Device[]): Device[] {
  return [...devices].sort((a, b) => {
    const ra = TRUST_ORDER[a.state ?? ''] ?? 5;
    const rb = TRUST_ORDER[b.state ?? ''] ?? 5;
    return ra - rb || (b.lastSeen ?? 0) - (a.lastSeen ?? 0);
  });
}

export const NAME_MAX = 64;

/** A display name as the backend accepts it (1-64 characters, no control characters). */
export function sanitizeName(raw: string): string | null {
  const text = raw.trim();
  // eslint-disable-next-line no-control-regex
  if (!text || text.length > NAME_MAX || /[\u0000-\u001f\u007f]/.test(text)) return null;
  return text;
}

// ── Time ─────────────────────────────────────────────────────────────────

export function formatTs(sec: number | null): string {
  if (sec === null) return '–';
  const d = new Date(sec * 1000);
  if (Number.isNaN(d.getTime())) return '–';
  return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

export function formatRelativeTs(sec: number | null, nowMs: number): string {
  if (sec === null) return '–';
  const diff = Math.round((nowMs - sec * 1000) / 60000);
  const abs = Math.abs(diff);
  const text = abs < 1 ? 'jetzt'
    : abs < 60 ? `${abs} min`
    : abs < 48 * 60 ? `${Math.round(abs / 60)} h`
    : `${Math.round(abs / 1440)} Tagen`;
  if (text === 'jetzt') return text;
  return diff >= 0 ? `vor ${text}` : `in ${text}`;
}

/** `rtr_0123456789ab…` -> `rtr_012345…`; routers have no name in this API. */
export function shortId(id: string | null): string {
  if (!id) return '–';
  return id.length > 12 ? `${id.slice(0, 10)}…` : id;
}

// ── Timeline filters ─────────────────────────────────────────────────────

export interface RangeOption { id: string; label: string; seconds: number | null }
export const RANGE_OPTIONS: readonly RangeOption[] = [
  { id: '1h', label: 'Letzte Stunde', seconds: 3600 },
  { id: '24h', label: 'Letzte 24 Stunden', seconds: 86400 },
  { id: '7d', label: 'Letzte 7 Tage', seconds: 7 * 86400 },
  { id: 'all', label: 'Gesamter Zeitraum', seconds: null },
];

export interface TimelineFilters {
  range: string;
  routerId: string;
  category: string;
  /** Minimum severity ('' = all). */
  severity: string;
  /** MAC or `cli_…`; set from a device row, '' = all. */
  client: string;
}

export const DEFAULT_FILTERS: TimelineFilters = { range: 'all', routerId: '', category: '', severity: '', client: '' };

export function filtersAreDefault(f: TimelineFilters): boolean {
  return f.range === 'all' && !f.routerId && !f.category && !f.severity && !f.client;
}

export const SEVERITY_FILTER_LABEL: Record<string, string> = { warning: 'ab Warnung', critical: 'nur Kritisch' };

export function toOverviewFilters(f: TimelineFilters, nowSec: number): OverviewFilters {
  const out: OverviewFilters = {};
  const range = RANGE_OPTIONS.find(r => r.id === f.range);
  if (range?.seconds != null) out.since = Math.floor(nowSec - range.seconds);
  if (f.routerId) out.routerId = f.routerId;
  if (f.category) out.category = f.category;
  if (f.severity === 'warning' || f.severity === 'critical' || f.severity === 'info') out.severity = f.severity as SecSeverity;
  if (f.client) out.client = f.client;
  return out;
}

/** Router ids seen anywhere in the data, for the router filter (sorted, unique). */
export function routerIds(o: Overview, d: DetectionsView | null): string[] {
  const ids = new Set<string>();
  for (const i of o.incidents) if (i.routerId) ids.add(i.routerId);
  for (const t of o.timeline) if (t.routerId) ids.add(t.routerId);
  if (d) for (const rid of Object.keys(d.sources)) ids.add(rid);
  return [...ids].sort();
}

// ── Settings form ────────────────────────────────────────────────────────

export interface SettingsDraft {
  enabled: boolean;
  logPath: string;
  syslogPort: string;
  keepDnsNames: boolean;
}

export const PORT_MIN = 1024;
export const PORT_MAX = 65535;

export function draftFromSettings(s: Settings): SettingsDraft {
  return {
    enabled: s.enabled,
    logPath: s.logPath ?? 'off',
    syslogPort: s.syslogPort !== null ? String(s.syslogPort) : '',
    keepDnsNames: s.keepDnsNames,
  };
}

export function portError(text: string): string | null {
  if (!/^\d{1,5}$/.test(text.trim())) return 'Bitte eine Portnummer eingeben.';
  const n = Number(text.trim());
  if (n < PORT_MIN || n > PORT_MAX) return `Der Port muss zwischen ${PORT_MIN} und ${PORT_MAX} liegen.`;
  return null;
}

export interface UpdateBuild {
  /** Only the changed fields; empty = nothing to save. */
  update: SettingsUpdate;
  error: string | null;
}

/** The POST body from the form: changed fields only; collector is never sent. */
export function buildSettingsUpdate(current: Settings, draft: SettingsDraft): UpdateBuild {
  const update: SettingsUpdate = {};
  if (draft.enabled !== current.enabled) update.enabled = draft.enabled;
  if (draft.logPath !== (current.logPath ?? 'off')) {
    if (draft.logPath === 'collector') return { update: {}, error: 'Der Collector ist noch nicht verfügbar.' };
    if (draft.logPath === 'off' || draft.logPath === 'syslog') update.log_path = draft.logPath;
    else return { update: {}, error: 'Unbekannter Log-Pfad.' };
  }
  // The port only matters (and is only checked) while the syslog path is chosen.
  if (draft.logPath === 'syslog') {
    const port = draft.syslogPort.trim();
    const bad = portError(port);
    if (bad) return { update: {}, error: bad };
    if (Number(port) !== current.syslogPort) update.syslog_port = Number(port);
  }
  if (draft.keepDnsNames !== current.keepDnsNames) update.keep_dns_names = draft.keepDnsNames;
  return { update, error: null };
}
