/**
 * trafficLogic.ts — pure logic of the Traffic Analytics tab.
 *
 * Parsers (server JSON -> view types), German texts per code, number and
 * time formatting, coverage / source display, error mapping, the query
 * builders and the chart data. No React, no DOM, no network: node --test
 * imports it.
 *
 * Hard rules kept here:
 *  - Unknown is never 0 and never green: a missing value is "—" with its
 *    reason. rx and tx are never added up.
 *  - Daily values are UTC days; they are labelled in local time and say so.
 *  - Ids are pseudonyms; every free token shown passes safeText() (MAC ->
 *    [MAC], WLAN netdev names hidden). Server text is never shown: errors
 *    map from status and code.
 *  - The tab only reads; nothing here builds a write.
 */

import { formatBitRate, formatBytes } from '../../utils/format.ts';
import { DASH, POLL_MIN_MS, fmtNum, formatTs, linePath, pollDelay, routerLabel, scrub as scrubWords, shouldFetch } from '../wifi/wifiLogic.ts';
import type {
  AnomalyFamily,
  AnomalyList,
  AnomalyRow,
  AnomalySummary,
  Base,
  CapacityDirection,
  CapacityList,
  CapacityRow,
  ClientList,
  ClientRow,
  CoverageLevel,
  CoverageSummary,
  Finding,
  FlowsView,
  HistoryInfo,
  InterfaceRow,
  Observation,
  Overview,
  PointList,
  PointRow,
  RateRow,
  Recommendations,
  RouterRow,
  Series,
  SeriesBucket,
  SeriesQuery,
  SourceState,
  TalkerList,
  TalkerQuery,
  TalkerRow,
  Tone,
  TrafficStatus,
  Trend,
  VlanList,
  VlanRow,
  WanTotal,
  WindowSummary,
} from './trafficTypes';

export { DASH, POLL_MIN_MS, fmtNum, formatTs, linePath, pollDelay, routerLabel, shouldFetch };

// ── Constants ────────────────────────────────────────────────────────────

export const TAB_ID = 'traffic';
export const TAB_TITLE = 'Traffic Analytics';
/** After Konfiguration (10), Security (20), Diagnose (30) and WiFi (40). */
export const TAB_ORDER = 50;

export type SectionId = 'overview' | 'history' | 'talkers' | 'clients' | 'anomalies' | 'capacity' | 'flows';
export const SECTIONS: readonly { id: SectionId; title: string; adminOnly?: boolean }[] = [
  { id: 'overview', title: 'Übersicht' },
  { id: 'history', title: 'Verlauf' },
  { id: 'talkers', title: 'Top Talkers' },
  { id: 'clients', title: 'Clients & VLANs' },
  { id: 'anomalies', title: 'Anomalien' },
  { id: 'capacity', title: 'Kapazität' },
  { id: 'flows', title: 'Flows', adminOnly: true },
];

export function sectionsFor(admin: boolean): { id: SectionId; title: string }[] {
  return SECTIONS.filter(s => admin || !s.adminOnly);
}

/** Windows of /series (5 min has no series; 90 d needs the standard profile). */
export const SERIES_WINDOWS: readonly string[] = ['1h', '24h', '7d', '30d', '90d'];
export const TALKER_WINDOWS: readonly string[] = ['5m', '1h', '24h', '7d', '30d'];
export const WINDOW_LABEL: Record<string, string> = {
  '5m': '5 Minuten', '1h': '1 Stunde', '24h': '24 Stunden', '7d': '7 Tage', '30d': '30 Tage', '90d': '90 Tage',
};
export const TALKER_KINDS: readonly string[] = ['window', 'current', 'peaks'];
export const TALKER_KIND_LABEL: Record<string, string> = {
  window: 'Datenmenge im Zeitraum', current: 'Aktuelle Rate', peaks: 'Wiederkehrende Spitzen',
};
export const TALKER_SCOPES: readonly string[] = ['client', 'wan', 'port', 'interface', 'vlan'];
export const DIRECTIONS: readonly string[] = ['download', 'upload'];
export const DIRECTION_LABEL: Record<string, string> = {
  download: 'Download', upload: 'Upload', rx: 'Empfangen (rx)', tx: 'Gesendet (tx)',
};
export const TALKER_LIMIT = 20;

export const SCOPE_LABEL: Record<string, string> = {
  client: 'Client', wan: 'WAN', port: 'Port', interface: 'Schnittstelle', vlan: 'VLAN', station: 'WLAN-Station', flow: 'Flow',
};

export const OFF_HINT =
  'Traffic Analytics ist aus. Das Modul ist standardmäßig ausgeschaltet und fragt dann keinen Router ab und liest '
  + 'keinen Verlauf. Ein Schalter dafür ist im Panel noch nicht vorhanden; er folgt in einer späteren Ausbaustufe.';

export const UNKNOWN_RULE = 'Was nicht gemessen wurde, steht als „—“ mit Grund da, nie als 0. Empfangen (rx) und Gesendet (tx) werden nie addiert.';

export const FLOWS_NOTE =
  'Eine leere Liste heißt nicht „kein Verkehr“: Ohne Flow-Quelle sind Verbindungen unbekannt, nicht abwesend.';

// ── Small parse helpers ──────────────────────────────────────────────────

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}
function n(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : [];
}
function objList(v: unknown, max = 500): Obj[] {
  return Array.isArray(v) ? v.slice(0, max).map(obj).filter((x): x is Obj => x !== null) : [];
}
/** {code: count} -> sorted list (counts only, never a text). */
function counts(v: unknown): { code: string; count: number }[] {
  const o = obj(v);
  if (!o) return [];
  return Object.entries(o)
    .filter((e): e is [string, number] => typeof e[1] === 'number' && Number.isFinite(e[1]))
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
}
/** {field: reason} -> list. */
function reasonMap(v: unknown): { field: string; reason: string }[] {
  const o = obj(v);
  if (!o) return [];
  return Object.entries(o)
    .filter((e): e is [string, string] => typeof e[1] === 'string')
    .map(([field, reason]) => ({ field, reason }));
}

const STATUSES: readonly string[] = ['off', 'not_ready', 'ready'];
const COVERAGES: readonly string[] = ['full', 'partial', 'estimated', 'unavailable', 'unknown'];

function status(v: unknown): TrafficStatus | null {
  return typeof v === 'string' && STATUSES.includes(v) ? (v as TrafficStatus) : null;
}
function coverage(v: unknown): CoverageLevel | null {
  return typeof v === 'string' && COVERAGES.includes(v) ? (v as CoverageLevel) : null;
}
function dirCounter(v: unknown): 'rx' | 'tx' | null {
  return v === 'rx' || v === 'tx' ? v : null;
}

function base(o: Obj | null): Base {
  return { status: status(o?.status), reasons: strList(o?.reasons), generatedAt: n(o?.generated_at) };
}

function source(o: Obj | null, nameKey = 'module'): SourceState {
  return {
    name: str(o?.[nameKey]) ?? str(o?.source) ?? str(o?.module) ?? '',
    state: str(o?.state) ?? str(o?.coverage),
    reason: str(o?.reason),
  };
}

// ── Parsers ──────────────────────────────────────────────────────────────

function parseRate(o: Obj): RateRow {
  const d = obj(o.direction);
  return {
    pointId: str(o.point_id) ?? '',
    routerId: str(o.router_id),
    scope: str(o.scope) ?? '',
    device: str(o.device),
    vlanId: n(o.vlan_id),
    rxBps: n(o.rx_bps),
    txBps: n(o.tx_bps),
    downBps: n(o.down_bps),
    upBps: n(o.up_bps),
    directionReason: str(d?.reason),
    quality: str(o.quality),
    coverage: coverage(o.coverage),
    coverageReason: str(o.coverage_reason),
    wallS: n(o.wall_s),
  };
}

function parseInterface(o: Obj): InterfaceRow {
  return {
    ...parseRate(o),
    linkMbps: n(o.link_mbps),
    duplex: str(o.duplex),
    utilizationPct: n(o.utilization_pct),
    utilizationReason: str(o.utilization_reason),
  };
}

function parseCoverage(o: Obj | null): CoverageSummary | null {
  if (!o) return null;
  return {
    points: n(o.points), full: n(o.full), partial: n(o.partial), estimated: n(o.estimated),
    unavailable: n(o.unavailable), unknown: n(o.unknown), fullShare: n(o.full_share), reasons: counts(o.reasons),
  };
}

function parseWanTotal(o: Obj | null): WanTotal | null {
  if (!o) return null;
  return {
    rxBps: n(o.rx_bps), txBps: n(o.tx_bps), coverage: coverage(o.coverage), reasons: strList(o.coverage_reasons),
    contributing: n(o.contributing), omitted: n(o.omitted), routers: n(o.routers), refused: str(o.refused),
  };
}

export function parseWindow(o: Obj): WindowSummary {
  return {
    pointId: str(o.point_id) ?? str(obj(o.point)?.point_id) ?? '',
    routerId: str(o.router_id),
    scope: str(o.scope),
    state: str(o.state),
    reason: str(o.reason),
    rxBytes: n(o.rx_bytes),
    txBytes: n(o.tx_bytes),
    avgRxBps: n(o.avg_rx_bps),
    avgTxBps: n(o.avg_tx_bps),
    peakRxBps: n(o.peak_rx_bps),
    peakTxBps: n(o.peak_tx_bps),
    download: dirCounter(o.download),
    upload: dirCounter(o.upload),
    timeCoverage: n(o.time_coverage),
    coverage: coverage(o.coverage),
    reasons: o.window_reasons !== undefined ? strList(o.window_reasons) : strList(o.reasons),
  };
}

function parseTalkerRow(o: Obj): TalkerRow {
  return {
    rank: n(o.rank),
    pointId: str(o.point_id) ?? '',
    scope: str(o.scope) ?? '',
    routerId: str(o.router_id),
    clientRef: str(o.client_ref),
    device: str(o.device),
    vlanId: n(o.vlan_id),
    counter: str(o.counter),
    value: n(o.value),
    observedBytes: n(o.observed_bytes),
    peakBps: n(o.peak_bps),
    measuringArea: str(o.measuring_area),
    coverage: coverage(o.coverage),
    coverageReasons: strList(o.coverage_reasons),
    timeCoverage: n(o.time_coverage),
    sharePct: n(o.share_pct),
    shareReason: str(o.share_reason),
    lastActive: n(o.last_active),
  };
}

export function parseTalkers(v: unknown): TalkerList {
  const o = obj(v);
  return {
    ...base(o),
    kind: str(o?.kind),
    scope: str(o?.scope),
    window: str(o?.window),
    direction: str(o?.direction),
    metric: str(o?.metric),
    state: str(o?.state),
    reason: str(o?.reason),
    partial: o?.partial !== false,
    partialReasons: strList(o?.partial_reasons),
    rows: objList(o?.rows, 50).map(parseTalkerRow),
    considered: n(o?.considered),
    omitted: counts(o?.omitted),
  };
}

function parseFamilies(v: unknown): AnomalyFamily[] {
  const o = obj(v);
  if (!o) return [];
  return Object.entries(o).map(([family, raw]) => {
    const f = obj(raw);
    return { family, state: str(f?.state), reason: str(f?.reason) };
  });
}

function parseAnomalySummary(o: Obj | null): AnomalySummary | null {
  if (!o) return null;
  return { open: n(o.open), ended: n(o.ended), suppressed: n(o.suppressed), families: parseFamilies(o.families) };
}

function parseVlan(o: Obj): VlanRow {
  return {
    routerId: str(o.router_id),
    vlanId: n(o.vlan_id),
    measured: Array.isArray(o.measured) ? o.measured.length : 0,
    rxBps: n(o.rx_bps),
    txBps: n(o.tx_bps),
    rxBytes: n(o.rx_bytes),
    txBytes: n(o.tx_bytes),
    coverage: coverage(o.coverage),
    coverageReasons: strList(o.coverage_reasons),
    directionReason: str(obj(o.direction)?.reason),
    configuredPorts: Array.isArray(o.configured_ports) ? o.configured_ports.length : 0,
    interVlan: source(obj(o.inter_vlan)),
    wanRelated: source(obj(o.wan_related)),
    activeClients: n(o.active_clients),
    activeClientsBasis: str(o.active_clients_basis),
    unavailable: reasonMap(o.unavailable),
  };
}

function parseRouter(o: Obj): RouterRow | null {
  const id = str(o.router_id);
  if (!id) return null;
  return { routerId: id, devices: n(o.devices), stations: n(o.stations), conntrackCount: n(o.conntrack_count) };
}

function parseHistory(o: Obj | null): HistoryInfo | null {
  if (!o) return null;
  return { profile: str(o.profile), fineBytes: n(o.fine_bytes), coarseBytes: n(o.coarse_bytes), dayBoundary: str(o.day_boundary) };
}

export function parseOverview(v: unknown): Overview {
  const o = obj(v);
  const talkers = obj(o?.talkers_top);
  return {
    ...base(o),
    coverage: parseCoverage(obj(o?.coverage)),
    wan: objList(o?.wan).map(parseRate),
    wanTotal: parseWanTotal(obj(o?.wan_total)),
    wan24h: objList(o?.wan_24h).map(parseWindow),
    talkersTop: talkers ? parseTalkers(talkers) : null,
    anomalies: parseAnomalySummary(obj(o?.anomalies)),
    interfaces: objList(o?.interfaces, 16).map(parseInterface),
    vlans: objList(o?.vlans, 64).map(parseVlan),
    flowSources: objList(o?.flow_sources).map(s => source(s, 'source')),
    correlationSources: objList(o?.correlation_sources).map(s => source(s)),
    routers: objList(o?.routers).map(parseRouter).filter((r): r is RouterRow => r !== null),
    drops: counts(o?.drops).filter(d => d.count > 0),
    history: parseHistory(obj(o?.history)),
  };
}

export function parsePoints(v: unknown): PointList {
  const o = obj(v);
  const points: PointRow[] = objList(o?.points).map(p => ({
    pointId: str(p.point_id) ?? '',
    routerId: str(p.router_id),
    scope: str(p.scope) ?? '',
    device: str(p.device),
    vlanId: n(p.vlan_id),
    coverage: coverage(p.coverage),
    quality: str(p.quality),
    lastSeen: n(p.last_seen),
  })).filter(p => isPointId(p.pointId));
  return { ...base(o), points, total: n(o?.total), truncated: o?.truncated === true };
}

function parseBucket(o: Obj): SeriesBucket | null {
  const ts = n(o.ts);
  if (ts === null) return null;
  return {
    ts, rxBytes: n(o.rx_bytes), txBytes: n(o.tx_bytes), rxPeakBps: n(o.rx_peak_bps), txPeakBps: n(o.tx_peak_bps),
    coverage: n(o.coverage),
  };
}

export function parseSeries(v: unknown): Series {
  const o = obj(v);
  const available = o !== null && Array.isArray(o.buckets) && str(o.state) === 'available';
  return {
    ...base(o),
    pointId: str(o?.point_id),
    window: str(o?.window),
    state: str(o?.state),
    reason: str(o?.reason),
    windowReasons: strList(o?.window_reasons),
    resolutionS: n(o?.resolution_s),
    summary: available && o ? parseWindow(o) : null,
    utcDays: o?.utc_days === true,
    buckets: objList(o?.buckets, 500).map(parseBucket).filter((b): b is SeriesBucket => b !== null),
  };
}

function parseClient(o: Obj): ClientRow {
  return {
    clientRef: str(o.client_ref) ?? '',
    link: str(o.link),
    identity: str(o.identity),
    routerId: str(o.router_id),
    locationSource: str(o.location_source),
    downBps: n(o.down_bps),
    upBps: n(o.up_bps),
    downBytes: n(o.down_bytes),
    upBytes: n(o.up_bytes),
    coveredS: n(o.covered_s),
    vlanId: n(o.vlan_id),
    coverage: coverage(o.coverage),
    coverageReasons: strList(o.coverage_reasons),
    wanAttribution: source(obj(o.wan_attribution)),
    roamingGaps: n(o.roaming_gaps),
    interruptions: n(o.interruptions),
    lastSeen: n(o.last_seen_wall),
    unavailable: reasonMap(o.unavailable),
  };
}

export function parseClients(v: unknown): ClientList {
  const o = obj(v);
  return {
    ...base(o),
    clients: objList(o?.clients, 200).map(parseClient).filter(c => c.clientRef !== ''),
    total: n(o?.total),
    truncated: o?.truncated === true,
  };
}

export function parseVlans(v: unknown): VlanList {
  const o = obj(v);
  return { ...base(o), vlans: objList(o?.vlans, 64).map(parseVlan) };
}

function parseDirection(o: Obj): CapacityDirection {
  return {
    counter: str(o.counter) ?? '',
    meaning: str(o.meaning),
    avgBps: n(o.avg_bps), peakBps: n(o.peak_bps), p95Bps: n(o.p95_bps),
    avgPct: n(o.avg_pct), peakPct: n(o.peak_pct), p95Pct: n(o.p95_pct),
    unavailable: reasonMap(o.unavailable),
  };
}

function parseTrend(o: Obj | null): Trend | null {
  if (!o) return null;
  return {
    state: str(o.state), reason: str(o.reason), basisDays: n(o.basis_days), slopePctPerWeek: n(o.slope_pct_per_week),
    daysToNearCapacity: n(o.days_to_near_capacity), daysReason: str(o.days_to_near_capacity_reason), confidence: n(o.confidence),
  };
}

function parseCapacityRow(o: Obj): CapacityRow {
  return {
    pointId: str(o.point_id) ?? '',
    scope: str(o.scope) ?? '',
    routerId: str(o.router_id),
    device: str(o.device),
    vlanId: n(o.vlan_id),
    linkMbps: n(o.link_mbps),
    duplex: str(o.duplex),
    uplink: typeof o.uplink === 'boolean' ? o.uplink : null,
    windowS: n(o.window_s),
    timeCoverage: n(o.time_coverage),
    p95Estimated: o.p95_estimated === true,
    directions: objList(o.directions, 4).map(parseDirection),
    sharedP95Pct: n(o.shared_p95_pct),
    nearCapacityDays: n(o.near_capacity_days),
    state: str(o.state),
    reasons: strList(o.reasons),
    trend: parseTrend(obj(o.trend)),
  };
}

export function parseCapacity(v: unknown): CapacityList {
  const o = obj(v);
  return { ...base(o), rows: objList(o?.rows).map(parseCapacityRow) };
}

function parseObservation(o: Obj): Observation {
  return {
    indicator: str(o.indicator) ?? '', family: str(o.family), elevated: o.elevated === true,
    value: n(o.value), unit: str(o.unit), threshold: n(o.threshold),
  };
}

function parseFinding(o: Obj): Finding {
  return {
    findingId: str(o.finding_id) ?? '',
    routerId: str(o.router_id),
    pointId: str(o.point_id),
    scope: str(o.scope),
    assessment: str(o.assessment) ?? '',
    observations: objList(o.observations, 20).map(parseObservation),
    possibleCauses: strList(o.possible_causes),
    recommendations: strList(o.recommendations),
    recommendationWithheld: str(o.recommendation_withheld),
    confidence: n(o.confidence),
    unmeasured: reasonMap(o.unmeasured),
    windowS: n(o.window_s),
    start: n(o.start),
    end: n(o.end),
  };
}

export function parseRecommendations(v: unknown): Recommendations {
  const o = obj(v);
  return {
    ...base(o),
    verdict: str(o?.verdict),
    findings: objList(o?.findings, 100).map(parseFinding),
    sources: objList(o?.sources).map(s => source(s)),
    pointsEvaluated: n(o?.points_evaluated),
    pointsInsufficient: n(o?.points_insufficient),
  };
}

function parseAnomaly(o: Obj): AnomalyRow {
  return {
    candidateId: str(o.candidate_id) ?? '',
    pointId: str(o.point_id),
    routerId: str(o.router_id),
    clientRef: str(o.client_ref),
    kind: str(o.kind) ?? '',
    observed: n(o.observed),
    baselineMedian: n(o.baseline_median),
    threshold: n(o.threshold),
    windowS: n(o.window_s),
    confidence: n(o.confidence),
    coverage: coverage(o.coverage),
    started: n(o.started),
    lastSeen: n(o.last_seen),
    state: str(o.state),
    suppressedReason: str(o.suppressed_reason),
  };
}

export function parseAnomalies(v: unknown): AnomalyList {
  const o = obj(v);
  return {
    ...base(o),
    rows: objList(o?.rows, 100).map(parseAnomaly),
    total: n(o?.total),
    families: parseFamilies(o?.families),
    incidentEngine: source(obj(o?.incident_engine)),
  };
}

export function parseFlows(v: unknown): FlowsView {
  const o = obj(v);
  return {
    ...base(o),
    source: source(obj(o?.source), 'source'),
    notes: strList(o?.notes),
    sources: objList(o?.sources).map(s => source(s, 'source')),
  };
}

// ── Safe text, labels ────────────────────────────────────────────────────

const MAC_ANY_RE = /[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}/gi;
const MAC_DOTTED_RE = /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/gi;

/** MACs masked as [MAC], also inside a token (WiFi's scrub needs word boundaries). */
export function scrub(text: string): string {
  return scrubWords(text).replace(MAC_ANY_RE, '[MAC]').replace(MAC_DOTTED_RE, '[MAC]');
}

const WLAN_NETDEV_RE = /^(phy\d+-(ap|sta|mesh)\d+|wlan\d+(-\d+)?|ath\d+)$/i;

/** A device / port name as shown: MACs masked, WLAN netdev names hidden. */
export function safeText(text: string | null | undefined): string | null {
  if (!text) return null;
  if (WLAN_NETDEV_RE.test(text)) return 'WLAN-Schnittstelle';
  return scrub(text);
}

export function clientLabel(ref: string | null | undefined): string {
  if (!ref) return 'Client';
  const m = /^cli_([0-9a-f]{6})/.exec(ref);
  return m ? `Client ${m[1]}` : 'Client';
}

export function routerName(id: string | null | undefined): string {
  return id ? routerLabel(id) : 'Router unbekannt';
}

export function scopeLabel(scope: string | null | undefined): string {
  return scope ? SCOPE_LABEL[scope] ?? scrub(scope) : 'Messpunkt';
}

/** "WAN wan", "Port lan1 · VLAN 20", "Client 1a2b3c". */
export function pointLabel(p: { scope: string | null; device: string | null; vlanId: number | null; clientRef?: string | null }): string {
  if (p.scope === 'client' || p.scope === 'station') return clientLabel(p.clientRef ?? null);
  const parts = [scopeLabel(p.scope)];
  const dev = safeText(p.device);
  if (dev && p.scope !== 'vlan') parts.push(dev);
  if (p.vlanId !== null) parts.push(p.scope === 'vlan' ? String(p.vlanId) : `· VLAN ${p.vlanId}`);
  return parts.join(' ');
}

// ── Reason texts ─────────────────────────────────────────────────────────

export const REASON_TEXT: Record<string, string> = {
  disabled: 'Modul ausgeschaltet',
  core_missing: 'Enterprise Core läuft nicht',
  module_key_missing: 'Schlüssel des Moduls fehlt',
  hw_offload_unknown: 'Hardware-Offload unbekannt: am Prozessor vorbeigeleiteter Verkehr fehlt evtl.',
  hw_offload_on: 'Hardware-Offload aktiv: ein Teil des Verkehrs wird nicht gezählt',
  station_counters_only: 'nur WLAN-Stationszähler des Access Points',
  roaming_gap: 'Lücke durch Roaming',
  no_wired_client_source: 'keine Quelle für kabelgebundene Clients',
  needs_flow_source: 'braucht eine Flow-Quelle (nicht vorhanden)',
  source_disabled: 'Quelle ausgeschaltet',
  module_missing: 'Modul nicht geladen',
  module_not_loaded: 'Modul nicht geladen',
  module_disabled: 'Modul ausgeschaltet',
  interface_mismatch: 'Schnittstellen passen nicht zusammen',
  not_connected: 'nicht angebunden',
  not_ready: 'noch nicht bereit',
  security_center_has_no_traffic_indicator_intake: 'Security Center nimmt noch keine Verkehrsindikatoren an',
  net_engine_has_no_candidate_api: 'Incident Engine hat noch keine Schnittstelle für Kandidaten',
  collector_interface_not_built: 'Collector-Schnittstelle noch nicht gebaut',
  not_offered_unbounded: 'nicht angeboten (unbegrenzte Tabelle)',
  count_file_not_seen: 'Zähldatei nicht gefunden',
  count_only_no_flows: 'nur Anzahl, keine Verbindungen',
  conntrack_source_not_count_file: 'keine Conntrack-Zähldatei',
  link_speed_unknown: 'Link-Geschwindigkeit unbekannt',
  no_rate_yet: 'noch keine Rate',
  no_data: 'keine Daten',
  no_data_yet: 'noch keine Daten',
  no_data_for_window: 'keine Daten in diesem Zeitraum',
  history_shorter_than_window: 'Verlauf kürzer als der Zeitraum',
  time_coverage_incomplete: 'Zeitraum nicht vollständig abgedeckt',
  window_beyond_retention: 'Zeitraum länger als die Aufbewahrung',
  unknown_point: 'Messpunkt unbekannt',
  unknown_window: 'Zeitraum unbekannt',
  insufficient_data: 'zu wenige Daten',
  p95_from_coarse_buckets: 'P95 aus groben Intervallen (Schätzung)',
  trend_series_too_short: 'Verlauf für einen Trend zu kurz',
  trend_series_low_coverage: 'Verlauf für einen Trend zu lückenhaft',
  trend_not_rising: 'kein steigender Trend',
  beyond_forecast_horizon: 'jenseits des Schätzhorizonts',
  bridged_traffic_not_counted: 'gebrückter Verkehr: Download/Upload nicht zuzuordnen',
  unknown_direction: 'Richtung unbekannt',
  direction_missing: 'Richtung fehlt',
  rx_tx_never_combined: 'rx und tx werden nie addiert',
  scope_not_ranked: 'dieser Bereich wird nicht gereiht',
  share_reference_zero: 'Bezugsgröße ist 0',
  share_reference_not_fully_covered: 'Bezugsgröße nicht vollständig erfasst',
  port_is_uplink_of_counted_router: 'Port ist Uplink eines gezählten Routers',
  port_vlan_unknown: 'VLAN des Ports unbekannt',
  port_vlan_ambiguous: 'Port in mehreren VLANs',
  no_location: 'Standort unbekannt',
  no_wifi_vlan_mapping: 'keine Zuordnung WLAN → VLAN',
  no_client_vlan_source: 'keine Quelle für VLAN der Clients',
  vlan_not_configured: 'VLAN nicht konfiguriert',
  no_vlan_netdev: 'keine VLAN-Schnittstelle',
  no_fleet_vlan_total: 'keine flottenweite VLAN-Summe',
  wan_same_router: 'nur am selben Router',
  mac_only: 'nur über die MAC erkannt',
  registry: 'im Geräteregister',
  registry_missing: 'nicht im Geräteregister',
  unconfirmed: 'nicht bestätigt',
  no_reference_window: 'kein Vergleichszeitraum',
  too_few_samples: 'zu wenige Messwerte',
  single_indicator_only: 'nur ein Hinweis: keine Empfehlung',
  high_bandwidth_alone_proves_no_bottleneck: 'hohe Bandbreite allein ist kein Engpass',
  network_intelligence_rule: 'durch Network Intelligence abgedeckt',
  snapshot_is_not_flow_history: 'Momentaufnahme ist kein Flow-Verlauf',
  empty_is_not_no_traffic: 'leer heißt nicht „kein Verkehr“',
  invisible_is_unknown: 'Unsichtbares ist unbekannt',
  unknown_evidence: 'Beleg unbekannt',
  points_dropped_by_quota: 'Messpunkte wegen Obergrenze verworfen',
  ssh_fallback: 'Router über SSH-Ersatzweg abgefragt',
  router_busy: 'Router ausgelastet',
  paused: 'pausiert',
  throttled: 'gedrosselt',
  station_counters: 'WLAN-Stationszähler',
  source_missing: 'Quelle fehlt',
  interface_counters: 'Schnittstellenzähler',
  bridge_fdb: 'Bridge-Tabelle (FDB)',
  wlan_traffic_at_ap: 'WLAN-Verkehr am Access Point',
  interface_plus_vlan: 'Schnittstelle und VLAN',
  station_plus_port: 'Station und Port',
  client_plus_wan: 'Client und WAN',
  bridge_plus_ports: 'Bridge und Ports',
  wired: 'kabelgebunden',
  wifi: 'WLAN',
  dsa_port_counters_unverified: 'Portzähler (DSA) nicht geprüft',
  sysfs_fallback: 'Ersatzquelle sysfs',
  half_duplex_rx_tx_share_the_link: 'Halbduplex: rx und tx teilen sich den Link',
};

/** German text of a reason code; an unknown code is shown as a code, scrubbed. */
export function reasonText(code: string | null | undefined): string {
  if (!code) return 'ohne Angabe';
  const known = REASON_TEXT[code];
  if (known) return known;
  const prefix = code.split(':')[0];
  if (REASON_TEXT[prefix]) return REASON_TEXT[prefix];
  return `Code ${scrub(code)}`;
}

export function reasonsText(codes: readonly string[]): string {
  return codes.length ? codes.map(reasonText).join(' · ') : '';
}

// ── Status, coverage, sources ────────────────────────────────────────────

export interface Shown {
  label: string;
  tone: Tone;
}

export function statusView(s: TrafficStatus | null, reasons: readonly string[]): Shown & { hint: string | null } {
  switch (s) {
    case 'ready': return { label: 'Bereit', tone: 'ok', hint: null };
    case 'not_ready': return { label: 'Eingeschränkt', tone: 'warn', hint: reasonsText(reasons) || null };
    case 'off': return { label: 'Aus', tone: 'muted', hint: null };
    default: return { label: 'Unbekannt', tone: 'muted', hint: null };
  }
}

export const COVERAGE_VIEW: Record<CoverageLevel, Shown> = {
  full: { label: 'vollständig', tone: 'ok' },
  partial: { label: 'teilweise', tone: 'info' },
  estimated: { label: 'geschätzt', tone: 'warn' },
  unavailable: { label: 'nicht verfügbar', tone: 'muted' },
  unknown: { label: 'unbekannt', tone: 'muted' },
};

export function coverageView(c: CoverageLevel | null | undefined): Shown {
  return c ? COVERAGE_VIEW[c] : COVERAGE_VIEW.unknown;
}

const SOURCE_STATE: Record<string, Shown> = {
  ready: { label: 'bereit', tone: 'ok' },
  active: { label: 'aktiv', tone: 'ok' },
  available: { label: 'verfügbar', tone: 'ok' },
  full: { label: 'vollständig', tone: 'ok' },
  partial: { label: 'teilweise', tone: 'info' },
  covered_by_network_intelligence: { label: 'über Network Intelligence', tone: 'info' },
  covered_by_other_module: { label: 'über anderes Modul', tone: 'info' },
  learning: { label: 'lernt noch', tone: 'info' },
  not_ready: { label: 'nicht bereit', tone: 'warn' },
  interface_mismatch: { label: 'Schnittstellen passen nicht', tone: 'warn' },
  module_disabled: { label: 'ausgeschaltet', tone: 'muted' },
  module_missing: { label: 'nicht geladen', tone: 'muted' },
  not_connected: { label: 'nicht angebunden', tone: 'muted' },
  unavailable: { label: 'nicht verfügbar', tone: 'muted' },
  disabled: { label: 'ausgeschaltet', tone: 'muted' },
};

export function sourceStateView(state: string | null | undefined): Shown {
  return (state && SOURCE_STATE[state]) || { label: state ? reasonText(state) : 'unbekannt', tone: 'muted' };
}

export const SOURCE_NAME: Record<string, string> = {
  traffic_analytics: 'Traffic Analytics',
  net_diagnostics: 'Netzwerkdiagnose',
  wifi_rf: 'WiFi Intelligence',
  security_center: 'Security Center',
  network_intelligence: 'Network Intelligence',
  incident_engine: 'Incident Engine',
  collector: 'Flow-Collector',
  conntrack_snapshot: 'Conntrack-Momentaufnahme',
  conntrack_count: 'Conntrack-Anzahl',
};

export function sourceName(name: string): string {
  return SOURCE_NAME[name] ?? scrub(name);
}

// ── Numbers and time (unknown is a dash, never 0) ────────────────────────

export function fmtRate(bps: number | null | undefined): string {
  return formatBitRate(bps);
}
export function fmtBytes(bytes: number | null | undefined): string {
  return formatBytes(bytes);
}
export function fmtPct(v: number | null | undefined, digits = 1): string {
  return v == null || !Number.isFinite(v) ? DASH : `${fmtNum(v, digits)} %`;
}
/** A 0..1 share as whole percent. */
export function fmtShare(v: number | null | undefined): string {
  return v == null || !Number.isFinite(v) ? DASH : `${fmtNum(v * 100, 0)} %`;
}
export function fmtCount(v: number | null | undefined): string {
  return v == null || !Number.isFinite(v) ? DASH : fmtNum(v, 0);
}

/** "—" plus the reason, for a value that is not known. */
export function unknownText(reason: string | null | undefined): string {
  return reason ? `${DASH} ${reasonText(reason)}` : DASH;
}

/** Download / upload of a rate row, or rx / tx when the direction is not nameable. */
export function rateParts(r: RateRow): { name: string; text: string; known: boolean }[] {
  if (r.downBps !== null || r.upBps !== null || r.directionReason === null) {
    return [
      { name: 'Download', text: fmtRate(r.downBps), known: r.downBps !== null },
      { name: 'Upload', text: fmtRate(r.upBps), known: r.upBps !== null },
    ];
  }
  return [
    { name: 'Empfangen (rx)', text: fmtRate(r.rxBps), known: r.rxBps !== null },
    { name: 'Gesendet (tx)', text: fmtRate(r.txBps), known: r.txBps !== null },
  ];
}

/** Value of a talker row in its metric's unit. */
export function talkerValue(metric: string | null, v: number | null): string {
  if (v === null) return DASH;
  if (metric === 'bps') return fmtRate(v);
  if (metric === 'episodes' || metric === 'peak_episodes') return `${fmtNum(v, 0)} Spitzen`;
  return fmtBytes(v);
}

/** Bucket start in local time. A UTC day is named by its local date and says so. */
export function bucketLabel(ts: number, utcDays: boolean): string {
  if (!Number.isFinite(ts) || ts <= 0) return DASH;
  if (!utcDays) return formatTs(ts);
  const d = new Date(ts * 1000);
  const day = d.toLocaleDateString('de-DE', { timeZone: 'UTC', day: '2-digit', month: '2-digit', year: 'numeric' });
  return `${day} (UTC-Tag, ab ${d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })} Ortszeit)`;
}

/** The fixed note under every view with daily values. */
export function utcDayNote(sampleTs?: number | null): string {
  const ts = sampleTs != null && Number.isFinite(sampleTs) && sampleTs > 0 ? sampleTs : 86400 * 20000;
  const midnight = Math.floor(ts / 86400) * 86400;
  const local = new Date(midnight * 1000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  return `Tageswerte sind UTC-Tage (00:00–24:00 UTC). In Ortszeit beginnt ein solcher Tag um ${local} Uhr; Zeiten stehen in Ortszeit.`;
}

export function durationText(s: number | null | undefined): string {
  if (s == null || !Number.isFinite(s) || s < 0) return DASH;
  if (s >= 86400) return `${fmtNum(s / 86400, s % 86400 ? 1 : 0)} Tage`;
  if (s >= 3600) return `${fmtNum(s / 3600, s % 3600 ? 1 : 0)} Std.`;
  if (s >= 60) return `${fmtNum(s / 60, 0)} Min.`;
  return `${fmtNum(s, 0)} s`;
}

// ── Chart data ───────────────────────────────────────────────────────────

export interface SeriesChart {
  label: string;
  /** Bytes per bucket; null is a gap (never drawn as 0). */
  points: { ts: number; mean: number | null }[];
  known: number;
  max: number | null;
}

/** Download and upload volume per bucket (bytes, never added up); rx/tx when unnamed. */
export function seriesCharts(s: Series): SeriesChart[] {
  const dl = s.summary?.download ?? null;
  const ul = s.summary?.upload ?? null;
  const lines: { label: string; counter: 'rx' | 'tx' }[] = dl && ul
    ? [{ label: 'Download', counter: dl }, { label: 'Upload', counter: ul }]
    : [{ label: 'Empfangen (rx)', counter: 'rx' }, { label: 'Gesendet (tx)', counter: 'tx' }];
  return lines.map(({ label, counter }) => {
    const points = s.buckets.map(b => ({ ts: b.ts, mean: counter === 'rx' ? b.rxBytes : b.txBytes }));
    const known = points.filter(p => p.mean !== null).map(p => p.mean as number);
    return { label, points, known: known.length, max: known.length ? Math.max(...known) : null };
  });
}

/** Window summary as named facts (download/upload, or rx/tx when unnamed). */
export function windowFacts(w: WindowSummary): { name: string; text: string; known: boolean }[] {
  const pick = (c: 'rx' | 'tx' | null, rx: number | null, tx: number | null) => (c === 'rx' ? rx : c === 'tx' ? tx : null);
  const named = w.download !== null && w.upload !== null;
  const rows = named
    ? [
      ['Download gesamt', fmtBytes(pick(w.download, w.rxBytes, w.txBytes))],
      ['Upload gesamt', fmtBytes(pick(w.upload, w.rxBytes, w.txBytes))],
      ['Download Ø', fmtRate(pick(w.download, w.avgRxBps, w.avgTxBps))],
      ['Upload Ø', fmtRate(pick(w.upload, w.avgRxBps, w.avgTxBps))],
      ['Download Spitze', fmtRate(pick(w.download, w.peakRxBps, w.peakTxBps))],
      ['Upload Spitze', fmtRate(pick(w.upload, w.peakRxBps, w.peakTxBps))],
    ]
    : [
      ['Empfangen (rx) gesamt', fmtBytes(w.rxBytes)],
      ['Gesendet (tx) gesamt', fmtBytes(w.txBytes)],
      ['Empfangen (rx) Spitze', fmtRate(w.peakRxBps)],
      ['Gesendet (tx) Spitze', fmtRate(w.peakTxBps)],
    ];
  return rows.map(([name, text]) => ({ name, text, known: text !== DASH }));
}

// ── Anomalies, findings, capacity ────────────────────────────────────────

const KIND_SUFFIX: [string, string][] = [
  ['_night_activity', 'Nachtaktivität'],
  ['_sustained_high', 'dauerhaft hoch'],
  ['_spike', 'Spitze'],
  ['_drop', 'plötzlicher Abfall'],
  ['_bursts', 'wiederholte Spitzen'],
  ['_volume', 'ungewöhnliche Datenmenge'],
];

export function anomalyKindText(kind: string): string {
  for (const [suffix, text] of KIND_SUFFIX) {
    if (kind.endsWith(suffix)) {
      const dir = kind.slice(0, -suffix.length);
      const d = DIRECTION_LABEL[dir];
      return d ? `${d}: ${text}` : text;
    }
  }
  return `Code ${scrub(kind)}`;
}

export const FAMILY_LABEL: Record<string, string> = {
  spikes: 'Spitzen', sustained_high: 'Dauerlast', sudden_drop: 'Plötzlicher Abfall', night_activity: 'Nachtaktivität',
  repeated_bursts: 'Wiederholte Spitzen', client_volume: 'Datenmenge je Client', connection_rate: 'Verbindungsrate',
  communication_pattern: 'Kommunikationsmuster', inter_vlan: 'Verkehr zwischen VLANs', port_load: 'Portlast',
  port_errors: 'Portfehler', incident_engine: 'Incident Engine',
};

export const ANOMALY_STATE: Record<string, Shown> = {
  open: { label: 'offen', tone: 'warn' },
  ended: { label: 'beendet', tone: 'info' },
  suppressed: { label: 'unterdrückt', tone: 'muted' },
};

export function anomalyStateView(s: string | null): Shown {
  return (s && ANOMALY_STATE[s]) || { label: 'unbekannt', tone: 'muted' };
}

export const ASSESSMENT_TEXT: Record<string, Shown> = {
  high_utilization_observed: { label: 'Hohe Auslastung beobachtet', tone: 'info' },
  possible_bottleneck: { label: 'Möglicher Engpass', tone: 'warn' },
  possible_uplink_bottleneck: { label: 'Möglicher Engpass am Uplink', tone: 'warn' },
  possible_link_quality_issue: { label: 'Mögliches Problem der Leitungsqualität', tone: 'warn' },
  possible_wifi_congestion: { label: 'Mögliche WLAN-Überlastung', tone: 'warn' },
  wifi_rf_indicator_observed: { label: 'WLAN-Hinweis beobachtet', tone: 'info' },
};

export function assessmentView(a: string): Shown {
  return ASSESSMENT_TEXT[a] ?? { label: `Code ${scrub(a)}`, tone: 'info' };
}

export const VERDICT_TEXT: Record<string, Shown> = {
  findings_present: { label: 'Mögliche Engpässe gefunden', tone: 'warn' },
  nothing_detected_in_covered_data: { label: 'In den erfassten Daten nichts gefunden', tone: 'ok' },
  insufficient_data: { label: 'Zu wenige Daten für eine Aussage', tone: 'muted' },
};

export const CAUSE_TEXT: Record<string, string> = {
  upstream_congestion: 'Überlastung vor dem Router (Anbieter / Gegenstelle)',
  upstream_or_isp_issue: 'Störung beim Anbieter oder der Leitung',
  unstable_link_or_upstream: 'instabile Verbindung oder Gegenstelle',
  cable_or_port_fault: 'Kabel- oder Portfehler',
  queue_overflow: 'Warteschlange läuft über',
  interface_drops: 'verworfene Pakete an der Schnittstelle',
  interface_errors: 'Fehler an der Schnittstelle',
  airtime_saturation: 'Funkzeit ausgeschöpft',
  interference_or_weak_clients: 'Störungen oder schwache Clients',
};

export const RECOMMENDATION_TEXT: Record<string, string> = {
  check_wan_capacity: 'WAN-Bandbreite prüfen (Tarif, Leitung)',
  check_link_capacity: 'Kapazität der Verbindung prüfen',
  check_sqm_configuration: 'SQM / Warteschlangen-Einstellungen prüfen',
  check_upstream_line: 'Leitung beim Anbieter prüfen lassen',
  check_cabling_and_port: 'Kabel und Port prüfen',
  check_channel_plan_and_airtime: 'Kanalplan und Funkzeit prüfen (WiFi Intelligence)',
  add_measuring_points: 'Weitere Messpunkte einschalten',
};

export const INDICATOR_TEXT: Record<string, string> = {
  utilization_high: 'Auslastung hoch',
  link_down_observed: 'Link-Ausfall beobachtet',
  router_restart: 'Neustart des Routers',
  connectivity_incident: 'Verbindungsstörung',
  latency_elevated: 'Latenz erhöht',
  packet_loss: 'Paketverlust',
  airtime_high: 'Funkzeit hoch',
  retransmissions_high: 'Wiederholungen hoch',
};

export function codeText(map: Record<string, string>, code: string): string {
  return map[code] ?? `Code ${scrub(code)}`;
}

export const CAPACITY_STATE: Record<string, Shown> = {
  ok: { label: 'ausreichend', tone: 'ok' },
  headroom: { label: 'Reserve vorhanden', tone: 'ok' },
  approaching_capacity: { label: 'nähert sich der Kapazität', tone: 'warn' },
  possible_bottleneck: { label: 'möglicher Engpass', tone: 'warn' },
  possible_uplink_bottleneck: { label: 'möglicher Engpass am Uplink', tone: 'warn' },
  insufficient_data: { label: 'zu wenige Daten', tone: 'muted' },
  no_link_speed: { label: 'Link-Geschwindigkeit unbekannt', tone: 'muted' },
};

export function capacityStateView(s: string | null): Shown {
  return (s && CAPACITY_STATE[s]) || { label: s ? reasonText(s) : 'unbekannt', tone: 'muted' };
}

export function trendText(t: Trend | null): string {
  if (!t) return DASH;
  if (t.state !== 'estimated') return unknownText(t.reason ?? t.state);
  const slope = t.slopePctPerWeek === null ? DASH : `${t.slopePctPerWeek > 0 ? '+' : ''}${fmtNum(t.slopePctPerWeek, 1)} %-Punkte je Woche`;
  const days = t.daysToNearCapacity === null
    ? (t.daysReason ? ` · ${reasonText(t.daysReason)}` : '')
    : ` · Kapazitätsnähe in etwa ${fmtNum(t.daysToNearCapacity, 0)} Tagen (Schätzung)`;
  return `${slope}${days}`;
}

// ── Errors ───────────────────────────────────────────────────────────────

/** A failed request: status and code only, never the server message. */
export class TrafficApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly details: { field?: string; reason?: string };

  constructor(status: number | null, code: string, details: { field?: string; reason?: string } = {}) {
    super(`traffic api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'TrafficApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type ErrorKind = 'forbidden' | 'unavailable' | 'network' | 'invalid' | 'session' | 'not_found' | 'other';

export interface ErrorInfo {
  kind: ErrorKind;
  message: string;
  retry: boolean;
}

const NETWORK = 'Traffic Analytics ist nicht erreichbar: keine Verbindung zu Home Assistant. Bitte erneut versuchen.';

export function errorInfo(err: unknown): ErrorInfo {
  if (!(err instanceof TrafficApiError)) {
    const name = (err as { name?: unknown } | null)?.name;
    if (err instanceof TypeError || name === 'AbortError' || name === 'NetworkError') {
      return { kind: 'network', message: NETWORK, retry: true };
    }
    return { kind: 'other', message: 'Unerwarteter Fehler im Panel.', retry: true };
  }
  switch (err.status) {
    case null:
      return { kind: 'network', message: NETWORK, retry: true };
    case 400:
      return { kind: 'invalid', message: 'Die Anfrage wurde vom Server nicht akzeptiert.', retry: false };
    case 401:
      return { kind: 'session', message: 'Die Sitzung ist abgelaufen. Bitte die Seite neu laden.', retry: false };
    case 403:
      return { kind: 'forbidden', message: 'Admin nötig: Diese Ansicht ist Administratoren vorbehalten.', retry: false };
    case 404:
      return { kind: 'not_found', message: 'Nicht gefunden.', retry: false };
    case 410:
      return { kind: 'unavailable', message: 'Traffic Analytics ist nicht verfügbar: die Integration ist nicht geladen.', retry: true };
    case 503:
      return { kind: 'unavailable', message: 'Traffic Analytics ist nicht verfügbar: das Modul läuft gerade nicht.', retry: true };
    default:
      return { kind: 'other', message: 'Die Anfrage ist fehlgeschlagen.', retry: err.status >= 500 };
  }
}

// ── Queries ──────────────────────────────────────────────────────────────

const POINT_ID_RE = /^tpt_[0-9a-f]{16}$/;

export function isPointId(v: unknown): v is string {
  return typeof v === 'string' && POINT_ID_RE.test(v);
}

/** Query of /series; anything off the fixed lists is refused before a request. */
export function seriesQuery(q: SeriesQuery): string {
  if (!isPointId(q.pointId)) throw new TrafficApiError(400, 'invalid_query', { field: 'point_id' });
  if (!SERIES_WINDOWS.includes(q.window)) throw new TrafficApiError(400, 'invalid_query', { field: 'window' });
  return new URLSearchParams({ point_id: q.pointId, window: q.window }).toString();
}

/** Query of /talkers, from the fixed lists only. */
export function talkerQuery(q: TalkerQuery): string {
  if (!TALKER_KINDS.includes(q.kind)) throw new TrafficApiError(400, 'invalid_query', { field: 'kind' });
  if (!TALKER_SCOPES.includes(q.scope)) throw new TrafficApiError(400, 'invalid_query', { field: 'scope' });
  if (!TALKER_WINDOWS.includes(q.window)) throw new TrafficApiError(400, 'invalid_query', { field: 'window' });
  if (!DIRECTIONS.includes(q.direction)) throw new TrafficApiError(400, 'invalid_query', { field: 'direction' });
  if (!Number.isInteger(q.limit) || q.limit < 1 || q.limit > 50) throw new TrafficApiError(400, 'invalid_query', { field: 'limit' });
  const p: Record<string, string> = { kind: q.kind, scope: q.scope, direction: q.direction, limit: String(q.limit) };
  if (q.kind !== 'current') p.window = q.window; // "current" has no window
  return new URLSearchParams(p).toString();
}

// ── Overview helpers ─────────────────────────────────────────────────────

/** Points the history view can show: infrastructure first, WAN on top. */
export function historyPoints(list: PointList): PointRow[] {
  const order: Record<string, number> = { wan: 0, interface: 1, port: 2, vlan: 3, station: 4, client: 5 };
  return [...list.points].sort((a, b) =>
    (order[a.scope] ?? 9) - (order[b.scope] ?? 9)
    || (a.routerId ?? '').localeCompare(b.routerId ?? '')
    || pointLabel(a).localeCompare(pointLabel(b))
    || a.pointId.localeCompare(b.pointId));
}

/** Tiles of the overview; every unknown is "—" with its reason. */
export function overviewTiles(o: Overview): { name: string; text: string; known: boolean; sub: string }[] {
  const t = o.wanTotal;
  const cov = o.coverage;
  const usable = t !== null && t.refused === null && o.wan.length > 0;
  const down = usable ? sumNamed(o.wan, 'down') : null;
  const up = usable ? sumNamed(o.wan, 'up') : null;
  return [
    {
      name: 'WAN Download jetzt', text: fmtRate(down), known: down !== null,
      sub: t ? `Abdeckung ${coverageView(t.coverage).label} · ${fmtCount(t.contributing)} von ${fmtCount((t.contributing ?? 0) + (t.omitted ?? 0))} WAN-Messpunkten` : 'kein WAN-Messpunkt',
    },
    {
      name: 'WAN Upload jetzt', text: fmtRate(up), known: up !== null,
      sub: t && t.reasons.length ? reasonsText(t.reasons) : (t ? '' : 'kein WAN-Messpunkt'),
    },
    {
      name: 'Messpunkte vollständig', text: cov ? `${fmtCount(cov.full)} von ${fmtCount(cov.points)}` : DASH, known: cov !== null && cov.points !== null,
      sub: cov && cov.reasons.length ? cov.reasons.map(r => `${reasonText(r.code)} (${r.count})`).join(' · ') : '',
    },
    {
      name: 'Offene Anomalien', text: fmtCount(o.anomalies?.open), known: o.anomalies?.open != null,
      sub: o.anomalies ? `${fmtCount(o.anomalies.ended)} beendet · ${fmtCount(o.anomalies.suppressed)} unterdrückt` : '',
    },
  ];
}

function sumNamed(rows: readonly RateRow[], which: 'down' | 'up'): number | null {
  const vals = rows.map(r => (which === 'down' ? r.downBps : r.upBps));
  if (vals.some(v => v === null)) return null; // a missing part makes the sum unknown, not smaller
  return vals.reduce<number>((a, v) => a + (v as number), 0);
}
