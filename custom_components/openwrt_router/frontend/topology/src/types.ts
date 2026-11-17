// ── Domain types ──────────────────────────────────────────────────────────

export interface RouterEvent {
  ts: number;          // unix timestamp
  type: 'info' | 'warn' | 'error';
  message: string;
  detail?: string;
}

export type NodeStatus = 'online' | 'offline' | 'warning';
// 'router_uplink' = LLDP-verified router-to-router ethernet link (high confidence).
export type UplinkType = 'wired' | 'mesh' | 'repeater' | 'router_uplink';
export type DeviceCategory = 'smartphone' | 'laptop' | 'iot' | 'guest' | 'other';
export type FilterType = 'all' | 'aps' | 'clients' | 'warnings';

// ── Client / link metadata (v1.22 richer model) ───────────────────────────
export type ConnectionType = 'wired' | 'wireless' | 'router_uplink' | 'unknown';
export type ConfidenceLevel = 'high' | 'medium' | 'low';

/** A discrepancy between the LLDP-reported port and the bridge-FDB port. */
export interface LldpConflict {
  source: string;        // e.g. "fdb"
  fdb_port?: string;
  lldp_port?: string;
}

/** LLDP-derived router-to-router uplink details (relationship: router_uplink). */
export interface LldpUplink {
  linkType?: string;                 // "lldp"
  detectionMethod?: string;          // "lldp"
  confidence?: ConfidenceLevel;      // "high" | "medium" | "low"
  direction?: 'bidirectional' | 'one_way';
  fromPort?: string;                 // physical port on the "from" router (e.g. lan3)
  toPort?: string;                   // physical port on the "to" router (e.g. wan)
  gatewayPort?: string;
  apPort?: string;
  vlanTags?: number[];
  neighborName?: string;
  neighborHost?: string;
  neighborMac?: string;
  neighborChassisId?: string;
  neighborPortId?: string;
  neighborPortDescription?: string;
  managementIp?: string;
  capabilities?: string[];
  conflicts?: LldpConflict[];
  /** Further LLDP observations of the same router pair (parallel links). */
  duplicates?: LldpDuplicate[];
}

/** One extra LLDP observation of an already linked router pair (parallel link). */
export interface LldpDuplicate {
  observer?: string;          // router id that saw this neighbour entry
  localInterface?: string;    // raw local interface on the observer (e.g. "lan2")
  localPort?: string;         // normalised local port
  neighborPortId?: string;    // port id the neighbour announced
}

export interface CpuHistoryPoint {
  ts: number;   // unix timestamp
  cpu: number;  // 0-100 percent
  mem?: number; // 0-100 percent
}

export interface DdnsService {
  section: string;
  service_name: string;
  domain: string;
  enabled: boolean;
  ip: string;
  last_update: number | null;  // unix timestamp
  status: 'ok' | 'error' | 'unknown';
}

export interface Gateway {
  id: string;
  name: string;
  model: string;
  ip: string;
  wanIp: string;
  uptime: string;
  status: NodeStatus;
  firmwareVersion?: string; // OpenWrt release version e.g. "23.05.2"
  cpuLoad?: number;     // 0-100 percent
  memUsage?: number;    // 0-100 percent
  cpuHistory?: number[]; // ring buffer of recent cpu_load values (frontend-accumulated, fallback)
  cpuHistoryBackend?: CpuHistoryPoint[]; // 1h history from backend (preferred)
  events?: RouterEvent[]; // recent status-change events (newest first)
  ssids?: SsidInfo[];   // WiFi networks at gateway
  pingMs?: number | null;
  ddnsServices?: DdnsService[];
  wanTraffic?: WanTraffic;
  portStats?: PortStat[];
  vlans?: VlanInfo[];
  vlansStale?: boolean;  // true = VLAN-Daten aus Cache (Router war kurzzeitig offline)
  topologySnapshots?: TopologySnapshot[];
  /** Config entry id: key of this router in the intelligence API (P7). */
  entryId?: string;
  /** Open root incidents by severity (warning symbol on the node, P7). */
  incidents?: IncidentCounts;
}

/** WAN throughput averaged between two coordinator polls. */
export interface WanTraffic {
  downstream_bps?: number; // bit/s
  upstream_bps?: number;   // bit/s
  interval_s?: number;     // averaging window (seconds between the two samples)
  sampled_at?: string;     // ISO timestamp of the newer sample
}

export interface TopologySnapshot {
  ts: number;           // unix timestamp
  routers: Array<{ id: string; hostname: string; ip: string; status: string }>;
  client_count: number;
  wan_connected: boolean;
}

export interface SsidInfo {
  ssid: string;
  band: string;    // '2.4 GHz' | '5 GHz' | '6 GHz'
  channel?: number; // WiFi channel (e.g. 6, 36, 100)
}

export type PortDeviceConfidence = 'high' | 'medium' | 'low' | 'none';

/** A device observed on a physical switch port (bridge FDB + DHCP/ARP). */
export interface PortDevice {
  mac: string;
  ip?: string;
  name?: string;                    // DHCP hostname if known
  source?: string;                  // e.g. "fdb+dhcp+arp" or "trunk_map"
  confidence: PortDeviceConfidence;
  webUrl?: string;                  // re-validated client-side before rendering
  isRouter?: boolean;               // true for mesh APs on trunk ports
  routerNodeId?: string;            // node id to focus when isRouter
}

export interface PortStat {
  name: string;        // "lan1", "wan", "eth0", etc.
  up: boolean;
  speed_mbps: number | null;  // Mbps or null if no link
  duplex?: string | null;     // "full" | "half" | null
  vlanIds?: number[];         // VLAN IDs on this port (from UCI bridge-vlan)
  connectedDevice?: string;   // hostname or MAC of device connected to this port
  rxBytes?: number | null;
  txBytes?: number | null;
  // ── v1.21 port-device model — all optional so old snapshots keep working ──
  role?: 'lan' | 'wan';
  connectedDevices?: PortDevice[];  // devices mapped to this port (sorted, capped)
  primaryDevice?: PortDevice;
  deviceCount?: number;             // uncapped total
  hasDownstreamSwitch?: boolean;
  webUrl?: string;
  mappingConfidence?: PortDeviceConfidence;
}

export interface VlanInfo {
  id: number;          // VLAN ID (e.g. 10, 20, 100)
  interface: string;   // e.g. "br-lan.10", "eth0.20"
  status: string;      // "up" | "down" | "unknown"
  ipv4?: string;       // gateway IP in this VLAN, e.g. "192.168.10.1"
  prefix?: number;     // subnet prefix length, e.g. 24
}

export interface AccessPoint {
  id: string;
  name: string;
  model: string;
  ip: string;
  uplinkType: UplinkType;
  uplinkTo: string; // gateway id or parent AP id
  clientCount: number;
  backhaulSignal: number; // dBm — falls back to -60 sentinel when no real measurement
  /** True when backhaulSignal is a real RSSI from the backend (wifi_uplink edges).
   *  False for mesh_member subnet-fallback edges where -60 is just a placeholder. */
  backhaulSignalKnown?: boolean;
  status: NodeStatus;
  firmwareVersion?: string; // OpenWrt release version e.g. "23.05.2"
  events?: RouterEvent[]; // recent status-change events (newest first)
  ssids?: SsidInfo[];      // WiFi networks broadcast by this AP
  cpuLoad?: number;        // 0-100 percent
  memUsage?: number;       // 0-100 percent
  cpuHistoryBackend?: CpuHistoryPoint[]; // 1h history from backend
  primaryVlanId?: number;  // majority VLAN among connected clients
  gatewayPort?: string;        // e.g. "lan1", "lan2" — switch port on gateway
  gatewayPortSpeed?: number | null;  // Mbps
  gatewayPortUp?: boolean;
  apPort?: string;             // physical port on AP side (e.g. "wan") — null for WLAN-Repeater
  vlanTags?: number[];         // VLAN IDs carried on the gateway port (Trunk = >1)
  portStats?: PortStat[];      // physical ports on this AP (WAN, LAN1, ...)
  /** Present when this AP's uplink was verified via LLDP (uplinkType === 'router_uplink'). */
  lldpUplink?: LldpUplink;
  /** True when the uplink edge is built from old data (one end router offline). */
  uplinkStale?: boolean;
  /** Config entry id: key of this router in the intelligence API (P7). */
  entryId?: string;
  /** Open root incidents by severity (warning symbol on the node, P7). */
  incidents?: IncidentCounts;
}

export interface Client {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  mac: string;
  apId: string;
  category: DeviceCategory;
  signal: number; // dBm
  band: string;
  status: NodeStatus;
  manufacturer?: string;
  connectedSince?: number; // seconds since connection (from hostapd connected_time)
  dhcpExpires?: number;    // unix timestamp when DHCP lease expires
  rxBytes?: number | null; // bytes received since connection (from hostapd)
  txBytes?: number | null; // bytes transmitted since connection (from hostapd)
  vlanId?: number;         // VLAN this client belongs to (matched via subnet)
  // True when the backend reported the client via hostapd (WiFi). False/undefined
  // means the client was learned only from DHCP/ARP and is most likely wired.
  isWifiClient?: boolean;
  // ── v1.22 richer client model — all optional so old snapshots keep working ──
  vendor?: string;              // server-side OUI vendor (preferred over local lookup)
  connectionType?: ConnectionType; // "wired" | "wireless" | "router_uplink" | "unknown"
  confidence?: ConfidenceLevel;    // detection confidence
  source?: string;                 // "hostapd" | "iwinfo" | "dhcp" | "fdb" | ...
  webUrl?: string;                 // http://<ip> — validated client-side; only set when reachable
  lastSeen?: string;               // ISO timestamp
  linkSpeed?: number;              // negotiated link speed in Mbps (if reported)
  iface?: string;                  // interface / port the client is on (if reported)
  // ── Names known to Home Assistant (read from the HA registries) ──
  haName?: string;                 // user-set name or another integration's device name
  haNameSource?: 'user' | 'device';
  haModel?: string;
  randomMac?: boolean;             // locally administered (private / randomised) MAC
  stale?: boolean;                 // reported by a router whose last update failed (old data)
}

export interface SwitchNode {
  id: string;
  label: string;
  gatewayPort?: string;  // which gateway port this switch is connected to
  apCount: number;       // how many APs are behind this switch
}

export interface TopologyData {
  gateway: Gateway;
  accessPoints: AccessPoint[];
  clients: Client[];
  switchNodes: SwitchNode[];  // inferred switch nodes between gateway and APs
  timestamp: string;
  // true = the snapshot listed no router at all; `gateway` is then only a
  // placeholder and must not raise "WAN offline" style alerts.
  noRouters?: boolean;
  /** Fleet health score from the network intelligence (P7); absent = engine not running. */
  intelligence?: { fleetScore: number | null; coverage: number };
}

// ── Layout types ──────────────────────────────────────────────────────────

export interface NodeLayout {
  id: string;
  cx: number; // center x
  cy: number; // center y
  width: number;
  height: number;
}

export type EdgeKind = 'internet' | 'gateway-wired' | 'ap-mesh' | 'router-uplink';

export interface EdgeLayout {
  id: string;
  sourceId: string;
  targetId: string;
  kind: EdgeKind;
  path: string; // SVG path d attribute
  status: NodeStatus;
  vlanId?: number;            // primary VLAN of the target AP (used for edge coloring in vlan-mode)
  gatewayPort?: string;       // e.g. "lan3" — switch port on gateway side
  gatewayPortSpeed?: number | null; // Mbps
  apPort?: string;            // e.g. "wan" — port on AP side (always WAN for wired uplinks)
  vlanTags?: number[];        // VLANs carried on the gateway port (length>1 ⇒ trunk)
  // ── router-uplink (LLDP) extras ──
  fromPort?: string;          // physical port on the source (from) router
  toPort?: string;            // physical port on the target (to) router
  lldp?: LldpUplink;          // full LLDP neighbor detail for router-uplink edges
  stale?: boolean;            // built from old data (one end router offline)
}

export interface TopologyLayout {
  internetNode: NodeLayout;
  gatewayNode: NodeLayout;
  apNodes: Map<string, NodeLayout>;
  clientStripNodes: Map<string, NodeLayout>;
  edges: EdgeLayout[];
  canvasWidth: number;
  canvasHeight: number;
}

// ── Hover/selection state ─────────────────────────────────────────────────

export interface HoverContext {
  hoveredNodeId: string | null;
  /** Edge ids that should be highlighted when a node is hovered. */
  highlightedEdges: Set<string>;
  /** Node ids that should be dimmed when another node is hovered. */
  dimmedNodes: Set<string>;
}

// ── Network intelligence (P7, /api/openwrt_topology/intelligence/*) ───────

export type Severity = 'info' | 'warning' | 'critical';
export type IncidentStatus = 'active' | 'acknowledged' | 'ignored' | 'resolved';
/** Graded by the engine (net_rules.cause_level, RT6): status, confidence, source families. */
export type CauseLevel = 'confirmed' | 'likely' | 'possible' | 'unknown';

export interface IncidentCounts {
  critical: number;
  warning: number;
  info: number;
}

export interface IntelEvent {
  id: string;
  ts: number;
  router: string;
  router_name: string;
  category: string;
  kind: string;
  origin: 'observed' | 'inferred';
  source: string;
  subject: Record<string, unknown>;
  signal: number | null;
  count: number;
  severity: Severity;
  cause: string | null;
  cause_status: 'confirmed' | 'hypothesis' | null;
  confidence: number;
  msg_key: string;
  params: Record<string, unknown>;
  maintenance: boolean;
  src_ts: number | null;
  clock_skew: boolean;
  parent_id: string | null;
  role?: 'evidence' | 'follow_up';
}

export interface IntelIncident {
  id: string;
  type: string;
  scope: string;
  scope_key: string;
  status: IncidentStatus;
  severity: Severity;
  confidence: number;
  origin: 'observed' | 'inferred';
  cause: string | null;
  cause_status: 'confirmed' | 'hypothesis' | null;
  cause_level: CauseLevel;
  /** rec_<cause> for a cause with a recommendation (RT7), else null. */
  recommendation_key?: string | null;
  area: string | null;
  parent_id: string | null;
  children: number;
  child: boolean;
  routers: string[];
  router_names: string[];
  affected: number;
  first_seen: number;
  last_seen: number;
  resolved_at: number | null;
  reopened_at: number | null;
  reopen_count: number;
  occurrences: number;
  ignore_until: number | null;
  duration_s: number;
  evidence_count: number;
  evidence?: Array<{ ts: number; id: string | null; kind: string; event: IntelEvent | null }>;
}

export interface IntelIncidentDetail {
  incident: IntelIncident;
  parent: IntelIncident | null;
  children: IntelIncident[];
  chain: IntelEvent[];
}

export interface IntelRouterSummary {
  id: string;
  name: string;
  score: number | null;
  coverage: number;
  areas: Record<string, { score: number | null; coverage: number }>;
  offline: boolean;
  maintenance: boolean;
  incidents_active: number;
  critical: boolean;
  reconnects_1h: number;
  auth_errors_1h: number;
  wan_reconnects_24h: number;
  incidents: IncidentCounts;
  /** Last log read (RT9): the log is the event source, read on every poll. */
  log?: IntelLogState;
}

export interface IntelLogState {
  /** ok | error | not_permitted | pending, null before the first poll */
  status: string | null;
  read_at: number | null;
  age_s: number | null;
}

export interface IntelSummary {
  generated_at: number;
  loaded: boolean;
  load_failed: boolean;
  fleet: {
    score: number | null;
    coverage: number;
    routers: number;
    maintenance: number;
    maintenance_until: number | null;
    incidents_active: number;
    critical: boolean;
  };
  routers: IntelRouterSummary[];
  incidents: IncidentCounts;
  incidents_open_total: number;
  incidents_ignored: number;
  events_24h: Record<string, number>;
  events_24h_by_severity: IncidentCounts;
  events_stored: number;
  wifi: {
    top_clients: Array<{
      mac: string;
      router: string;
      router_name: string;
      events: number;
      reconnects: number;
      auth_errors: number;
      last_ts: number;
    }>;
  };
}

export interface IntelEventsPage {
  events: IntelEvent[];
  next_before: string | null;
  limit: number;
}

export interface IntelIncidentsPage {
  incidents: IntelIncident[];
  total: number;
  limit: number;
}

/** Settings tree as stored by the engine (net_rules.DEFAULT_SETTINGS). */
export type IntelSettingsTree = { [key: string]: unknown };

export interface IntelSettingsResponse {
  settings: IntelSettingsTree;
  defaults: IntelSettingsTree;
  can_edit: boolean;
  routers: Array<{ id: string; name: string; maintenance: boolean }>;
  limits: { list_max: number; string_max: number };
}

// ── Client stability (B5 routes /intelligence/clients*) ─────────────────

export type StabilityClass =
  | 'very_stable' | 'stable' | 'noticeable' | 'unstable' | 'critical' | 'unknown';
export type ClientState = 'online' | 'grace' | 'offline' | 'unknown';
export type StabilityWindow = '1h' | '24h' | '7d' | '30d';

export interface ClientLastDisconnect {
  ts: number;
  reason: string | null;
  class: string | null;
  timed: boolean;
}

export interface StabilityRow {
  mac: string;
  name: string | null;
  ip: string | null;
  private_mac: boolean;
  router: string | null;
  router_name: string | null;
  band: string | null;
  ssid: string | null;
  state: ClientState;
  rssi: number | null;
  since: number | null;
  last_seen: number | null;
  score: number | null;
  class: StabilityClass;
  coverage: number | null;
  availability_24h: number | null;
  reconnects_24h: number | null;
  last_disconnect: ClientLastDisconnect | null;
  entity: boolean;
  sleepy: boolean;
  score_7d: number | null;
  availability_7d: number | null;
  trend: 'up' | 'down' | 'flat' | null;
  // 1.43
  score_previous_24h?: number | null;
  trend_delta?: number | null;
  last_problem?: StabilityProblem | null;
}

/** Newest disconnect or auth/assoc/DHCP failure of a client (1.43). */
export interface StabilityProblem {
  ts: number;
  kind: 'disconnect' | 'auth_fail' | 'assoc_fail' | 'dhcp_fail' | string;
  class: string | null;
  reason: string | null;
}

export interface StabilityTable {
  now: number;
  enabled: boolean;
  total: number;
  clients: StabilityRow[];
  next_cursor: string | null;
  routers: Array<{ id: string; name: string }>;
  ssids: string[];
}

export interface StabilityPart {
  value: number | null;
  coverage: number;
  metric: number | null;
  included: boolean;
}

export interface StabilityPoint {
  t: number;
  observed_s: number;
  online_s: number;
  gap_s: number;
  disconnects: number;
  infra: number;
  reconnects: number;
  rssi_mean: number | null;
  rssi_min: number | null;
  rssi_max: number | null;
  // 1.43: main AP (most online time) and its band, roams, flaps, failures
  aps?: string[];
  ap?: string | null;
  band?: string | null;
  leaves?: number;
  roams?: number;
  flaps?: number;
  auth_fail?: number;
  dhcp_fail?: number;
}

/** One hour (7 d) or day (30 d) of the coarse strip; shares sum to 1 (1.43). */
export interface StabilityStripCell {
  t: number;
  span_s: number;
  online: number;
  offline: number;
  gap: number;
  unknown: number;
  disconnects: number;
  infra: number;
  roams: number;
  flaps: number;
}

export interface StabilitySegment {
  start: number;
  end: number;
  state: 'online' | 'offline' | 'gap' | 'unknown';
}

export interface StabilityTransition {
  ts: number;
  kind: string;
  router?: string | null;
  router_name: string | null;
  reason: string | null;
  class: string | null;
  incident_id: string | null;
}

export interface StabilityRecommendation {
  key: string;
  kind: 'observation' | 'hypothesis' | 'confirmed';
  confidence: number | null;
  subject: string;
  params: Record<string, string | number>;
}

export interface ClientStabilityDetail {
  now: number;
  mac: string;
  window: StabilityWindow;
  live: {
    state: ClientState;
    since: number | null;
    router_name: string | null;
    band: string | null;
    ssid: string | null;
    rssi: number | null;
    session_start: number | null;
    first_seen: number | null;
    last_seen: number | null;
    last_disconnect: ClientLastDisconnect | null;
    hostname: string | null;
    ip: string | null;
    private_mac: boolean;
  };
  score: {
    score: number | null;
    class: StabilityClass;
    coverage: number | null;
    parts: Record<string, StabilityPart>;
  };
  stats: {
    coverage: number | null;
    availability: number | null;
    sessions: number;
    longest_stable_s: number;
    disconnects: Record<string, number>;
    reconnects: number;
    roams_in: number;
    roam_flaps: number;
    auth_fail: number;
    dhcp_fail: number;
    rssi_mean: number | null;
    weak_share: number | null;
    log_coverage: number | null;
    // 1.43
    start?: number | null;
    memory_from?: number | null;
    window_s?: number;
    observed_s?: number;
    online_s?: number;
    gap_s?: number;
    roams_out?: number;
    band_changes?: number;
    assoc_fail?: number;
    rssi_n?: number;
    rssi_min?: number | null;
    rssi_max?: number | null;
    rate_rx_kbit?: number | null;
    rate_tx_kbit?: number | null;
    finished_sessions?: number;
    session_mean_s?: number | null;
    ip_visible_share?: number | null;
    notable_events?: number;
  };
  series: StabilityPoint[];
  score_series: Array<{ t: number; score: number | null; class: StabilityClass }>;
  rssi: Array<{ t: number; rssi: number | null; router?: string | null; band?: string | null; state?: string }>;
  timeline: StabilitySegment[];
  strip?: StabilityStripCell[];
  routers?: Record<string, string>;
  transitions: StabilityTransition[];
  incidents: Array<{ incident_id: string; cause_status: string | null; cause: string | null }>;
  attribution: {
    attribution: string;
    kind: string | null;
    confidence: number | null;
    infra: number;
    client: number;
    total: number;
  };
  patterns: {
    time: { status: string; hours: Array<{ hour: number; hit_days: number; covered_days: number }> };
    signal: { status: string; reason: string | null; delta_db: number | null };
    ap: { status: string; worst_ap: string | null; best_ap: string | null };
  };
  recommendations: StabilityRecommendation[];
  entity: boolean;
  sleepy: boolean;
}

export interface StabilityApStats {
  ap: string;
  name: string;
  status: string;
  clients: number;
  client_hours: number;
  disconnects_per_100h: number | null;
  reconnects_per_100h: number | null;
  flaps_per_100h: number | null;
  rssi_mean: number | null;
  stability: number | null;
  infra_disconnects: number;
  low_basis: boolean;
  rank: number | null;
  auth_fail_per_100h?: number | null;
  roams_in_per_100h?: number | null;
  roams_out_per_100h?: number | null;
  weak_share?: number | null;
  infra_clients?: number;
}

export interface StabilityApView {
  now: number;
  window: StabilityWindow;
  aps: StabilityApStats[];
  ranking: string[];
  recommendations: StabilityRecommendation[];
}

export interface StabilitySettings {
  enabled: boolean;
  retention_days: number;
  entity_macs: string[];
  sleepy_macs: string[];
  max_store_mb: number;
  weights: Record<string, number>;
  classes: number[];
  [key: string]: unknown;
}

export interface StabilitySettingsResponse {
  settings: StabilitySettings;
  defaults?: StabilitySettings;
  can_edit: boolean;
  limits: {
    entity_max: number;
    sleepy_max: number;
    retention_days_max: number;
    store_mb_min: number;
    store_mb_max: number;
    parts?: string[];
    classes?: string[];
  };
  status: {
    clients: number;
    store_bytes_last_save: number | null;
    store_limit_bytes: number;
    trimmed_for_size: number;
    store_load_failed: boolean;
  };
}
