// ── Domain types ──────────────────────────────────────────────────────────

export interface RouterEvent {
  ts: number;          // unix timestamp
  type: 'info' | 'warn' | 'error';
  message: string;
  detail?: string;
}

export type NodeStatus = 'online' | 'offline' | 'warning';
export type UplinkType = 'wired' | 'mesh';
export type DeviceCategory = 'smartphone' | 'laptop' | 'iot' | 'guest' | 'other';
export type FilterType = 'all' | 'aps' | 'clients' | 'warnings';

export interface DslStats {
  downstream_kbps: number;
  upstream_kbps: number;
  downstream_max_kbps: number;
  upstream_max_kbps: number;
  snr_down_db: number;
  snr_up_db: number;
  attn_down_db: number;
  attn_up_db: number;
}

export interface DslHistoryPoint {
  ts: number;        // unix timestamp
  dsl_down: number;  // kbps
  dsl_up: number;    // kbps
  ping_ms: number | null;
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
  // Fritz!Box / DSL data (optional — only present when Fritz!Box is configured)
  dslStats?: DslStats;
  pingMs?: number | null;
  dslHistory?: DslHistoryPoint[];
  ddnsServices?: DdnsService[];
  wanTraffic?: { downstream_bps?: number; upstream_bps?: number };
  portStats?: PortStat[];
  vlans?: VlanInfo[];
  vlansStale?: boolean;  // true = VLAN-Daten aus Cache (Router war kurzzeitig offline)
}

export interface SsidInfo {
  ssid: string;
  band: string;    // '2.4 GHz' | '5 GHz' | '6 GHz'
  channel?: number; // WiFi channel (e.g. 6, 36, 100)
}

export interface PortStat {
  name: string;        // "lan1", "wan", "eth0", etc.
  up: boolean;
  speed_mbps: number | null;  // Mbps or null if no link
  duplex?: string | null;     // "full" | "half" | null
  vlanIds?: number[];         // VLAN IDs on this port (from UCI bridge-vlan)
  connectedDevice?: string;   // hostname or MAC of device connected to this port
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
  backhaulSignal: number; // dBm
  status: NodeStatus;
  firmwareVersion?: string; // OpenWrt release version e.g. "23.05.2"
  events?: RouterEvent[]; // recent status-change events (newest first)
  ssids?: SsidInfo[];      // WiFi networks broadcast by this AP
  cpuLoad?: number;        // 0-100 percent
  memUsage?: number;       // 0-100 percent
  cpuHistoryBackend?: CpuHistoryPoint[]; // 1h history from backend
  primaryVlanId?: number;  // majority VLAN among connected clients
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
}

export interface TopologyData {
  gateway: Gateway;
  accessPoints: AccessPoint[];
  clients: Client[];
  timestamp: string;
}

// ── Layout types ──────────────────────────────────────────────────────────

export interface NodeLayout {
  id: string;
  cx: number; // center x
  cy: number; // center y
  width: number;
  height: number;
}

export type EdgeKind = 'internet' | 'gateway-wired' | 'ap-mesh';

export interface EdgeLayout {
  id: string;
  sourceId: string;
  targetId: string;
  kind: EdgeKind;
  path: string; // SVG path d attribute
  status: NodeStatus;
  vlanId?: number; // primary VLAN of the target AP (used for edge coloring in vlan-mode)
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
