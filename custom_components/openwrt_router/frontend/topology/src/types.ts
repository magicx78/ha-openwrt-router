// ── Domain types ──────────────────────────────────────────────────────────

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
  cpuLoad?: number;     // 0-100 percent
  memUsage?: number;    // 0-100 percent
  cpuHistory?: number[]; // ring buffer of recent cpu_load values (frontend-accumulated)
  ssids?: SsidInfo[];   // WiFi networks at gateway
  // Fritz!Box / DSL data (optional — only present when Fritz!Box is configured)
  dslStats?: DslStats;
  pingMs?: number | null;
  dslHistory?: DslHistoryPoint[];
  ddnsServices?: DdnsService[];
  wanTraffic?: { downstream_bps?: number; upstream_bps?: number };
  portStats?: PortStat[];
}

export interface SsidInfo {
  ssid: string;
  band: string; // '2.4 GHz' | '5 GHz' | '6 GHz'
}

export interface PortStat {
  name: string;        // "lan1", "wan", "eth0", etc.
  up: boolean;
  speed_mbps: number | null;  // Mbps or null if no link
  duplex?: string | null;     // "full" | "half" | null
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
  ssids?: SsidInfo[];      // WiFi networks broadcast by this AP
  cpuLoad?: number;        // 0-100 percent
  memUsage?: number;       // 0-100 percent
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
