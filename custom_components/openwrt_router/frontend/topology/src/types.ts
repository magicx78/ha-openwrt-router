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
  wanTraffic?: { downstream_bps?: number; upstream_bps?: number };
  portStats?: PortStat[];
  vlans?: VlanInfo[];
  vlansStale?: boolean;  // true = VLAN-Daten aus Cache (Router war kurzzeitig offline)
  topologySnapshots?: TopologySnapshot[];
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
