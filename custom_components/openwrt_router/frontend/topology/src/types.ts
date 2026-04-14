// ── Domain types ──────────────────────────────────────────────────────────

export type NodeStatus = 'online' | 'offline' | 'warning';
export type UplinkType = 'wired' | 'mesh';
export type DeviceCategory = 'smartphone' | 'laptop' | 'iot' | 'guest' | 'other';
export type FilterType = 'all' | 'aps' | 'clients' | 'warnings';

export interface Gateway {
  id: string;
  name: string;
  model: string;
  ip: string;
  wanIp: string;
  uptime: string;
  status: NodeStatus;
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
