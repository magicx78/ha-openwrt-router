/**
 * api.ts — Fetch topology snapshot from HA API and adapt to TopologyData.
 *
 * The /api/openwrt_topology/snapshot endpoint returns a mesh snapshot with
 * nodes (type=router|interface|client), edges, and a clients array.
 * This module maps that to the flat TopologyData shape consumed by TopologyView.
 */

import type {
  TopologyData,
  Gateway,
  AccessPoint,
  Client,
  NodeStatus,
  DeviceCategory,
  UplinkType,
} from './types';

// ── Raw snapshot types ───────────────────────────────────────────────────

interface SnapshotNodeAttributes {
  model?: string;
  board_name?: string;
  host_ip?: string;
  wan_proto?: string;
  wan_connected?: boolean;
  mac?: string;
  // interface attrs
  ssid?: string;
  band?: string;
  // client attrs
  ap_mac?: string;
  ip?: string;
  hostname?: string;
  radio?: string;
  signal?: number | null;
  [key: string]: unknown;
}

interface SnapshotNode {
  id: string;
  type: 'router' | 'interface' | 'client';
  label: string;
  role?: string; // 'gateway' | 'ap' | 'unknown'
  ip?: string;   // WAN IP for routers
  status?: string;
  attributes: SnapshotNodeAttributes;
}

interface SnapshotEdge {
  id: string;
  from: string;
  to: string;
  relationship: string; // 'lan_uplink' | 'wifi_uplink' | 'mesh_member' | 'has_interface' | 'has_client'
  inferred?: boolean;
  attributes?: {
    link_type?: string;
    signal?: number;
    [key: string]: unknown;
  };
}

interface SnapshotClient {
  mac: string;
  ap_mac: string; // router node id that owns this client
  signal: number | null;
  connected: boolean;
  last_seen?: string;
}

interface Snapshot {
  generated_at: string;
  nodes: SnapshotNode[];
  edges: SnapshotEdge[];
  interfaces: unknown[];
  clients: SnapshotClient[];
  meta: Record<string, unknown>;
}

// ── Helpers ──────────────────────────────────────────────────────────────

function guessCategory(hostname: string, ssid?: string): DeviceCategory {
  const h = (hostname || '').toLowerCase();
  const s = (ssid || '').toLowerCase();
  if (/iphone|android|pixel|samsung.*(s\d|a\d)|oneplus|galaxy/.test(h)) return 'smartphone';
  if (/ipad/.test(h)) return 'smartphone';
  if (/macbook|laptop|thinkpad|notebook|mbp|dell|hp-/.test(h)) return 'laptop';
  if (s.includes('guest') || /guest/.test(h)) return 'guest';
  if (
    /tv|chromecast|firetv|appletv|shield|roku|hue|ring|nest|iot|smart|bridge|sensor|cam|plug|bulb|esp|tasmota|wyze|echo|alexa|wemo|homepod|synology|nas|printer/.test(
      h,
    )
  )
    return 'iot';
  return 'other';
}

function signalStatus(signal: number | null | undefined): NodeStatus {
  if (signal == null) return 'online';
  if (signal >= -70) return 'online';
  return 'warning';
}

// ── Core adapter ─────────────────────────────────────────────────────────

export function adaptSnapshot(snap: Snapshot): TopologyData {
  const routerNodes = snap.nodes.filter((n) => n.type === 'router');
  const clientNodes = snap.nodes.filter((n) => n.type === 'client');

  // Inter-router edges only
  const interRouterEdges = snap.edges.filter(
    (e) =>
      e.relationship === 'lan_uplink' ||
      e.relationship === 'wifi_uplink' ||
      e.relationship === 'mesh_member',
  );

  // Gateway = first router with role=gateway, fallback to first router
  const gwNode = routerNodes.find((n) => n.role === 'gateway') ?? routerNodes[0];

  if (!gwNode) {
    return {
      gateway: {
        id: 'gw',
        name: 'No routers online',
        model: '',
        ip: '',
        wanIp: '',
        uptime: '',
        status: 'offline',
      },
      accessPoints: [],
      clients: [],
      timestamp: snap.generated_at,
    };
  }

  const gateway: Gateway = {
    id: gwNode.id,
    name: gwNode.label,
    model: gwNode.attributes?.model ?? '',
    ip: gwNode.attributes?.host_ip ?? '',
    wanIp: gwNode.ip ?? '',
    uptime: '',
    status: 'online',
  };

  // AP nodes = all router nodes that are not the gateway
  const apRouterNodes = routerNodes.filter((n) => n.id !== gwNode.id);

  // Build uplink map: ap_id → uplink info (from inter-router edges)
  const uplinkMap = new Map<string, { uplinkTo: string; uplinkType: UplinkType; backhaulSignal: number }>();
  for (const edge of interRouterEdges) {
    const apId = edge.to;
    if (apId === gwNode.id) continue;
    // lan_uplink = confirmed wired, wifi_uplink = confirmed mesh,
    // mesh_member = inferred (unknown) → show as wired to avoid false "mesh" label
    const uplinkType: UplinkType =
      edge.relationship === 'wifi_uplink' ? 'mesh' : 'wired';
    const backhaulSignal = (edge.attributes?.signal as number | undefined) ?? -60;
    uplinkMap.set(apId, { uplinkTo: edge.from, uplinkType, backhaulSignal });
  }

  // Count clients per router (from the clients array, ap_mac = router id)
  const clientCountMap = new Map<string, number>();
  for (const c of snap.clients) {
    clientCountMap.set(c.ap_mac, (clientCountMap.get(c.ap_mac) ?? 0) + 1);
  }

  const accessPoints: AccessPoint[] = apRouterNodes.map((n) => {
    const uplink = uplinkMap.get(n.id);
    return {
      id: n.id,
      name: n.label,
      model: n.attributes?.model ?? '',
      ip: n.attributes?.host_ip ?? '',
      uplinkType: uplink?.uplinkType ?? 'wired',
      uplinkTo: uplink?.uplinkTo ?? gwNode.id,
      clientCount: clientCountMap.get(n.id) ?? 0,
      backhaulSignal: uplink?.backhaulSignal ?? -60,
      status: 'online' as NodeStatus,
    };
  });

  // Build client list from client nodes
  const clients: Client[] = clientNodes.map((n) => {
    const attr = n.attributes;
    const signal = attr?.signal as number | null | undefined;
    const hostname = (attr?.hostname as string) || n.label || (attr?.mac as string) || '';
    const apId = (attr?.ap_mac as string) ?? gwNode.id;

    return {
      id: n.id,
      name: hostname,
      hostname,
      ip: (attr?.ip as string) ?? '',
      mac: (attr?.mac as string) ?? '',
      apId,
      category: guessCategory(hostname, attr?.ssid as string | undefined),
      signal: signal ?? -65,
      band: '',
      status: signalStatus(signal),
    };
  });

  return {
    gateway,
    accessPoints,
    clients,
    timestamp: snap.generated_at,
  };
}

// ── HA API fetch ─────────────────────────────────────────────────────────

/** HA hass object — only the parts we need. */
export interface HassLike {
  callApi<T>(method: 'GET' | 'POST', path: string): Promise<T>;
  // The real HA Auth object (home-assistant-js-websocket) exposes the token
  // under auth.data.access_token — there is no auth.accessToken property.
  auth?: { data?: { access_token?: string } };
}

/**
 * Fetch topology snapshot.
 *
 * Preferred: window.fetch() with Bearer token extracted from hass.auth.
 * This bypasses HA's navigation AbortController (which fires "Transition was
 * skipped" and cancels callApi calls during panel transitions).
 *
 * Fallback: hass.callApi() — used if no token is available.
 */
export async function fetchTopologyData(hass: HassLike): Promise<TopologyData> {
  const token = (hass as any).auth?.data?.access_token as string | undefined;
  let snap: Snapshot;

  if (token) {
    // Native fetch — no AbortSignal, not affected by HA navigation state.
    const response = await window.fetch('/api/openwrt_topology/snapshot', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    snap = (await response.json()) as Snapshot;
  } else {
    // Fallback: callApi (may throw AbortError during HA panel transitions)
    snap = await hass.callApi<Snapshot>('GET', 'openwrt_topology/snapshot');
  }

  return adaptSnapshot(snap);
}
