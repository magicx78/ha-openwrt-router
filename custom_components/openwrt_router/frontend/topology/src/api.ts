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

function formatUptime(seconds: number): string {
  if (!seconds || seconds <= 0) return '';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** Map internal band codes to display strings. */
function formatBand(raw: string): string {
  const b = raw.toLowerCase();
  if (b === '2.4g' || b === '2.4ghz' || b === '2g') return '2.4 GHz';
  if (b === '5g'   || b === '5ghz')                  return '5 GHz';
  if (b === '6g'   || b === '6ghz')                  return '6 GHz';
  return raw; // pass through anything else (e.g. "unknown" or empty)
}

/** Format seconds-since-connection as human duration: "5h 23m" or "42m". */
export function formatConnectedSince(seconds: number): string {
  if (!seconds || seconds <= 0) return '';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `< 1m`;
}

/** Format a unix timestamp as "HH:MM (noch Xh Ym)" or "Abgelaufen". */
export function formatLeaseExpiry(unixTs: number): string {
  if (!unixTs || unixTs <= 0) return '';
  const expiry = new Date(unixTs * 1000);
  const now = Date.now();
  const diffMs = expiry.getTime() - now;
  if (diffMs <= 0) return 'Abgelaufen';
  const diffH = Math.floor(diffMs / 3_600_000);
  const diffM = Math.floor((diffMs % 3_600_000) / 60_000);
  const time = expiry.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  if (diffH > 0) return `${time} (noch ${diffH}h ${diffM}m)`;
  return `${time} (noch ${diffM}m)`;
}

function guessCategory(hostname: string, ssid?: string): DeviceCategory {
  const h = (hostname || '').toLowerCase();
  const s = (ssid || '').toLowerCase();

  // Guest SSID or guest hostname → always guest
  if (s.includes('guest') || /guest/.test(h)) return 'guest';

  // Smartphones & tablets
  if (/iphone|ipad|ipod/.test(h)) return 'smartphone';
  if (/android|pixel[- ]?\d|oneplus|huawei|xiaomi|redmi|oppo|vivo|realme/.test(h)) return 'smartphone';
  if (/samsung|galaxy|sm-[a-z]\d{3}|sch-|sgh-/.test(h)) return 'smartphone';
  if (/motorola|moto[- g|z|e]|nokia|lg-|htc|sony.*xperia|fairphone/.test(h)) return 'smartphone';

  // Laptops & desktops
  if (/macbook|macmini|imac|mac-studio/.test(h)) return 'laptop';
  if (/thinkpad|thinkbook|ideapad|lenovo/.test(h)) return 'laptop';
  if (/latitude|xps|inspiron|optiplex|vostro/.test(h)) return 'laptop'; // Dell
  if (/elitebook|probook|pavilion|envy|omen/.test(h)) return 'laptop';  // HP
  if (/surface|msft/.test(h)) return 'laptop';
  if (/chromebook|acer|asus.*laptop|zenbook|vivobook/.test(h)) return 'laptop';
  if (/\bnotebook\b|\blaptop\b|\bdesktop\b|\bworkstation\b|\bpc\b/.test(h)) return 'laptop';

  // IoT / smart home / embedded
  if (/\b(shelly|tasmota|sonoff|wled|esphome|esp8266|esp32)\b/.test(h)) return 'iot';
  if (/\b(tuya|meross|govee|kasa|tplink|lifx|wemo|hue|ring|nest)\b/.test(h)) return 'iot';
  if (/\b(chromecast|firetv|appletv|shield|roku|fire-?tv|apple-?tv)\b/.test(h)) return 'iot';
  if (/\b(echo|alexa|homepod|google-home|nest-?hub)\b/.test(h)) return 'iot';
  if (/\b(synology|qnap|nas|diskstation)\b/.test(h)) return 'iot';
  if (/\b(printer|epson|canon|brother|hp.*deskjet|hp.*laserjet)\b/.test(h)) return 'iot';
  if (/\b(cam|camera|ipcam|doorbell|wyze|reolink|amcrest|hikvision|dahua)\b/.test(h)) return 'iot';
  if (/\b(sensor|bridge|hub|zigbee|zwave|z-wave|iot|smart)\b/.test(h)) return 'iot';
  if (/\b(plug|switch|bulb|strip|dimmer|relay|outlet)\b/.test(h)) return 'iot';
  if (/^(esp|shelly|tasmota|sonoff|wled|athom|blitzwolf)\d/.test(h)) return 'iot';

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
    uptime: gwNode.attributes?.uptime != null
      ? formatUptime(gwNode.attributes.uptime as number)
      : '',
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

    const connectedSince = attr?.connected_since as number | undefined;
    const dhcpExpires = attr?.dhcp_expires as number | undefined;
    const rawBand = (attr?.band as string) ?? '';

    return {
      id: n.id,
      name: hostname,
      hostname,
      ip: (attr?.ip as string) ?? '',
      mac: (attr?.mac as string) ?? '',
      apId,
      category: guessCategory(hostname, attr?.ssid as string | undefined),
      signal: signal ?? -65,
      band: formatBand(rawBand),
      status: signalStatus(signal),
      connectedSince: connectedSince && connectedSince > 0 ? connectedSince : undefined,
      dhcpExpires: dhcpExpires && dhcpExpires > 0 ? dhcpExpires : undefined,
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
  console.debug('[openwrt-topology] fetchTopologyData — token?', !!token, 'auth keys:', Object.keys((hass as any).auth ?? {}));
  let snap: Snapshot;

  if (token) {
    console.debug('[openwrt-topology] using window.fetch');
    const response = await window.fetch('/api/openwrt_topology/snapshot', {
      headers: { Authorization: `Bearer ${token}` },
    });
    console.debug('[openwrt-topology] fetch response status:', response.status);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    snap = (await response.json()) as Snapshot;
    console.debug('[openwrt-topology] snapshot nodes:', snap.nodes?.length, 'clients:', snap.clients?.length);
  } else {
    console.debug('[openwrt-topology] no token — falling back to callApi');
    snap = await hass.callApi<Snapshot>('GET', 'openwrt_topology/snapshot');
  }

  return adaptSnapshot(snap);
}
