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
  DslStats,
  DslHistoryPoint,
  DdnsService,
  SsidInfo,
  PortStat,
  VlanInfo,
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
  // gateway DSL attrs
  dsl_stats?: DslStats;
  wan_traffic?: { downstream_bps?: number; upstream_bps?: number };
  ping_ms?: number | null;
  dsl_history?: DslHistoryPoint[];
  ddns_status?: DdnsService[];
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

// ── OUI manufacturer lookup ───────────────────────────────────────────────
// First 6 hex chars (3 octets) of MAC → manufacturer name.
// Covers the most common consumer device vendors.
const OUI_TABLE: Record<string, string> = {
  // Apple
  '000393': 'Apple', '000502': 'Apple', '000a27': 'Apple', '000a95': 'Apple',
  '000d93': 'Apple', '001124': 'Apple', '001451': 'Apple', '0016cb': 'Apple',
  '001731': 'Apple', '001b63': 'Apple', '001e52': 'Apple', '001f5b': 'Apple',
  '001ff3': 'Apple', '0021e9': 'Apple', '002241': 'Apple', '002312': 'Apple',
  '0023df': 'Apple', '002500': 'Apple', '00254b': 'Apple', '002608': 'Apple',
  '003065': 'Apple', '0050e4': 'Apple', '006171': 'Apple', '00c610': 'Apple',
  '08002e': 'Apple', '0c1539': 'Apple', '0c3e9f': 'Apple', '0c4de9': 'Apple',
  '0c7202': 'Apple', '0c74c2': 'Apple', '0cd746': 'Apple', '10002d': 'Apple',
  '103025': 'Apple', '109a59': 'Apple', '10ddb1': 'Apple', '1499e2': 'Apple',
  '146060': 'Apple', '18209d': 'Apple', '18af61': 'Apple', '18e7f4': 'Apple',
  '1c1ac0': 'Apple', '1c36bb': 'Apple', '1c5cf2': 'Apple', '1c9e46': 'Apple',
  '20a2e4': 'Apple', '20c9d0': 'Apple', '241ebb': 'Apple', '24516b': 'Apple',
  '283737': 'Apple', '28cfda': 'Apple', '28e02c': 'Apple', '2c1f23': 'Apple',
  '2c612e': 'Apple', '2cf0a2': 'Apple', '303115': 'Apple', '34363b': 'Apple',
  '34a395': 'Apple', '34c059': 'Apple', '380195': 'Apple', '3859f9': 'Apple',
  '38bae9': 'Apple', '3c0754': 'Apple', '3c15c2': 'Apple', '3ca9f4': 'Apple',
  '40331a': 'Apple', '406c8f': 'Apple', '40a6d9': 'Apple', '40cbe6': 'Apple',
  '44004d': 'Apple', '44d884': 'Apple', '48437c': 'Apple', '485b39': 'Apple',
  '4c57ca': 'Apple', '4c74bf': 'Apple', '4c7c5f': 'Apple', '4c8d79': 'Apple',
  '50bcc0': 'Apple', '50eaac': 'Apple', '54267e': 'Apple', '546021': 'Apple',
  '54ae27': 'Apple', '546100': 'Apple', '58404e': 'Apple', '5849ba': 'Apple',
  '58b035': 'Apple', '5cf739': 'Apple', '60c547': 'Apple', '60d9c7': 'Apple',
  '60f4ef': 'Apple', '64200c': 'Apple', '64a3cb': 'Apple', '64b9e8': 'Apple',
  '683721': 'Apple', '68a86d': 'Apple', '6c3d35': 'Apple', '6c4008': 'Apple',
  '6c709f': 'Apple', '6c96cf': 'Apple', '70480f': 'Apple', '704f57': 'Apple',
  '70700d': 'Apple', '70e72c': 'Apple', '70f087': 'Apple', '743144': 'Apple',
  '7440bb': 'Apple', '745d22': 'Apple', '7831c1': 'Apple', '784f43': 'Apple',
  '786c1c': 'Apple', '7c11be': 'Apple', '7c5049': 'Apple', '7c6d62': 'Apple',
  '7cf05f': 'Apple', '80006e': 'Apple', '80be05': 'Apple', '80d605': 'Apple',
  '84789c': 'Apple', '8485e4': 'Apple', '848870': 'Apple', '84b1e4': 'Apple',
  '88198f': 'Apple', '886b6e': 'Apple', '88c663': 'Apple', '8c2937': 'Apple',
  '8c7b9d': 'Apple', '8c8590': 'Apple', '90272c': 'Apple', '902b34': 'Apple',
  '904840': 'Apple', '90b21f': 'Apple', '90c1c6': 'Apple', '90fd61': 'Apple',
  '98010a': 'Apple', '98b8e3': 'Apple', '98d6bb': 'Apple', '98e0d9': 'Apple',
  '98f4ab': 'Apple', '9c04eb': 'Apple', '9c207b': 'Apple', '9c293b': 'Apple',
  'a03397': 'Apple', 'a06095': 'Apple', 'a0999b': 'Apple', 'a0b4a5': 'Apple',
  'a45e60': 'Apple', 'a48195': 'Apple', 'a4b197': 'Apple', 'a4c361': 'Apple',
  'a4d9ef': 'Apple', 'a8233f': 'Apple', 'a88740': 'Apple', 'a8968a': 'Apple',
  'a8bbcf': 'Apple', 'ac3c0b': 'Apple', 'ac7f3e': 'Apple', 'accf85': 'Apple',
  'b03495': 'Apple', 'b05bba': 'Apple', 'b418d1': 'Apple', 'b481a5': 'Apple',
  'b8098a': 'Apple', 'b86ce8': 'Apple', 'b88d12': 'Apple', 'b89a2a': 'Apple',
  'b8c111': 'Apple', 'bc4cc4': 'Apple', 'bc52b7': 'Apple', 'bc9fef': 'Apple',
  'bce143': 'Apple', 'c06363': 'Apple', 'c09839': 'Apple', 'c0cda8': 'Apple',
  'c0d0e0': 'Apple', 'c42c03': 'Apple', 'c4b301': 'Apple', 'c81eee': 'Apple',
  'c82a14': 'Apple', 'c8bc12': 'Apple', 'c8d083': 'Apple', 'cc29f5': 'Apple',
  'cc44f4': 'Apple', 'd023db': 'Apple', 'd06224': 'Apple', 'd09a2e': 'Apple',
  'd4619d': 'Apple', 'd4f46f': 'Apple', 'd8004d': 'Apple', 'd88196': 'Apple',
  'd8bb2c': 'Apple', 'dca9f9': 'Apple', 'dcef09': 'Apple', 'e0b52d': 'Apple',
  'e0f5c6': 'Apple', 'e4258a': 'Apple', 'e4c63d': 'Apple', 'e4e0a6': 'Apple',
  'e80688': 'Apple', 'e89b71': 'Apple', 'ec85f0': 'Apple', 'ecadf3': 'Apple',
  'f02475': 'Apple', 'f01bf2': 'Apple', 'f09fc2': 'Apple', 'f0b479': 'Apple',
  'f0cbe1': 'Apple', 'f0d1a9': 'Apple', 'f4059a': 'Apple', 'f40f1b': 'Apple',
  'f45c89': 'Apple', 'f4f15a': 'Apple', 'f81efe': 'Apple', 'f87bf1': 'Apple',
  'fc253f': 'Apple', 'fcd848': 'Apple',
  // Samsung
  '001247': 'Samsung', '0015b9': 'Samsung', '0017c9': 'Samsung', '001a8a': 'Samsung',
  '001c43': 'Samsung', '001d25': 'Samsung', '001fe2': 'Samsung',
  '002191': 'Samsung', '0024e9': 'Samsung', '0025f5': 'Samsung', '002638': 'Samsung',
  '0026e2': 'Samsung', '002757': 'Samsung', '0026b6': 'Samsung', '246359': 'Samsung',
  '2c44fd': 'Samsung', '2c0e3d': 'Samsung', '34aa8b': 'Samsung', '38aa3c': 'Samsung',
  '380a94': 'Samsung', '4001c6': 'Samsung', '40d3ae': 'Samsung',
  '4c3c16': 'Samsung', '4c73d5': 'Samsung', '50a4c8': 'Samsung', '5001bb': 'Samsung',
  '543b9b': 'Samsung', '549b12': 'Samsung', '54920a': 'Samsung', '5ca399': 'Samsung',
  '5c3c27': 'Samsung', '5cf6dc': 'Samsung', '6014f8': 'Samsung', '606bbd': 'Samsung',
  '68eb70': 'Samsung', '6c2f2c': 'Samsung', '70f927': 'Samsung', '7449f6': 'Samsung',
  '74457a': 'Samsung', '7825ad': 'Samsung', '788cb5': 'Samsung', '7c1c68': 'Samsung',
  '80650a': 'Samsung', '80187b': 'Samsung', '84119e': 'Samsung', '8c1ab0': 'Samsung',
  '8c7712': 'Samsung', '90f1aa': 'Samsung', '9451f4': 'Samsung',
  'a0cbfd': 'Samsung', 'a4ebba': 'Samsung', 'a8063b': 'Samsung', 'b0c655': 'Samsung',
  'b0d09c': 'Samsung', 'b407f9': 'Samsung', 'b44bd2': 'Samsung', 'b4ef39': 'Samsung',
  'b8c68e': 'Samsung', 'bc765e': 'Samsung', 'bc8ccd': 'Samsung', 'c01173': 'Samsung',
  'c0d321': 'Samsung', 'c4a366': 'Samsung', 'c81f66': 'Samsung', 'cc05c8': 'Samsung',
  'd087e2': 'Samsung', 'd0dfb2': 'Samsung', 'd4e8b2': 'Samsung',
  'dc7144': 'Samsung', 'e4404b': 'Samsung', 'e4e0c5': 'Samsung', 'e87808': 'Samsung',
  'ec1d7a': 'Samsung', 'f05a5f': 'Samsung', 'f01d4d': 'Samsung', 'f49f54': 'Samsung',
  'f4d9fb': 'Samsung', 'f89e28': 'Samsung', 'fc1910': 'Samsung',
  // Google / Android
  '000000': 'Google', '00e04c': 'Google', '04d3b0': 'Google', '08f1ea': 'Google',
  '1cabed': 'Google', '20df3b': 'Google', '38680a': 'Google', '3c5ab4': 'Google',
  '485c7f': 'Google', '489c28': 'Google', '54607e': 'Google', '606d3c': 'Google',
  '6496b4': 'Google', '6ca14b': 'Google', '70b3d5': 'Google', '787b8a': 'Google',
  '94eb2c': 'Google', 'a47733': 'Google', 'a4c138': 'Google', 'a4774a': 'Google',
  'cc3a61': 'Google', 'd83add': 'Google', 'f88fca': 'Google',
  // Xiaomi / Redmi
  '001dc9': 'Xiaomi', '0040d0': 'Xiaomi', '04cff8': 'Xiaomi', '086986': 'Xiaomi',
  '0c1daf': 'Xiaomi', '14f65a': 'Xiaomi', '18590a': 'Xiaomi', '20a360': 'Xiaomi',
  '28e31f': 'Xiaomi', '2c4412': 'Xiaomi', '302244': 'Xiaomi', '34ce00': 'Xiaomi',
  '382dd1': 'Xiaomi', '405bd8': 'Xiaomi', '64b473': 'Xiaomi', '68dfdd': 'Xiaomi',
  '689b89': 'Xiaomi', '6c5c89': 'Xiaomi', '742344': 'Xiaomi', '74a728': 'Xiaomi',
  '7c1dd9': 'Xiaomi', '8c888e': 'Xiaomi', '9c99a0': 'Xiaomi',
  'a08669': 'Xiaomi', 'a4a194': 'Xiaomi', 'b0e235': 'Xiaomi', 'c40bcb': 'Xiaomi',
  'cc2d83': 'Xiaomi', 'd4977d': 'Xiaomi', 'f048ef': 'Xiaomi', 'f0b429': 'Xiaomi',
  'f8a45f': 'Xiaomi', 'fc64ba': 'Xiaomi',
  // Raspberry Pi
  'b827eb': 'Raspberry Pi', 'dca632': 'Raspberry Pi', 'e45f01': 'Raspberry Pi',
  '28cdc4': 'Raspberry Pi',
  // Intel (laptops/WiFi cards)
  '00044b': 'Intel', '000347': 'Intel', '000732': 'Intel', '001517': 'Intel',
  '001f3b': 'Intel', '00215d': 'Intel', '002218': 'Intel', '002369': 'Intel',
  '0027bd': 'Intel', '0800f4': 'Intel', '1c65aa': 'Intel', '3425c4': 'Intel',
  '40a5ef': 'Intel', '4cfece': 'Intel', '606720': 'Intel', '648d89': 'Intel',
  '6c2904': 'Intel', '788ff8': 'Intel', '7c5c16': 'Intel', '8c8d28': 'Intel',
  'a0a8cd': 'Intel', 'a4c3f0': 'Intel', 'c4d98810': 'Intel', 'd0abd5': 'Intel',
  'd85185': 'Intel', 'e04f43': 'Intel', 'f40e11': 'Intel',
  // Huawei
  '001e10': 'Huawei', '001fca': 'Huawei', '002568': 'Huawei', '00259e': 'Huawei',
  '0026bb': 'Huawei', '00664b': 'Huawei', '040102': 'Huawei', '048758': 'Huawei',
  '10c61f': 'Huawei', '107b44': 'Huawei', '143ed0': 'Huawei', '18c58a': 'Huawei',
  '202bc1': 'Huawei', '24cba8': 'Huawei', '2c9d1e': 'Huawei', '30d17e': 'Huawei',
  '3c47c8': 'Huawei', '40cb20': 'Huawei', '441ca8': 'Huawei', '488710': 'Huawei',
  '4c1fcc': 'Huawei', '58605f': 'Huawei', '5c4cca': 'Huawei', '5c8a8e': 'Huawei',
  '6045cb': 'Huawei', '6c4b90': 'Huawei', '6c8d12': 'Huawei', '706655': 'Huawei',
  '70723c': 'Huawei', '74a528': 'Huawei', '78f557': 'Huawei', '7c3984': 'Huawei',
  '8ce748': 'Huawei', '900748': 'Huawei', '904e2b': 'Huawei', '9419d2': 'Huawei',
  '9cb286': 'Huawei', 'a04e0f': 'Huawei', 'a468bc': 'Huawei', 'a8ca89': 'Huawei',
  'ac64dd': 'Huawei', 'b4430d': 'Huawei', 'bc7670': 'Huawei', 'c007c8': 'Huawei',
  'c4073b': 'Huawei', 'c8d15e': 'Huawei', 'cc53b5': 'Huawei', 'd00fe0': 'Huawei',
  'd4614f': 'Huawei', 'd46a6a': 'Huawei', 'dc724c': 'Huawei', 'e0247f': 'Huawei',
  'e8088b': 'Huawei', 'f0b9b7': 'Huawei', 'f43b5b': 'Huawei', 'f80113': 'Huawei',
  'f87288': 'Huawei', 'fc3f7c': 'Huawei',
  // OnePlus
  '001e43': 'OnePlus', '041355': 'OnePlus', '2c54cf': 'OnePlus', '40cb02': 'OnePlus',
  '4812d7': 'OnePlus', '4c54a0': 'OnePlus', '789682': 'OnePlus', '8891d0': 'OnePlus',
  '94652d': 'OnePlus', 'c4de5f': 'OnePlus',
  // Motorola
  '00134a': 'Motorola', '001a3f': 'Motorola', '001b4f': 'Motorola', '001c1a': 'Motorola',
  '0026e9': 'Motorola', '040cc2': 'Motorola', '108f20': 'Motorola', '1c2c64': 'Motorola',
  '3476c5': 'Motorola', '34d2c4': 'Motorola', '3c22fb': 'Motorola', '4480eb': 'Motorola',
  '488a3c': 'Motorola', '58c8a7': 'Motorola', '606060': 'Motorola', '6c4052': 'Motorola',
  '7c32a5': 'Motorola', '84dd20': 'Motorola', '8c49c2': 'Motorola', '8c77a5': 'Motorola',
  '90e695': 'Motorola', '9c4fe0': 'Motorola', 'ac37a4': 'Motorola', 'b8701a': 'Motorola',
  'bc764e': 'Motorola', 'c0ee40': 'Motorola', 'd0176a': 'Motorola', 'e47cf9': 'Motorola',
  // Note: d0176a is Motorola (confirmed); Samsung entry removed
  'ec58ea': 'Motorola',
  // Sony
  '0013a9': 'Sony', '001a80': 'Sony', '001d0d': 'Sony', '00d9d1': 'Sony',
  '10a5d0': 'Sony', '1c98c1': 'Sony', '28385a': 'Sony', '2cb033': 'Sony',
  '2cfd08': 'Sony', '3023f3': 'Sony', '3058af': 'Sony', '308730': 'Sony',
  '34c337': 'Sony', '40b0fa': 'Sony', '4c0f6e': 'Sony', '54a259': 'Sony',
  '602ad0': 'Sony', '6c5481': 'Sony', '74bdb8': 'Sony', '78843c': 'Sony',
  '80b8fa': 'Sony', '84c7e9': 'Sony', '8c6425': 'Sony', '90a96c': 'Sony',
  '98024c': 'Sony', 'a062fb': 'Sony', 'a0c589': 'Sony', 'b8c75d': 'Sony',
  'cc3f98': 'Sony', 'd0271e': 'Sony', 'd4517a': 'Sony', 'dc085e': 'Sony',
  'e0e2e6': 'Sony', 'f0b6e1': 'Sony',
  // LG
  '001e75': 'LG', '001ffb': 'LG', '0021fb': 'LG', '002688': 'LG',
  '00d0e5': 'LG', '10f96f': 'LG', '1835d1': 'LG', '24f5aa': 'LG',
  '3c8bfe': 'LG', '48597e': 'LG', '4cbca5': 'LG', '54723d': 'LG',
  // Note: 001e75 and 3c8bfe are LG; Samsung entries removed
  '60dea4': 'LG', '6cbdf8': 'LG', '78a882': 'LG', '7ce905': 'LG',
  '8008f4': 'LG', '88e87f': 'LG', '98c9a7': 'LG', 'a834d9': 'LG',
  'b4a7c6': 'LG', 'c4438f': 'LG', 'c8f660': 'LG', 'd8b377': 'LG',
  'e8f2e2': 'LG', 'f8a9d0': 'LG',
  // Amazon (Echo, Kindle, Fire TV)
  '0c9640': 'Amazon', '1c12b0': 'Amazon', '34d270': 'Amazon',
  '3c30aa': 'Amazon', '40b4cd': 'Amazon', '44650d': 'Amazon', '488d36': 'Amazon',
  '4c4fea': 'Amazon', '68a3c4': 'Amazon', '74c246': 'Amazon', '788ee1': 'Amazon',
  '843836': 'Amazon', '8cf9c1': 'Amazon', 'a002dc': 'Amazon', 'a4088b': 'Amazon',
  'ac63be': 'Amazon', 'b47c9c': 'Amazon', 'b820b3': 'Amazon', 'cc9e00': 'Amazon',
  'f0272d': 'Amazon', 'f0f061': 'Amazon', 'f4f1e1': 'Amazon', 'fc65de': 'Amazon',
  // Espressif (ESP32/ESP8266 — IoT)
  '10521c': 'Espressif', '18fe34': 'Espressif', '240ac4': 'Espressif',
  '2462ab': 'Espressif', '3c71bf': 'Espressif', '3ce90e': 'Espressif',
  '40f520': 'Espressif', '4c11ae': 'Espressif', '4ceb48': 'Espressif',
  '54b5a7': 'Espressif', '5c5f67': 'Espressif', '60019f': 'Espressif',
  '68c63a': 'Espressif', '6c29aa': 'Espressif', '7cdfa1': 'Espressif',
  '84f3eb': 'Espressif', '8caab5': 'Espressif', '94b97e': 'Espressif',
  '9897d5': 'Espressif', 'a02082': 'Espressif', 'a42044': 'Espressif',
  'a4cf12': 'Espressif', 'a8032a': 'Espressif', 'ac67b2': 'Espressif',
  'b0a732': 'Espressif', 'b4e62d': 'Espressif', 'bc971e': 'Espressif',
  'bcddc2': 'Espressif', 'c44f33': 'Espressif', 'c8c9a3': 'Espressif',
  'ccba97': 'Espressif', 'd24e4f': 'Espressif', 'd8bfc0': 'Espressif',
  'e007f4': 'Espressif', 'e89f6d': 'Espressif',
  'ec622c': 'Espressif', 'f0f5bd': 'Espressif', 'f4cfa2': 'Espressif',
  // Shelly
  'c45bbe': 'Shelly', '3494b4': 'Shelly', '8ca2f4': 'Shelly',
  // Sonos
  '000e58': 'Sonos', '5caafd': 'Sonos', '94b474': 'Sonos', 'b8e937': 'Sonos',
  'f0f6c1': 'Sonos',
  // Philips Hue / Signify
  '001788': 'Philips Hue', '0017e2': 'Philips Hue', 'ecb5fa': 'Philips Hue',
  'f0d2f1': 'Philips Hue',
  // TP-Link
  '000c43': 'TP-Link', '001d0f': 'TP-Link', '10feed': 'TP-Link', '1c3bde': 'TP-Link',
  '1c61b4': 'TP-Link', '2046ad': 'TP-Link', '286285': 'TP-Link', '2cb43a': 'TP-Link',
  '302303': 'TP-Link', '34fdc4': 'TP-Link', '3c529d': 'TP-Link', '3c84af': 'TP-Link',
  '40ed00': 'TP-Link', '44285e': 'TP-Link', '486e73': 'TP-Link',
  '50c7bf': 'TP-Link', '54e6fc': 'TP-Link', '60e327': 'TP-Link', '6466b3': 'TP-Link',
  '68ff7b': 'TP-Link', '74da38': 'TP-Link', '78d2be': 'TP-Link',
  '844716': 'TP-Link', '90f65c': 'TP-Link', '98daed': 'TP-Link', 'a00460': 'TP-Link',
  'a0f3c1': 'TP-Link', 'b0487a': 'TP-Link', 'b08c75': 'TP-Link', 'b4b024': 'TP-Link',
  'c46e1f': 'TP-Link', 'cc32e5': 'TP-Link', 'd84d49': 'TP-Link', 'e012d7': 'TP-Link',
  'ec172f': 'TP-Link', 'ecd908': 'TP-Link', 'f0a731': 'TP-Link', 'f81a67': 'TP-Link',
  'fc7516': 'TP-Link',
  // Netgear
  '001b2f': 'Netgear', '002275': 'Netgear', '00265a': 'Netgear', '20e52a': 'Netgear',
  '28c68e': 'Netgear', '2c3033': 'Netgear', '44940c': 'Netgear', '48ef29': 'Netgear',
  '4cdf45': 'Netgear', '60383e': 'Netgear', '6cb0ce': 'Netgear', '9c3426': 'Netgear',
  'a040a0': 'Netgear', 'b03986': 'Netgear', 'c03f0e': 'Netgear', 'c04a00': 'Netgear',
  'c80cc8': 'Netgear',
  // Cudy (your routers!)
  '34298f': 'Cudy', '681d21': 'Cudy', '9c9d7e': 'Cudy',
};

/** Look up manufacturer from MAC address OUI (first 3 octets). */
function lookupManufacturer(mac: string): string | undefined {
  if (!mac) return undefined;
  // Normalize: strip separators, lowercase, take first 6 chars
  const oui = mac.toLowerCase().replace(/[:\-\.]/g, '').slice(0, 6);
  return OUI_TABLE[oui];
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

// ── VLAN subnet matching ─────────────────────────────────────────────────

function ipToNum(ip: string): number {
  const p = ip.split('.').map(Number);
  return (((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0);
}

function ipInSubnet(ip: string, gatewayIp: string, prefix: number): boolean {
  if (!ip || !gatewayIp || prefix <= 0) return false;
  const mask = prefix >= 32 ? 0xffffffff : (~0 << (32 - prefix)) >>> 0;
  return (ipToNum(ip) & mask) === (ipToNum(gatewayIp) & mask);
}

/** Return the VLAN ID for a client IP, or null if no match. */
function matchVlan(ip: string, vlans: import('./types').VlanInfo[]): number | null {
  if (!ip) return null;
  for (const v of vlans) {
    if (v.ipv4 && v.prefix != null && ipInSubnet(ip, v.ipv4, v.prefix)) return v.id;
  }
  return null;
}

/** Return the most-common VLAN ID among a list of vlanIds (null = unknown). */
function primaryVlan(vlanIds: (number | null | undefined)[]): number | undefined {
  const counts = new Map<number, number>();
  for (const id of vlanIds) {
    if (id != null) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  if (!counts.size) return undefined;
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
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

  const gwAttr = gwNode.attributes ?? {};
  const gateway: Gateway = {
    id: gwNode.id,
    name: gwNode.label,
    model: gwAttr.model ?? '',
    ip: gwAttr.host_ip ?? '',
    wanIp: gwNode.ip ?? '',
    uptime: gwAttr.uptime != null ? formatUptime(gwAttr.uptime as number) : '',
    status: 'online',
    firmwareVersion: (gwAttr.firmware as string | undefined) || undefined,
    cpuLoad: gwAttr.cpu_load as number | undefined,
    memUsage: gwAttr.mem_usage as number | undefined,
    dslStats: gwAttr.dsl_stats as DslStats | undefined,
    pingMs: gwAttr.ping_ms as number | null | undefined,
    dslHistory: (gwAttr.dsl_history as DslHistoryPoint[] | undefined) ?? [],
    ddnsServices: (gwAttr.ddns_status as DdnsService[] | undefined) ?? [],
    wanTraffic: gwAttr.wan_traffic as { downstream_bps?: number; upstream_bps?: number } | undefined,
    portStats: (gwAttr.port_stats as PortStat[] | undefined) ?? [],
    vlans: ((gwAttr.vlans as any[] | undefined) ?? []).map((v: any): VlanInfo => ({
      id: v.id,
      interface: v.interface,
      status: v.status ?? 'unknown',
      ipv4: v.ipv4_addr ?? undefined,
      prefix: v.prefix_len ?? undefined,
    })),
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

  // Build ssids per router: has_interface edges → interface nodes with ssid+band
  const ssidsByRouter = new Map<string, SsidInfo[]>();
  const ifaceNodes = snap.nodes.filter((n) => n.type === 'interface');
  const ifaceById = new Map(ifaceNodes.map((n) => [n.id, n]));
  for (const edge of snap.edges) {
    if (edge.relationship !== 'has_interface') continue;
    const iface = ifaceById.get(edge.to);
    if (!iface) continue;
    const ssid = iface.attributes?.ssid as string | undefined;
    const band = iface.attributes?.band as string | undefined;
    const channel = iface.attributes?.channel as number | undefined;
    if (!ssid) continue;
    const list = ssidsByRouter.get(edge.from) ?? [];
    const formattedBand = band ? formatBand(band) : '';
    if (!list.find((s) => s.ssid === ssid && s.band === formattedBand)) {
      list.push({ ssid, band: formattedBand, channel });
    }
    ssidsByRouter.set(edge.from, list);
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
      firmwareVersion: (n.attributes?.firmware as string | undefined) || undefined,
      ssids: ssidsByRouter.get(n.id) ?? [],
      cpuLoad: n.attributes?.cpu_load as number | undefined,
      memUsage: n.attributes?.mem_usage as number | undefined,
    };
  });

  // Also extract SSIDs for gateway
  const gatewaySsids = ssidsByRouter.get(gwNode.id) ?? [];
  gateway.ssids = gatewaySsids.length > 0 ? gatewaySsids : undefined;

  // Build client list from client nodes
  const clients: Client[] = clientNodes.map((n) => {
    const attr = n.attributes;
    const signal = attr?.signal as number | null | undefined;
    const hostname = (attr?.hostname as string) || n.label || (attr?.mac as string) || '';
    const apId = (attr?.ap_mac as string) ?? gwNode.id;

    const connectedSince = attr?.connected_since as number | undefined;
    const dhcpExpires = attr?.dhcp_expires as number | undefined;
    const rawBand = (attr?.band as string) ?? '';

    const mac = (attr?.mac as string) ?? '';
    return {
      id: n.id,
      name: hostname,
      hostname,
      ip: (attr?.ip as string) ?? '',
      mac,
      apId,
      category: guessCategory(hostname, attr?.ssid as string | undefined),
      signal: signal ?? -65,
      band: rawBand ? formatBand(rawBand) : '',
      status: signalStatus(signal),
      manufacturer: lookupManufacturer(mac),
      connectedSince: connectedSince && connectedSince > 0 ? connectedSince : undefined,
      dhcpExpires: dhcpExpires && dhcpExpires > 0 ? dhcpExpires : undefined,
      rxBytes: attr?.rx_bytes as number | null | undefined,
      txBytes: attr?.tx_bytes as number | null | undefined,
      vlanId: matchVlan((attr?.ip as string) ?? '', gateway.vlans ?? []) ?? undefined,
    };
  });

  // Assign primaryVlanId to APs now that clients are available
  for (const ap of accessPoints) {
    const apClients = clients.filter(c => c.apId === ap.id);
    ap.primaryVlanId = primaryVlan(apClients.map(c => c.vlanId ?? null));
  }

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
