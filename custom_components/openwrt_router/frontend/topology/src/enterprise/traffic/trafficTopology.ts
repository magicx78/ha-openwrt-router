/**
 * trafficTopology.ts — Traffic Analytics values on the topology.
 *
 * The backend adds `attributes.traffic` to router nodes and router-uplink
 * edges only while Traffic Analytics runs (traffic_topology.py); without
 * it these parsers return undefined and the topology renders exactly as
 * before. Pure functions: parse, and the rows the detail panel and the
 * edge tooltip show. Unknown is "—" with its reason, never 0; rx and tx
 * are never added up. No React, no network.
 */

import { formatBitRate } from '../../utils/format.ts';

const DASH = '—';

export interface TopoRate {
  rxBps: number | null;
  txBps: number | null;
  downBps: number | null;
  upBps: number | null;
  coverage: string | null;
  utilizationPct: number | null;
  utilizationReason: string | null;
  linkMbps: number | null;
}

export interface RouterTraffic {
  state: 'available' | 'unavailable';
  reason: string | null;
  wan: TopoRate | null;
  wanPoints: number;
  ports: Record<string, TopoRate>;
}

export interface UplinkTraffic {
  fromPort: TopoRate | null;
  fromReason: string | null;
  toPort: TopoRate | null;
  toReason: string | null;
}

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null);
const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const s = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);

function rate(v: unknown): TopoRate | null {
  const o = obj(v);
  if (!o) return null;
  return {
    rxBps: n(o.rx_bps), txBps: n(o.tx_bps), downBps: n(o.down_bps), upBps: n(o.up_bps), coverage: s(o.coverage),
    utilizationPct: n(o.utilization_pct), utilizationReason: s(o.utilization_reason), linkMbps: n(o.link_mbps),
  };
}

/** `attributes.traffic` of a router node; undefined while the module is off. */
export function parseRouterTraffic(attrs: unknown): RouterTraffic | undefined {
  const t = obj(obj(attrs)?.traffic);
  if (!t) return undefined;
  const ports: Record<string, TopoRate> = {};
  const raw = obj(t.ports) ?? {};
  for (const [name, value] of Object.entries(raw).slice(0, 32)) {
    const r = rate(value);
    if (r) ports[name] = r;
  }
  return {
    state: t.state === 'available' ? 'available' : 'unavailable',
    reason: s(t.reason),
    wan: rate(t.wan),
    wanPoints: n(t.wan_points) ?? 0,
    ports,
  };
}

/** `attributes.traffic` of a router-uplink edge; undefined while the module is off. */
export function parseUplinkTraffic(attrs: unknown): UplinkTraffic | undefined {
  const t = obj(obj(attrs)?.traffic);
  if (!t) return undefined;
  return { fromPort: rate(t.from_port), fromReason: s(t.from_port_reason), toPort: rate(t.to_port), toReason: s(t.to_port_reason) };
}

const REASON: Record<string, string> = {
  router_not_measured: 'Router nicht erfasst',
  port_not_measured: 'Port nicht erfasst',
  link_speed_unknown: 'Link-Geschwindigkeit unbekannt',
  no_rate_yet: 'noch keine Rate',
};
const reason = (r: string | null): string => (r ? REASON[r] ?? 'nicht erfasst' : 'nicht erfasst');

const COVERAGE: Record<string, string> = {
  full: 'vollständig', partial: 'teilweise', estimated: 'geschätzt', unavailable: 'nicht verfügbar', unknown: 'unbekannt',
};

/** "12,0 Mbit/s ↓ · 1,0 Mbit/s ↑" or "rx … · tx …" when the direction is not nameable. */
export function rateText(r: TopoRate): string {
  if (r.downBps !== null || r.upBps !== null) return `${formatBitRate(r.downBps)} ↓ · ${formatBitRate(r.upBps)} ↑`;
  return `rx ${formatBitRate(r.rxBps)} · tx ${formatBitRate(r.txBps)}`;
}

function portText(r: TopoRate): string {
  const load = r.utilizationPct !== null
    ? ` · ${r.utilizationPct.toLocaleString('de-DE', { maximumFractionDigits: 1 })} % Last`
    : r.utilizationReason ? ` · Last ${DASH} ${reason(r.utilizationReason)}` : '';
  return `${rateText(r)}${load}`;
}

export interface Row { label: string; value: string }

/** Rows of the detail panel for one router. */
export function routerTrafficRows(t: RouterTraffic | undefined): Row[] {
  if (!t) return [];
  if (t.state !== 'available') return [{ label: 'Traffic', value: `${DASH} ${reason(t.reason)}` }];
  const rows: Row[] = [];
  rows.push({
    label: 'WAN',
    value: t.wan ? `${rateText(t.wan)}${t.wan.coverage ? ` (Abdeckung ${COVERAGE[t.wan.coverage] ?? t.wan.coverage})` : ''}`
      : t.wanPoints > 1 ? `${t.wanPoints} WAN-Messpunkte (siehe Traffic Analytics)` : `${DASH} kein WAN-Messpunkt`,
  });
  for (const [name, r] of Object.entries(t.ports)) rows.push({ label: name.toUpperCase(), value: portText(r) });
  return rows;
}

/** Rows of the edge tooltip for one router uplink. */
export function uplinkTrafficRows(t: UplinkTraffic | undefined): Row[] {
  if (!t) return [];
  return [
    { label: 'Traffic oben', value: t.fromPort ? portText(t.fromPort) : `${DASH} ${reason(t.fromReason)}` },
    { label: 'Traffic unten', value: t.toPort ? portText(t.toPort) : `${DASH} ${reason(t.toReason)}` },
  ];
}
