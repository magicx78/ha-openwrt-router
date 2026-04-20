/**
 * EdgeTooltip — fixed-position overlay shown when hovering over a topology edge.
 * Displays link type, signal, client count, and traffic info per edge kind.
 */

import React from 'react';
import { EdgeLayout, TopologyData } from '../types';

interface Props {
  edgeId: string;
  x: number;
  y: number;
  edges: EdgeLayout[];
  data: TopologyData;
}

/** Convert bytes/s to human-readable bit rate. */
function fmtBps(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(1)} Mbit/s`;
  if (bits >= 1_000)     return `${(bits / 1_000).toFixed(0)} kbit/s`;
  return `${bits} bit/s`;
}

export function EdgeTooltip({ edgeId, x, y, edges, data }: Props) {
  const edge = edges.find(e => e.id === edgeId);
  if (!edge) return null;

  // ── Content per edge kind ────────────────────────────────────────────────

  let title = '';
  let badge = '';
  let badgeMod = '';
  const rows: { label: string; value: string }[] = [];

  if (edge.kind === 'internet') {
    title  = 'Internet';
    badge  = 'WAN';
    badgeMod = 'internet';

    const wt = data.gateway.wanTraffic;
    if (wt && (wt.downstream_bps || wt.upstream_bps)) {
      rows.push({ label: '↓', value: fmtBps(wt.downstream_bps ?? 0) });
      rows.push({ label: '↑', value: fmtBps(wt.upstream_bps   ?? 0) });
    } else if (data.gateway.dslStats) {
      const ds = data.gateway.dslStats;
      rows.push({ label: '↓ Sync', value: `${(ds.downstream_kbps / 1000).toFixed(1)} Mbit/s` });
      rows.push({ label: '↑ Sync', value: `${(ds.upstream_kbps   / 1000).toFixed(1)} Mbit/s` });
      if (ds.snr_down_db) rows.push({ label: 'SNR ↓', value: `${ds.snr_down_db} dB` });
    }
    if (data.gateway.wanIp) rows.push({ label: 'WAN IP', value: data.gateway.wanIp });

  } else if (edge.kind === 'gateway-wired') {
    const ap = data.accessPoints.find(a => a.id === edge.targetId);
    title  = ap?.name ?? 'Access Point';
    badge  = 'LAN-Kabel';
    badgeMod = 'wired';

    // Trunk port connection details
    if (ap?.gatewayPort) {
      const speed = ap.gatewayPortSpeed
        ? (ap.gatewayPortSpeed >= 1000 ? `${ap.gatewayPortSpeed / 1000}G` : `${ap.gatewayPortSpeed}M`)
        : null;
      const gwPortLabel = speed ? `${ap.gatewayPort.toUpperCase()} · ${speed}` : ap.gatewayPort.toUpperCase();
      rows.push({ label: 'GW-Port',  value: gwPortLabel });
      rows.push({ label: 'AP-Port',  value: 'WAN · Trunk' });
    }
    rows.push({ label: 'Clients', value: String(ap?.clientCount ?? 0) });
    if (ap?.ip)     rows.push({ label: 'IP',     value: ap.ip });
    if (ap?.status) rows.push({ label: 'Status', value: ap.status });

  } else {
    // ap-mesh
    const ap = data.accessPoints.find(a => a.id === edge.targetId);
    title  = ap?.name ?? 'Access Point';
    badge  = 'WiFi Mesh';
    badgeMod = 'mesh';

    if (ap?.backhaulSignal) rows.push({ label: 'Signal', value: `${ap.backhaulSignal} dBm` });
    rows.push({ label: 'Clients', value: String(ap?.clientCount ?? 0) });
    if (ap?.ip) rows.push({ label: 'IP', value: ap.ip });
  }

  // ── Position: offset so tooltip doesn't sit under the cursor ────────────
  // Nudge left if near right edge (rough estimate: 200px tooltip width)
  const OFFSET_X = 14;
  const OFFSET_Y = -8;

  const style: React.CSSProperties = {
    position: 'fixed',
    left: x + OFFSET_X,
    top:  y + OFFSET_Y,
    pointerEvents: 'none',
    zIndex: 9998,
  };

  return (
    <div className={`edge-tooltip edge-tooltip--${badgeMod}`} style={style}>
      <div className="edge-tooltip__header">
        <span className="edge-tooltip__title">{title}</span>
        <span className={`edge-tooltip__badge edge-tooltip__badge--${badgeMod}`}>{badge}</span>
      </div>
      {rows.length > 0 && (
        <div className="edge-tooltip__rows">
          {rows.map((r, i) => (
            <div key={i} className="edge-tooltip__row">
              <span className="edge-tooltip__label">{r.label}</span>
              <span className="edge-tooltip__value">{r.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
