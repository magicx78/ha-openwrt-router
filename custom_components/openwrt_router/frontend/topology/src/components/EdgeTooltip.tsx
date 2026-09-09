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
    }
    if (data.gateway.wanIp) rows.push({ label: 'WAN IP', value: data.gateway.wanIp });

  } else if (edge.kind === 'gateway-wired') {
    const ap = data.accessPoints.find(a => a.id === edge.targetId);
    title  = ap?.name ?? 'Access Point';

    if (ap?.uplinkType === 'repeater') {
      badge    = 'WLAN Repeater';
      badgeMod = 'repeater';
      if (ap.backhaulSignal) rows.push({ label: 'Signal', value: `${ap.backhaulSignal} dBm` });
    } else if (ap?.uplinkType === 'mesh') {
      badge    = 'Mesh?';
      badgeMod = 'mesh';
      if (ap.backhaulSignal) rows.push({ label: 'Signal', value: `${ap.backhaulSignal} dBm` });
    } else {
      badge    = 'LAN-Kabel';
      badgeMod = 'wired';

      // Trunk port connection details
      if (ap?.gatewayPort) {
        const speed = ap.gatewayPortSpeed
          ? (ap.gatewayPortSpeed >= 1000 ? `${ap.gatewayPortSpeed / 1000}G` : `${ap.gatewayPortSpeed}M`)
          : null;
        const gwPortLabel = speed ? `${ap.gatewayPort.toUpperCase()} · ${speed}` : ap.gatewayPort.toUpperCase();
        rows.push({ label: 'GW-Port',  value: gwPortLabel });
      }
      if (ap?.apPort) {
        rows.push({ label: 'AP-Port', value: ap.apPort.toUpperCase() });
      }
      if (ap?.vlanTags && ap.vlanTags.length > 0) {
        rows.push({
          label: 'VLAN',
          value: ap.vlanTags.length > 1
            ? `Trunk ${ap.vlanTags.join(', ')}`
            : `${ap.vlanTags[0]}`,
        });
      }
    }
    rows.push({ label: 'Clients', value: String(ap?.clientCount ?? 0) });
    if (ap?.ip)     rows.push({ label: 'IP',     value: ap.ip });
    if (ap?.status) rows.push({ label: 'Status', value: ap.status });

  } else if (edge.kind === 'router-uplink') {
    const ap = data.accessPoints.find(a => a.id === edge.targetId);
    const lldp = edge.lldp;
    title    = lldp?.neighborName || ap?.name || 'Router-Uplink';
    badge    = 'LLDP';
    badgeMod = 'lldp';

    if (lldp?.neighborName)   rows.push({ label: 'Nachbar', value: lldp.neighborName });
    if (lldp?.managementIp)   rows.push({ label: 'Management-IP', value: lldp.managementIp });
    const localPort = edge.fromPort ?? lldp?.fromPort;
    const remotePort = edge.toPort ?? lldp?.toPort;
    if (localPort || remotePort) {
      rows.push({
        label: 'Port',
        value: `${(localPort ?? '?').toUpperCase()} ↔ ${(remotePort ?? '?').toUpperCase()}`,
      });
    }
    if (lldp?.neighborMac)        rows.push({ label: 'Nachbar-MAC', value: lldp.neighborMac });
    else if (lldp?.neighborChassisId) rows.push({ label: 'Chassis-ID', value: lldp.neighborChassisId });
    const vlans = lldp?.vlanTags ?? edge.vlanTags;
    if (vlans && vlans.length > 0) {
      rows.push({ label: 'VLAN', value: vlans.length > 1 ? `Trunk ${vlans.join(', ')}` : `${vlans[0]}` });
    }
    rows.push({ label: 'Verbindung', value: (lldp?.linkType ?? 'lldp').toUpperCase() });
    if (lldp?.confidence) rows.push({ label: 'Vertrauen', value: lldp.confidence });
    if (lldp?.direction)  rows.push({ label: 'Richtung', value: lldp.direction === 'one_way' ? 'einseitig' : 'beidseitig' });
    if (lldp?.capabilities && lldp.capabilities.length > 0) {
      rows.push({ label: 'Rolle', value: lldp.capabilities.join(', ') });
    }
    if ((lldp?.conflicts?.length ?? 0) > 0) {
      rows.push({ label: '⚠ Konflikt', value: 'LLDP-Port weicht von Bridge-FDB ab' });
    }
    if (ap?.clientCount != null) rows.push({ label: 'Clients', value: String(ap.clientCount) });

  } else {
    // ap-mesh (parent-AP → child-AP edge)
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
