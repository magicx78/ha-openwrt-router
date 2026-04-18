import React from 'react';
import { TopologyData } from '../types';

interface Props {
  nodeId: string;
  data: TopologyData;
  anchorRect: DOMRect;  // bounding box of the hovered node element
}

function Row({ label, value, warn }: { label: string; value: string | number; warn?: boolean }) {
  return (
    <div className="node-tooltip__row">
      <span className="node-tooltip__label">{label}</span>
      <span className={`node-tooltip__value${warn ? ' warn' : ''}`}>{value}</span>
    </div>
  );
}

function signalClass(dbm: number): string {
  if (dbm >= -65) return 'good';
  if (dbm >= -75) return 'warn';
  return 'bad';
}

export function NodeTooltip({ nodeId, data, anchorRect }: Props) {
  // Position tooltip to the right of the node, or left if near right edge
  const MARGIN = 8;
  const TOOLTIP_W = 180;
  const vpW = window.innerWidth;
  const rightSpace = vpW - anchorRect.right;
  const left = rightSpace >= TOOLTIP_W + MARGIN * 2
    ? anchorRect.right + MARGIN
    : anchorRect.left - TOOLTIP_W - MARGIN;
  const top = anchorRect.top + anchorRect.height / 2;

  let content: React.ReactNode = null;

  if (nodeId === data.gateway.id) {
    const gw = data.gateway;
    content = (
      <>
        <div className="node-tooltip__title">{gw.name}</div>
        {gw.model && <div className="node-tooltip__subtitle">{gw.model}</div>}
        <div className="node-tooltip__sep" />
        {gw.ip    && <Row label="LAN"    value={gw.ip} />}
        {gw.wanIp && <Row label="WAN"    value={gw.wanIp} />}
        {gw.uptime && <Row label="Uptime" value={gw.uptime} />}
        {gw.cpuLoad != null && (
          <Row label="CPU" value={`${gw.cpuLoad.toFixed(0)}%`} warn={gw.cpuLoad > 80} />
        )}
        {gw.memUsage != null && (
          <Row label="RAM" value={`${gw.memUsage.toFixed(0)}%`} warn={gw.memUsage > 85} />
        )}
        {gw.pingMs != null && gw.pingMs > 0 && (
          <Row label="Ping" value={`${gw.pingMs} ms`} warn={gw.pingMs > 80} />
        )}
        <Row label="Clients" value={data.clients.filter(c => c.apId === gw.id).length} />
      </>
    );
  } else {
    const ap = data.accessPoints.find(a => a.id === nodeId);
    if (!ap) return null;
    const apClients = data.clients.filter(c => c.apId === ap.id);
    const avgSig = apClients.length > 0
      ? Math.round(apClients.reduce((s, c) => s + c.signal, 0) / apClients.length)
      : null;
    content = (
      <>
        <div className="node-tooltip__title">{ap.name}</div>
        {ap.model && <div className="node-tooltip__subtitle">{ap.model}</div>}
        <div className="node-tooltip__sep" />
        {ap.ip && <Row label="IP" value={ap.ip} />}
        <Row label="Uplink" value={ap.uplinkType === 'mesh' ? 'Mesh' : 'Kabel'} />
        {ap.uplinkType === 'mesh' && (
          <Row label="Backhaul" value={`${ap.backhaulSignal} dBm`} warn={ap.backhaulSignal < -75} />
        )}
        {ap.cpuLoad != null && (
          <Row label="CPU" value={`${ap.cpuLoad.toFixed(0)}%`} warn={ap.cpuLoad > 80} />
        )}
        {ap.memUsage != null && (
          <Row label="RAM" value={`${ap.memUsage.toFixed(0)}%`} warn={ap.memUsage > 85} />
        )}
        <Row label="Clients" value={ap.clientCount} />
        {avgSig != null && (
          <Row
            label="Ø Signal"
            value={`${avgSig} dBm`}
            warn={avgSig < -72}
          />
        )}
      </>
    );
  }

  if (!content) return null;

  return (
    <div
      className="node-tooltip"
      style={{ position: 'fixed', left, top, transform: 'translateY(-50%)', zIndex: 9999 }}
    >
      {content}
    </div>
  );
}
