import React, { useState } from 'react';
import type { PortStat } from '../types';

const VLAN_COLORS = [
  '#3b82f6', '#22c55e', '#f59e0b', '#8b5cf6',
  '#ef4444', '#eab308', '#14b8a6',
];

function vlanColor(vlanId: number): string {
  return VLAN_COLORS[vlanId % VLAN_COLORS.length];
}

interface Props {
  ports: PortStat[];
  vlanMode?: boolean;
}

function shortName(name: string): string {
  // lan1 → L1, lan2 → L2, wan → WAN, eth0 → E0
  const m = name.match(/^(lan|eth|ge|fe)(\d+)$/i);
  if (m) return m[1][0].toUpperCase() + m[2];
  if (/^wan\d*$/i.test(name)) return 'WAN';
  if (name.length <= 4) return name.toUpperCase();
  return name.slice(0, 4).toUpperCase();
}

function speedLabel(mbps: number | null, up: boolean): string {
  if (!up || mbps == null) return '';
  if (mbps >= 2500) return '2.5G';
  if (mbps >= 1000) return '1G';
  if (mbps >= 100)  return '100M';
  if (mbps >= 10)   return '10M';
  return `${mbps}M`;
}

function portTypeClass(name: string): string {
  if (/^wan\d*$/i.test(name)) return 'port-strip__port--wan';
  if (/^sfp\d*$/i.test(name)) return 'port-strip__port--sfp';
  return 'port-strip__port--lan';
}

function isPhysicalPort(name: string): boolean {
  // Only WAN and numbered LAN/ETH ports — skip phy*, wg*, br-*, loopback, etc.
  return /^(wan\d*|lan\d+|eth\d+(\.\d+)?|ge-\d|fe-\d)$/i.test(name);
}

export function PortStrip({ ports, vlanMode }: Props) {
  if (!ports || ports.length === 0) return null;
  const physical = ports.filter((p) => isPhysicalPort(p.name));
  if (physical.length === 0) return null;

  return (
    <div className="port-strip">
      {physical.map((p) => (
        <PortChip key={p.name} port={p} vlanMode={vlanMode} />
      ))}
    </div>
  );
}

function PortChip({ port: p, vlanMode }: { port: PortStat; vlanMode?: boolean }) {
  const [showTooltip, setShowTooltip] = useState(false);

  const primaryVlan = (p.vlanIds ?? []).length > 0 ? p.vlanIds![0] : undefined;
  const hasVlanColor = primaryVlan != null;

  const cls = [
    'port-strip__port',
    p.up ? 'port-strip__port--up' : '',
    portTypeClass(p.name),
    hasVlanColor ? 'port-strip__port--vlan-colored' : '',
  ].filter(Boolean).join(' ');

  const vlanStyle = hasVlanColor
    ? ({ '--port-vlan-color': vlanColor(primaryVlan!) } as React.CSSProperties)
    : undefined;

  const linkDesc = p.up
    ? [p.speed_mbps ? `${p.speed_mbps} Mbps` : 'up', p.duplex ?? ''].filter(Boolean).join(' ')
    : 'no link';

  return (
    <div
      className={cls}
      style={vlanStyle}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <div className="port-strip__led" />
      <span className="port-strip__name">{shortName(p.name)}</span>
      {p.up && p.speed_mbps != null && (
        <span className="port-strip__speed">{speedLabel(p.speed_mbps, p.up)}</span>
      )}
      {showTooltip && (
        <div className="port-tooltip">
          <div className="port-tooltip__name">{p.name}</div>
          <div className="port-tooltip__meta">{linkDesc}</div>
          {(p.vlanIds ?? []).length > 0 && (
            <div className="port-tooltip__meta">
              VLAN: {p.vlanIds!.join(', ')}
            </div>
          )}
          {p.connectedDevice && (
            <div className="port-tooltip__meta" style={{ color: '#93c5fd' }}>
              → {p.connectedDevice}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
