import React, { useState } from 'react';
import { PortStat } from '../types';

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

export function PortStrip({ ports, vlanMode }: Props) {
  if (!ports || ports.length === 0) return null;

  return (
    <div className="port-strip">
      {ports.map((p) => (
        <PortChip key={p.name} port={p} vlanMode={vlanMode} />
      ))}
    </div>
  );
}

function PortChip({ port: p, vlanMode }: { port: PortStat; vlanMode?: boolean }) {
  const [showTooltip, setShowTooltip] = useState(false);

  const cls = [
    'port-strip__port',
    p.up ? 'port-strip__port--up' : '',
    portTypeClass(p.name),
  ].filter(Boolean).join(' ');

  const linkDesc = p.up
    ? [p.speed_mbps ? `${p.speed_mbps} Mbps` : 'up', p.duplex ?? ''].filter(Boolean).join(' ')
    : 'no link';

  return (
    <div
      className={cls}
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
        </div>
      )}
    </div>
  );
}
