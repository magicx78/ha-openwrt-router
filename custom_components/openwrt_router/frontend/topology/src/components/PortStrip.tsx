import React from 'react';
import { PortStat } from '../types';

interface Props {
  ports: PortStat[];
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

export function PortStrip({ ports }: Props) {
  if (!ports || ports.length === 0) return null;

  return (
    <div className="port-strip">
      {ports.map((p) => (
        <div key={p.name} className={`port-strip__port${p.up ? ' port-strip__port--up' : ''}`} title={`${p.name}: ${p.up ? (p.speed_mbps ? `${p.speed_mbps} Mbps` : 'up') : 'no link'}`}>
          <div className="port-strip__led" />
          <span className="port-strip__name">{shortName(p.name)}</span>
          {p.up && p.speed_mbps != null && (
            <span className="port-strip__speed">{speedLabel(p.speed_mbps, p.up)}</span>
          )}
        </div>
      ))}
    </div>
  );
}
