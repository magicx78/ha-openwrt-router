import React from 'react';
import { AccessPoint, Client } from '../types';
import { StatusDot } from './StatusDot';
import { IconAP } from './Icons';
import { SignalBar } from './SignalBar';

interface Props {
  ap: AccessPoint;
  clients: Client[];
  selected: boolean;
  dimmed: boolean;
  onSelect: () => void;
  onHover: (id: string | null) => void;
  heatmap?: boolean;
}

function avgSignalDbm(clients: Client[]): number | null {
  const sigs = clients.map(c => c.signal).filter(s => s != null && s !== 0) as number[];
  if (!sigs.length) return null;
  return Math.round(sigs.reduce((a, b) => a + b, 0) / sigs.length);
}

function heatmapGlow(dbm: number | null, uplinkSignal: number): string {
  const sig = dbm ?? uplinkSignal;
  if (sig >= -65) return '0 0 14px 4px rgba(34,197,94,0.45)';   // green
  if (sig >= -75) return '0 0 14px 4px rgba(134,239,172,0.35)'; // light green
  if (sig >= -80) return '0 0 14px 4px rgba(245,158,11,0.40)';  // amber
  return '0 0 14px 4px rgba(239,68,68,0.40)';                   // red
}

function bandClass(band: string): string {
  if (band.includes('6')) return 'ssid-badge--6g';
  if (band.includes('5')) return 'ssid-badge--5g';
  return 'ssid-badge--24g';
}

export function APNode({ ap, clients, selected, dimmed, onSelect, onHover, heatmap }: Props) {
  const statusClass = ap.status === 'online'
    ? 'status-online'
    : ap.status === 'warning'
      ? 'status-warning'
      : 'status-offline';

  const iconCls = ap.status === 'offline'
    ? 'offline'
    : ap.status === 'warning'
      ? 'warning'
      : ap.uplinkType;

  const avg = ap.status !== 'offline' ? avgSignalDbm(clients) : null;

  const glowStyle = heatmap && ap.status !== 'offline'
    ? { boxShadow: heatmapGlow(avg, ap.backhaulSignal) }
    : undefined;

  const cls = [
    'node-card ap-card',
    statusClass,
    selected ? 'selected' : '',
    dimmed ? 'dimmed' : '',
  ].filter(Boolean).join(' ');

  return (
    <div
      className={cls}
      style={glowStyle}
      onClick={onSelect}
      onMouseEnter={() => onHover(ap.id)}
      onMouseLeave={() => onHover(null)}
    >
      <div className="ap-card__header">
        <div className={`ap-card__icon ${iconCls}`}>
          <IconAP size={16} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="ap-card__name">{ap.name}</div>
          <div className="ap-card__ip">{ap.ip}</div>
        </div>
        <StatusDot status={ap.status} />
      </div>

      <div className="ap-card__footer">
        <span className={`ap-card__badge ${ap.uplinkType}`}>
          {ap.uplinkType === 'wired' ? 'Kabel' : 'Mesh'}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {ap.status !== 'offline' && <SignalBar dbm={ap.backhaulSignal} />}
          <span className="ap-card__clients">
            <strong>{ap.clientCount}</strong> Clients
          </span>
        </div>
      </div>

      {/* SSID badges */}
      {ap.ssids && ap.ssids.length > 0 && (
        <div className="ap-card__ssids">
          {ap.ssids.slice(0, 4).map((s, i) => (
            <span key={i} className={`ssid-badge ${bandClass(s.band)}`}>
              {s.band && <span className="ssid-badge__band">{s.band}</span>}
              <span className="ssid-badge__name">{s.ssid}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
