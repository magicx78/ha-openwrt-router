import React, { useState } from 'react';
import type { PortStat, PortDevice } from '../types';
import { vlanColor } from '../utils/vlanColor';

interface Props {
  ports: PortStat[];
  vlanMode?: boolean;
  onSelectPort?: (port: PortStat) => void;
}

export function shortName(name: string): string {
  // lan1 → LAN1, lan2 → LAN2, wan → WAN, eth0 → ETH0
  const m = name.match(/^(lan)(\d+)$/i);
  if (m) return `LAN${m[2]}`;
  if (/^wan\d*$/i.test(name)) return 'WAN';
  if (/^(eth|ge|fe)(\d+)$/i.test(name)) {
    const em = name.match(/^(eth|ge|fe)(\d+)$/i)!;
    return em[1].toUpperCase() + em[2];
  }
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

export function isPhysicalPort(name: string): boolean {
  // Only WAN and numbered LAN ports — skip eth0 (DSA conduit), phy*, wg*, br-*
  return /^(wan\d*|lan\d+)$/i.test(name);
}

export function portSortKey(name: string): number {
  // WAN first, then LAN1, LAN2, LAN3...
  if (/^wan/i.test(name)) return 0;
  const m = name.match(/(\d+)$/);
  return m ? parseInt(m[1]) + 1 : 99;
}

export function isWanPort(p: PortStat): boolean {
  return p.role === 'wan' || /^wan\d*$/i.test(p.name);
}

/** Display label for a device: hostname > IP > MAC > "Unbekannt". */
export function deviceLabel(d: PortDevice | undefined): string {
  if (!d) return 'Unbekannt';
  return d.name || d.ip || d.mac || 'Unbekannt';
}

/** Badge text under the port name — undefined = no badge (legacy snapshot). */
function badgeText(p: PortStat): string | undefined {
  if (p.connectedDevices === undefined) return undefined; // old snapshot
  if (isWanPort(p)) return p.up ? 'Internet' : undefined;
  const count = p.deviceCount ?? p.connectedDevices.length;
  if (count === 0) return p.up ? 'Unbekannt' : undefined;
  if (p.hasDownstreamSwitch && p.primaryDevice?.isRouter) return 'Switch/AP';
  if (count > 1) return `${count} Geräte`;
  return deviceLabel(p.primaryDevice ?? p.connectedDevices[0]);
}

export const CONFIDENCE_LABEL: Record<string, string> = {
  high: 'hoch',
  medium: 'mittel',
  low: 'niedrig',
  none: '—',
};

export function PortStrip({ ports, vlanMode, onSelectPort }: Props) {
  if (!ports || ports.length === 0) return null;
  const physical = ports
    .filter((p) => isPhysicalPort(p.name))
    .sort((a, b) => portSortKey(a.name) - portSortKey(b.name));
  if (physical.length === 0) return null;

  return (
    <div className="port-strip">
      {physical.map((p) => (
        <PortChip key={p.name} port={p} vlanMode={vlanMode} onSelectPort={onSelectPort} />
      ))}
    </div>
  );
}

function PortChip({
  port: p,
  vlanMode,
  onSelectPort,
}: {
  port: PortStat;
  vlanMode?: boolean;
  onSelectPort?: (port: PortStat) => void;
}) {
  const [showTooltip, setShowTooltip] = useState(false);

  const primaryVlan = (p.vlanIds ?? []).length > 0 ? p.vlanIds![0] : undefined;
  const hasVlanColor = primaryVlan != null;

  const cls = [
    'port-strip__port',
    p.up ? 'port-strip__port--up' : 'port-strip__port--down',
    portTypeClass(p.name),
    hasVlanColor ? 'port-strip__port--vlan-colored' : '',
    onSelectPort ? 'port-strip__port--clickable' : '',
  ].filter(Boolean).join(' ');

  const vlanStyle = hasVlanColor
    ? ({ '--port-vlan-color': vlanColor(primaryVlan!) } as React.CSSProperties)
    : undefined;

  const linkDesc = p.up
    ? [p.speed_mbps ? `${p.speed_mbps} Mbps` : 'up', p.duplex ?? ''].filter(Boolean).join(' ')
    : 'no link';

  const badge = badgeText(p);
  const tooltipDevices = (p.connectedDevices ?? []).slice(0, 6);
  const tooltipOverflow = (p.deviceCount ?? 0) - tooltipDevices.length;

  return (
    <div
      className={cls}
      style={vlanStyle}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
      onClick={(e) => {
        if (!onSelectPort) return;
        e.stopPropagation();
        onSelectPort(p);
      }}
    >
      <div className="port-strip__led" />
      <span className="port-strip__name">{shortName(p.name)}</span>
      {p.up && p.speed_mbps != null && (
        <span className="port-strip__speed">{speedLabel(p.speed_mbps, p.up)}</span>
      )}
      {badge && (
        <span
          className={`port-strip__device${
            p.mappingConfidence === 'medium' ? ' port-strip__device--uncertain' : ''
          }`}
        >
          {badge}
        </span>
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
          {isWanPort(p) && p.connectedDevices !== undefined && (
            <div className="port-tooltip__meta">Uplink zum Internet</div>
          )}
          {tooltipDevices.length > 0 ? (
            tooltipDevices.map((d) => (
              <div key={d.mac || deviceLabel(d)} className="port-tooltip__meta port-tooltip__device">
                <span className={`confidence-dot confidence-dot--${d.confidence}`} />
                {'→ '}
                {deviceLabel(d)}
                {d.confidence === 'medium' && ' (unsicher)'}
              </div>
            ))
          ) : (
            // Legacy snapshots: keep the old single-string line
            p.connectedDevice && (
              <div className="port-tooltip__meta" style={{ color: '#93c5fd' }}>
                → {p.connectedDevice}
              </div>
            )
          )}
          {tooltipOverflow > 0 && (
            <div className="port-tooltip__meta">… +{tooltipOverflow} weitere</div>
          )}
          {onSelectPort && p.connectedDevices !== undefined && (
            <div className="port-tooltip__hint">Klick für Details</div>
          )}
        </div>
      )}
    </div>
  );
}
