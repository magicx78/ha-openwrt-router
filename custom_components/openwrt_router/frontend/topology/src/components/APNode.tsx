import React from 'react';
import { AccessPoint, Client } from '../types';
import { StatusDot } from './StatusDot';
import { IconAP } from './Icons';
import { SignalBar } from './SignalBar';
import { computeHealth } from './GatewayNode';
import { useStatusFlash } from '../useStatusFlash';
import { PortStrip } from './PortStrip';

function trendArrow(history: number[]): string {
  if (history.length < 3) return '→';
  const recent = history.slice(-3);
  const delta = recent[2] - recent[0];
  if (delta > 5)  return '↑';
  if (delta < -5) return '↓';
  return '→';
}

function trendClass(history: number[], current: number): string {
  if (current > 80) return 'metric-critical';
  if (current > 60) return 'metric-warn';
  return 'metric-ok';
}

function MiniSparklineAP({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return null;
  const w = 52, h = 16;
  const max = Math.max(...values, 1);
  const step = w / (values.length - 1);
  const coords = values.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * h).toFixed(1)}`);
  return (
    <svg width={w} height={h} style={{ display: 'block', overflow: 'visible' }}>
      <polyline
        points={coords.join(' ')}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

interface Props {
  ap: AccessPoint;
  clients: Client[];
  selected: boolean;
  dimmed: boolean;
  expanded?: boolean;
  onSelect: () => void;
  onHover: (id: string | null) => void;
  onContextMenu?: (x: number, y: number) => void;
  onDoubleClick?: () => void;
  onToggleExpand?: () => void;
  heatmap?: boolean;
  vlanMode?: boolean;
  healthMode?: boolean;
}

function avgSignalDbm(clients: Client[]): number | null {
  const sigs = clients.map(c => c.signal).filter(s => s != null && s !== 0) as number[];
  if (!sigs.length) return null;
  return Math.round(sigs.reduce((a, b) => a + b, 0) / sigs.length);
}

export type HeatmapLevel = 'excellent' | 'good' | 'fair' | 'poor' | 'offline';

export function heatmapLevel(dbm: number | null, uplinkSignal: number, offline: boolean): HeatmapLevel {
  if (offline) return 'offline';
  const sig = dbm ?? uplinkSignal;
  if (sig >= -65) return 'excellent';
  if (sig >= -75) return 'good';
  if (sig >= -80) return 'fair';
  return 'poor';
}

function bandClass(band: string): string {
  if (band.includes('6')) return 'ssid-badge--6g';
  if (band.includes('5')) return 'ssid-badge--5g';
  return 'ssid-badge--24g';
}

function portSpeedLabel(mbps: number | null): string {
  if (mbps == null) return '?';
  if (mbps >= 2500) return '2.5G';
  if (mbps >= 1000) return '1G';
  if (mbps >= 100)  return '100M';
  return '10M';
}

export function APNode({ ap, clients, selected, dimmed, expanded, onSelect, onHover, onContextMenu, onDoubleClick, onToggleExpand, heatmap, vlanMode, healthMode }: Props) {
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
  const hmLevel = heatmap ? heatmapLevel(avg, ap.backhaulSignal, ap.status === 'offline') : undefined;

  const flashing = useStatusFlash(ap.status);

  const cls = [
    'node-card ap-card',
    statusClass,
    selected  ? 'selected'     : '',
    dimmed    ? 'dimmed'       : '',
    flashing  ? 'status-flash' : '',
  ].filter(Boolean).join(' ');

  const vlanAttr = vlanMode && ap.primaryVlanId != null ? ap.primaryVlanId : undefined;
  const health = healthMode ? computeHealth(ap.cpuLoad, ap.memUsage, ap.backhaulSignal) : undefined;

  return (
    <div
      className={cls}
      data-vlan={vlanAttr}
      data-health={health}
      data-heatmap={hmLevel}
      onClick={onSelect}
      onMouseEnter={() => onHover(ap.id)}
      onMouseLeave={() => onHover(null)}
      onContextMenu={e => { e.preventDefault(); onContextMenu?.(e.clientX, e.clientY); }}
      onDoubleClick={e => { e.stopPropagation(); onDoubleClick?.(); }}
    >
      <div className="ap-card__header">
        <div className={`ap-card__icon ${iconCls}`}>
          <IconAP size={16} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="ap-card__name">{ap.name}</div>
          <div className="ap-card__ip">{ap.ip}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
          <StatusDot status={ap.status} />
          {health && (
            <span className={`health-badge health-badge--${health}`}>
              {ap.cpuLoad != null ? `${ap.cpuLoad > 100 ? 'Load' : 'CPU'} ${ap.cpuLoad}%` : `${ap.backhaulSignal} dBm`}
            </span>
          )}
        </div>
      </div>

      <div className="ap-card__footer">
        <span className={`ap-card__badge ${ap.uplinkType}`}>
          {ap.uplinkType === 'wired' ? 'Kabel' : 'Mesh'}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {ap.status !== 'offline' && <SignalBar dbm={ap.backhaulSignal} />}
          <button
            className={`ap-card__clients${expanded ? ' expanded' : ''}`}
            onClick={e => { e.stopPropagation(); onToggleExpand?.(); }}
            title={expanded ? 'Clients einklappen' : 'Clients ausklappen'}
          >
            <strong>{ap.clientCount}</strong> Clients
            <span className="ap-card__clients-chevron">{expanded ? '▲' : '▼'}</span>
          </button>
        </div>
      </div>

      {/* Gateway port badge — only for wired APs with known port */}
      {ap.gatewayPort && ap.uplinkType === 'wired' && (
        <div className="ap-card__port-badge">
          <span className={`port-led port-led--${ap.gatewayPortUp ? 'up' : 'down'}`} />
          <span className="ap-card__port-name">{ap.gatewayPort.toUpperCase()}</span>
          <span className="ap-card__port-speed">{portSpeedLabel(ap.gatewayPortSpeed ?? null)}</span>
        </div>
      )}

      {/* SSID count badge + VLAN badges */}
      {((ap.ssids && ap.ssids.length > 0) || ap.primaryVlanId != null) && (
        <div className="ap-card__ssids">
          {ap.ssids && ap.ssids.length > 0 && (
            <span
              className="ssid-count-badge"
              title={ap.ssids.map(s =>
                [s.ssid, s.band, s.channel ? `ch${s.channel}` : ''].filter(Boolean).join(' · ')
              ).join('\n')}
            >
              📶 {ap.ssids.length}
            </span>
          )}
          {ap.primaryVlanId != null && (
            <span
              className="vlan-badge vlan-badge--up"
              title={`VLAN ${ap.primaryVlanId}`}
            >
              <span className="vlan-badge__id">VLAN {ap.primaryVlanId}</span>
            </span>
          )}
        </div>
      )}

      {/* CPU sparkline + trend (shown when backend history available) */}
      {(ap.cpuHistoryBackend?.length ?? 0) >= 3 && (() => {
        const cpuVals = ap.cpuHistoryBackend!.map(p => p.cpu);
        const cpu = ap.cpuLoad ?? cpuVals[cpuVals.length - 1] ?? 0;
        const sparkColor = cpu > 100 ? '#ef4444' : cpu > 80 ? '#ef4444' : cpu > 60 ? '#f59e0b' : '#22c55e';
        return (
          <div className="ap-card__metrics">
            <div className="gateway-metric">
              <div className="gateway-metric__row">
                <span className="gateway-metric__label">{cpu > 100 ? 'Load' : 'CPU'}</span>
                <span className={`gateway-metric__value ${cpu > 100 ? 'metric--critical' : trendClass(cpuVals, cpu)}`}>
                  {cpu.toFixed(0)}%&nbsp;{trendArrow(cpuVals)}
                </span>
              </div>
              <MiniSparklineAP values={cpuVals} color={sparkColor} />
            </div>
          </div>
        );
      })()}

      {/* Port strip — physical ports (WAN, LAN1, ...) */}
      {ap.portStats && ap.portStats.length > 0 && (
        <PortStrip ports={ap.portStats} />
      )}
    </div>
  );
}
