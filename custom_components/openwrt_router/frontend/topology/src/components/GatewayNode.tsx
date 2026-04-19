import React from 'react';
import { Gateway, VlanInfo } from '../types';
import { StatusDot } from './StatusDot';
import { IconRouter } from './Icons';
import { PortStrip } from './PortStrip';

interface Props {
  gateway: Gateway;
  selected: boolean;
  dimmed: boolean;
  onSelect: () => void;
  onHover: (id: string | null) => void;
  onContextMenu?: (x: number, y: number) => void;
  clientCount?: number;
  vlanMode?: boolean;
  healthMode?: boolean;
}

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

function MiniSparkline({ values, color }: { values: number[]; color: string }) {
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

function bandClass(band: string): string {
  if (band.includes('6')) return 'ssid-badge--6g';
  if (band.includes('5')) return 'ssid-badge--5g';
  return 'ssid-badge--24g';
}

export function computeHealth(cpu?: number, mem?: number, signalDbm?: number): 'ok' | 'caution' | 'warning' | 'critical' {
  const c = cpu ?? 0;
  const m = mem ?? 0;
  if (c > 80 || m > 85) return 'critical';
  if (c > 60 || m > 70) return 'warning';
  if (c > 40 || m > 55) return 'caution';
  if (signalDbm != null && signalDbm < -80) return 'warning';
  if (signalDbm != null && signalDbm < -72) return 'caution';
  return 'ok';
}

export function GatewayNode({ gateway, selected, dimmed, onSelect, onHover, onContextMenu, clientCount, vlanMode, healthMode }: Props) {
  const statusClass = gateway.status === 'online'
    ? 'status-online'
    : gateway.status === 'warning'
      ? 'status-warning'
      : 'status-offline';

  const cls = [
    'node-card gateway-card',
    statusClass,
    selected ? 'selected' : '',
    dimmed ? 'dimmed' : '',
  ].filter(Boolean).join(' ');

  const history = gateway.cpuHistory ?? [];
  const cpu = gateway.cpuLoad;
  const mem = gateway.memUsage;

  const health = healthMode ? computeHealth(cpu, mem) : undefined;
  // Gateway hosts all VLANs — no single "primary", use first VLAN ID for border accent
  const firstVlan = vlanMode && (gateway.vlans ?? []).length > 0 ? gateway.vlans![0].id : undefined;

  return (
    <div
      className={cls}
      data-vlan={firstVlan ?? undefined}
      data-health={health}
      onClick={onSelect}
      onMouseEnter={() => onHover(gateway.id)}
      onMouseLeave={() => onHover(null)}
      onContextMenu={e => { e.preventDefault(); onContextMenu?.(e.clientX, e.clientY); }}
    >
      {/* ── Header ── */}
      <div className="gateway-card__header">
        <div className="gateway-card__icon">
          <IconRouter size={18} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="gateway-card__name">{gateway.name}</div>
          <div className="gateway-card__model">{gateway.model}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <StatusDot status={gateway.status} />
          {health ? (
            <span className={`health-badge health-badge--${health}`}>
              {cpu != null ? `CPU ${cpu}%` : health}
            </span>
          ) : (
            <span className="gateway-card__role">Gateway</span>
          )}
        </div>
      </div>

      <div className="gateway-card__sep" />

      {/* ── 2-column body ── */}
      <div className="gateway-card__body2">
        {/* Left: network */}
        <div className="gateway-card__col">
          <div className="gateway-card__row">
            <span>LAN</span><span>{gateway.ip}</span>
          </div>
          <div className="gateway-card__row">
            <span>WAN</span><span>{gateway.wanIp || '—'}</span>
          </div>
          <div className="gateway-card__row">
            <span>Uptime</span><span>{gateway.uptime}</span>
          </div>
        </div>

        {/* Right: system */}
        <div className="gateway-card__col gateway-card__col--right">
          {cpu != null && (
            <div className="gateway-metric">
              <div className="gateway-metric__row">
                <span className="gateway-metric__label">CPU</span>
                <span className={`gateway-metric__value ${trendClass(history, cpu)}`}>
                  {cpu.toFixed(0)}%&nbsp;{trendArrow(history)}
                </span>
              </div>
              {history.length > 1 && (
                <MiniSparkline values={history} color={cpu > 80 ? '#ef4444' : cpu > 60 ? '#f59e0b' : '#22c55e'} />
              )}
            </div>
          )}
          {mem != null && (
            <div className="gateway-metric">
              <div className="gateway-metric__row">
                <span className="gateway-metric__label">RAM</span>
                <span className={`gateway-metric__value ${trendClass([], mem)}`}>
                  {mem.toFixed(0)}%
                </span>
              </div>
            </div>
          )}
          {clientCount != null && clientCount > 0 && (
            <div className="gateway-metric">
              <div className="gateway-metric__row">
                <span className="gateway-metric__label">Clients</span>
                <span className="gateway-metric__value">{clientCount}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── SSID badges ── */}
      {gateway.ssids && gateway.ssids.length > 0 && (
        <div className="gateway-card__ssids">
          {gateway.ssids.map((s, i) => (
            <span
              key={i}
              className={`ssid-badge ${bandClass(s.band)}`}
              title={[s.ssid, s.band, s.channel ? `Kanal ${s.channel}` : ''].filter(Boolean).join(' · ')}
            >
              {s.band && <span className="ssid-badge__band">{s.band}</span>}
              <span className="ssid-badge__name">{s.ssid}</span>
              {s.channel && <span className="ssid-badge__ch">ch{s.channel}</span>}
            </span>
          ))}
        </div>
      )}

      {/* ── VLAN badges ── */}
      {gateway.vlans && gateway.vlans.length > 0 && (
        <div className="gateway-card__vlans">
          {gateway.vlans.map((v) => (
            <span
              key={v.id}
              className={`vlan-badge${v.status === 'up' ? ' vlan-badge--up' : v.status === 'down' ? ' vlan-badge--down' : ''}`}
              title={`VLAN ${v.id} · ${v.interface} · ${v.status}`}
            >
              <span className="vlan-badge__id">VLAN {v.id}</span>
              <span className="vlan-badge__iface">{v.interface}</span>
            </span>
          ))}
        </div>
      )}

      {/* ── Port strip ── */}
      {gateway.portStats && gateway.portStats.length > 0 && (
        <PortStrip ports={gateway.portStats} />
      )}
    </div>
  );
}
