/**
 * DevicesView — list of all routers (gateway + APs) with status, uplink, signal.
 * Click any row to open the DetailPanel for that device.
 */

import React, { useMemo } from 'react';
import { TopologyData, AccessPoint, Client, NodeStatus } from '../types';
import { StatusDot } from './StatusDot';
import { SignalBar } from './SignalBar';
import { IconRouter, IconAP } from './Icons';

interface Props {
  data: TopologyData;
  onSelectGateway: () => void;
  onSelectAP: (ap: AccessPoint) => void;
}

function avgSignal(clients: Client[]): number | null {
  const signals = clients.map(c => c.signal).filter(s => s != null && s !== 0) as number[];
  if (!signals.length) return null;
  return Math.round(signals.reduce((a, b) => a + b, 0) / signals.length);
}

function signalColor(dbm: number): string {
  if (dbm >= -65) return 'signal-excellent';
  if (dbm >= -75) return 'signal-good';
  if (dbm >= -80) return 'signal-fair';
  return 'signal-poor';
}

export function DevicesView({ data, onSelectGateway, onSelectAP }: Props) {
  const { gateway, accessPoints } = data;
  const gwClients = data.clients.filter(c => c.apId === gateway.id).length;

  // Build clients-per-AP map for the distribution row
  const clientsByAp = useMemo(() => {
    const m = new Map<string, Client[]>();
    for (const c of data.clients) {
      const list = m.get(c.apId) ?? [];
      list.push(c);
      m.set(c.apId, list);
    }
    return m;
  }, [data.clients]);

  const maxClients = useMemo(
    () => Math.max(1, ...accessPoints.map(ap => ap.clientCount)),
    [accessPoints],
  );

  return (
    <div className="topo-view">
      <div className="view-header">
        <span className="view-title">Geräte</span>
        <span className="view-count">{1 + accessPoints.length} Geräte</span>
      </div>

      <div className="device-list">
        {/* Gateway */}
        <DeviceRow
          type="gateway"
          name={gateway.name}
          model={gateway.model}
          ip={gateway.ip}
          status={gateway.status}
          badge="Gateway"
          badgeMod="gateway"
          detail={gwClients > 0 ? `${gwClients} direkte Clients` : gateway.uptime ? `Uptime: ${gateway.uptime}` : ''}
          extra={gateway.pingMs != null ? `Ping: ${gateway.pingMs} ms` : undefined}
          onClick={onSelectGateway}
        />

        {/* APs sorted: wired first, then mesh; offline last */}
        {[...accessPoints]
          .sort((a, b) => {
            if (a.status === 'offline' && b.status !== 'offline') return 1;
            if (a.status !== 'offline' && b.status === 'offline') return -1;
            if (a.uplinkType === 'wired' && b.uplinkType !== 'wired') return -1;
            if (a.uplinkType !== 'wired' && b.uplinkType === 'wired') return 1;
            return a.name.localeCompare(b.name);
          })
          .map(ap => {
            const apClients = clientsByAp.get(ap.id) ?? [];
            const avg = ap.status !== 'offline' ? avgSignal(apClients) : null;
            const loadPct = Math.round((ap.clientCount / maxClients) * 100);
            return (
              <DeviceRow
                key={ap.id}
                type="ap"
                name={ap.name}
                model={ap.model}
                ip={ap.ip}
                status={ap.status}
                badge={ap.uplinkType === 'wired' ? 'LAN-Kabel' : 'WiFi Mesh'}
                badgeMod={ap.uplinkType}
                signal={ap.status !== 'offline' ? ap.backhaulSignal : undefined}
                detail={`${ap.clientCount} Clients`}
                onClick={() => onSelectAP(ap)}
                clientDistribution={ap.status !== 'offline' ? { avg, loadPct } : undefined}
              />
            );
          })}
      </div>
    </div>
  );
}

interface RowProps {
  type: 'gateway' | 'ap';
  name: string;
  model: string;
  ip: string;
  status: NodeStatus;
  badge: string;
  badgeMod: string;
  signal?: number;
  detail: string;
  extra?: string;
  onClick: () => void;
  clientDistribution?: { avg: number | null; loadPct: number };
}

function DeviceRow({ type, name, model, ip, status, badge, badgeMod, signal, detail, extra, onClick, clientDistribution }: RowProps) {
  return (
    <div className={`device-row device-row--${status}`} onClick={onClick}>
      <div className="device-row__icon">
        {type === 'gateway' ? <IconRouter size={18} /> : <IconAP size={16} />}
      </div>
      <div className="device-row__info">
        <div className="device-row__name">{name}</div>
        <div className="device-row__meta">{model} · {ip}</div>
      </div>
      <span className={`device-badge device-badge--${badgeMod}`}>{badge}</span>
      {signal != null && (
        <div className="device-row__signal">
          <SignalBar dbm={signal} />
          <span className="device-row__dbm">{signal} dBm</span>
        </div>
      )}
      <div className="device-row__right">
        <span className="device-row__detail">{detail}</span>
        {extra && <span className="device-row__extra">{extra}</span>}
      </div>
      <StatusDot status={status} />
      {clientDistribution && (
        <div className="device-row__distribution">
          {clientDistribution.avg != null && (
            <span className={`dist-signal ${signalColor(clientDistribution.avg)}`}>
              Ø {clientDistribution.avg} dBm
            </span>
          )}
          <div className="dist-bar">
            <div className="dist-bar__fill" style={{ width: `${clientDistribution.loadPct}%` }} />
          </div>
          <span className="dist-load">{clientDistribution.loadPct}%</span>
        </div>
      )}
    </div>
  );
}
