/**
 * WiringView — port-to-port wiring schematic for the whole mesh.
 *
 * Shows every router-to-router connection as a row:
 *   Source : Port → Target : Port + Medium (Kabel/WLAN/Mesh) + VLAN tags + Status
 *
 * Built directly from the per-AP uplink fields already present in
 * `accessPoints[]` (gatewayPort, apPort, vlanTags, gatewayPortSpeed,
 * uplinkType, backhaulSignal). No extra backend call needed.
 */

import React, { useMemo } from 'react';
import type { TopologyData, AccessPoint } from '../types';
import { vlanColor } from '../utils/vlanColor';

interface Props {
  data: TopologyData;
  onSelectAP: (ap: AccessPoint) => void;
}

interface WiringRow {
  ap: AccessPoint;
  fromName: string;
  fromPort: string;
  toName: string;
  toPort: string;
  medium: 'wired' | 'wifi' | 'mesh';
  vlans: number[];
  speedLabel: string;
  statusLabel: string;
  detail?: string;
}

function formatSpeed(mbps: number | null | undefined): string {
  if (mbps == null) return '';
  if (mbps >= 2500) return '2.5G';
  if (mbps >= 1000) return '1G';
  if (mbps >= 100)  return '100M';
  if (mbps >= 10)   return '10M';
  return `${mbps}M`;
}

function shortPort(name: string | undefined | null): string {
  if (!name) return '—';
  if (/^wan/i.test(name)) return 'WAN';
  const m = name.match(/^lan(\d+)$/i);
  if (m) return `LAN${m[1]}`;
  return name.toUpperCase();
}

function mediumLabel(m: WiringRow['medium']): string {
  if (m === 'wired') return 'Kabel';
  if (m === 'wifi')  return 'WLAN';
  return 'Mesh?';
}

export function WiringView({ data, onSelectAP }: Props) {
  const rows = useMemo<WiringRow[]>(() => {
    return [...data.accessPoints]
      .map<WiringRow>((ap) => {
        const medium: WiringRow['medium'] =
          ap.uplinkType === 'wired' ? 'wired'
          : ap.uplinkType === 'mesh' ? 'wifi'
          : 'mesh';

        const speed = formatSpeed(ap.gatewayPortSpeed);
        const linkUp = ap.gatewayPortUp;
        const statusLabel =
          medium === 'wired'
            ? (speed ? `${speed} ${linkUp === false ? '✗' : '✓'}` : (linkUp === false ? 'down' : 'up'))
          : medium === 'wifi'
            ? (ap.backhaulSignal ? `${ap.backhaulSignal} dBm` : 'WLAN')
          : '—';

        return {
          ap,
          fromName: data.gateway.name,
          fromPort: shortPort(ap.gatewayPort),
          toName: ap.name,
          toPort: shortPort(ap.apPort ?? (medium === 'wifi' ? 'sta' : ap.apPort)),
          medium,
          vlans: ap.vlanTags ?? [],
          speedLabel: speed,
          statusLabel,
          detail: medium === 'mesh' ? 'unverifiziert (Subnet-Fallback)' : undefined,
        };
      })
      .sort((a, b) => {
        // Wired first, then wifi, then mesh; within each, source-port order
        const mediumRank = (m: WiringRow['medium']) => (m === 'wired' ? 0 : m === 'wifi' ? 1 : 2);
        const dm = mediumRank(a.medium) - mediumRank(b.medium);
        if (dm !== 0) return dm;
        return a.fromPort.localeCompare(b.fromPort, undefined, { numeric: true });
      });
  }, [data]);

  const wiredCount = rows.filter(r => r.medium === 'wired').length;
  const wifiCount  = rows.filter(r => r.medium === 'wifi').length;
  const meshCount  = rows.filter(r => r.medium === 'mesh').length;

  return (
    <div className="topo-view">
      <div className="view-header">
        <span className="view-title">Verkabelung</span>
        <span className="view-count">
          {wiredCount} Kabel · {wifiCount} WLAN{meshCount > 0 ? ` · ${meshCount} unverifiziert` : ''}
        </span>
      </div>

      {rows.length === 0 ? (
        <div className="wiring-empty">Keine Verbindungen erkannt.</div>
      ) : (
        <div className="wiring-table" role="table">
          <div className="wiring-row wiring-row--head" role="row">
            <div role="columnheader">Quelle</div>
            <div role="columnheader">Port</div>
            <div role="columnheader" />
            <div role="columnheader">Ziel</div>
            <div role="columnheader">Port</div>
            <div role="columnheader">Medium</div>
            <div role="columnheader">VLANs</div>
            <div role="columnheader">Status</div>
          </div>

          {rows.map(r => (
            <div
              key={r.ap.id}
              role="row"
              className={`wiring-row wiring-row--${r.medium}`}
              onClick={() => onSelectAP(r.ap)}
              title={r.detail ?? `${r.fromName} ${r.fromPort} → ${r.toName} ${r.toPort}`}
            >
              <div className="wiring-cell wiring-cell--src">{r.fromName}</div>
              <div className="wiring-cell wiring-cell--port">{r.fromPort}</div>
              <div className="wiring-cell wiring-cell--arrow">→</div>
              <div className="wiring-cell wiring-cell--dst">{r.toName}</div>
              <div className="wiring-cell wiring-cell--port">{r.toPort}</div>
              <div className={`wiring-cell wiring-cell--medium wiring-medium--${r.medium}`}>
                {mediumLabel(r.medium)}
              </div>
              <div className="wiring-cell wiring-cell--vlans">
                {r.vlans.length === 0 ? (
                  <span className="wiring-vlan-empty">—</span>
                ) : (
                  r.vlans.map(id => (
                    <span
                      key={id}
                      data-vlan={id}
                      style={{ '--vlan-color': vlanColor(id) } as React.CSSProperties}
                      className="vlan-badge vlan-badge--colored vlan-badge--up wiring-vlan"
                      title={`VLAN ${id}${r.vlans.length > 1 ? ' (Trunk)' : ''}`}
                    >
                      <span className="vlan-badge__id">{id}</span>
                    </span>
                  ))
                )}
              </div>
              <div className="wiring-cell wiring-cell--status">{r.statusLabel}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
