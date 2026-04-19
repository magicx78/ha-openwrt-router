/**
 * DetailPanel — Slide-in right panel showing details for a selected node.
 *
 * Handles three entity types: Gateway, AccessPoint, Client.
 * All data is passed in via props; the panel has no data-fetching logic.
 */

import React, { useState } from 'react';
import { Gateway, AccessPoint, Client, NodeStatus, DdnsService, SsidInfo, PortStat, VlanInfo } from '../types';
import { IconX } from './Icons';
import { StatusDot, statusLabel } from './StatusDot';
import { SignalBar } from './SignalBar';
import { SpeedChart } from './SpeedChart';
import { signalQuality } from '../layout';
import { formatConnectedSince, formatLeaseExpiry } from '../api';

type SelectedEntity =
  | { type: 'gateway'; data: Gateway }
  | { type: 'ap';      data: AccessPoint; clients: Client[] }
  | { type: 'client';  data: Client;      apName: string }
  | null;

export interface DetailPanelActions {
  onFocusNode: (nodeId: string) => void;
  onShowClients: () => void;
  onShowAlerts: () => void;
  onToggleVlan: () => void;
}

interface Props {
  entity: SelectedEntity;
  onClose: () => void;
  actions?: DetailPanelActions;
}

export function DetailPanel({ entity, onClose, actions }: Props) {
  return (
    <div className={`detail-panel ${entity ? 'open' : ''}`}>
      <div className="detail-panel__handle" aria-hidden="true" />
      <div className="detail-panel__header">
        <span className="detail-panel__title">
          {entity?.type === 'gateway' && 'Gateway'}
          {entity?.type === 'ap'      && 'Access Point'}
          {entity?.type === 'client'  && 'Client'}
          {!entity && 'Details'}
        </span>
        <button className="detail-panel__close" onClick={onClose}>
          <IconX size={13} />
        </button>
      </div>

      <div className="detail-panel__body">
        {entity?.type === 'gateway' && <GatewayDetail data={entity.data} actions={actions} />}
        {entity?.type === 'ap'      && <APDetail data={entity.data} clients={entity.clients} actions={actions} />}
        {entity?.type === 'client'  && <ClientDetail data={entity.data} apName={entity.apName} actions={actions} />}
      </div>
    </div>
  );
}

// ── Action bar ────────────────────────────────────────────────────────────

function ActionBtn({ icon, label, onClick }: { icon: string; label: string; onClick: () => void }) {
  return (
    <button className="inspector-action" onClick={onClick}>
      <span className="inspector-action__icon">{icon}</span>
      <span>{label}</span>
    </button>
  );
}

// ── Gateway detail ────────────────────────────────────────────────────────

function GatewayDetail({ data, actions }: { data: Gateway; actions?: DetailPanelActions }) {
  const [chartMode, setChartMode] = useState<'speed' | 'ping'>('speed');
  const history = data.dslHistory ?? [];
  const dsl = data.dslStats;
  const hasDsl = !!dsl && dsl.downstream_kbps > 0;
  const hasPing = data.pingMs != null;

  return (
    <>
      <div className="detail-section">
        <div className="detail-section__heading">Allgemein</div>
        <Row label="Name"   value={data.name} />
        <Row label="Modell" value={data.model} />
        <Row label="Status" value={<StatusBadge status={data.status} />} />
        {data.firmwareVersion && <Row label="Firmware" value={data.firmwareVersion} />}
      </div>
      <div className="detail-section">
        <div className="detail-section__heading">Netzwerk</div>
        <Row label="LAN IP"  value={data.ip} />
        <Row label="WAN IP"  value={data.wanIp} />
        <Row label="Uptime"  value={data.uptime} />
        {hasPing && <Row label="Ping (8.8.8.8)" value={`${data.pingMs} ms`} />}
      </div>

      {data.wanTraffic && (data.wanTraffic.downstream_bps != null || data.wanTraffic.upstream_bps != null) && (
        <div className="detail-section">
          <div className="detail-section__heading">WAN Aktivität</div>
          <WanTrafficBars
            down={data.wanTraffic.downstream_bps ?? 0}
            up={data.wanTraffic.upstream_bps ?? 0}
          />
        </div>
      )}

      {hasDsl && (
        <div className="detail-section">
          <div className="detail-section__heading">DSL (Fritz!Box)</div>
          <Row label="↓ Sync"        value={`${(dsl!.downstream_kbps / 1000).toFixed(1)} Mbps`} />
          <Row label="↑ Sync"        value={`${(dsl!.upstream_kbps / 1000).toFixed(1)} Mbps`} />
          <Row label="↓ Max"         value={`${(dsl!.downstream_max_kbps / 1000).toFixed(1)} Mbps`} />
          <Row label="↑ Max"         value={`${(dsl!.upstream_max_kbps / 1000).toFixed(1)} Mbps`} />
          {dsl!.snr_down_db > 0 && <Row label="SNR ↓"  value={`${dsl!.snr_down_db} dB`} />}
          {dsl!.snr_up_db > 0   && <Row label="SNR ↑"  value={`${dsl!.snr_up_db} dB`} />}
          {dsl!.attn_down_db > 0 && <Row label="Dämpfung ↓" value={`${dsl!.attn_down_db} dB`} />}
          {dsl!.attn_up_db > 0   && <Row label="Dämpfung ↑" value={`${dsl!.attn_up_db} dB`} />}
        </div>
      )}

      {history.length >= 2 && (
        <div className="detail-section">
          <div className="detail-section__heading" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>24h Verlauf</span>
            <span style={{ display: 'flex', gap: 6 }}>
              <ChartTabBtn active={chartMode === 'speed'} onClick={() => setChartMode('speed')}>
                DSL
              </ChartTabBtn>
              <ChartTabBtn active={chartMode === 'ping'} onClick={() => setChartMode('ping')}>
                Ping
              </ChartTabBtn>
            </span>
          </div>
          <SpeedChart history={history} width={310} height={110} mode={chartMode} />
        </div>
      )}

      {(data.cpuLoad != null || data.memUsage != null) && (
        <div className="detail-section">
          <div className="detail-section__heading">System</div>
          <ResourceBars cpu={data.cpuLoad} mem={data.memUsage} />
        </div>
      )}

      {(data.ssids ?? []).length > 0 && (
        <div className="detail-section">
          <div className="detail-section__heading">WLAN-Netze</div>
          <SsidList ssids={data.ssids!} />
        </div>
      )}

      {(data.portStats ?? []).length > 0 && (
        <div className="detail-section">
          <div className="detail-section__heading">Ports</div>
          <PortList ports={data.portStats!} />
        </div>
      )}

      {(data.vlans ?? []).length > 0 && (
        <div className="detail-section">
          <div className="detail-section__heading">VLANs</div>
          <VlanList vlans={data.vlans!} />
        </div>
      )}

      {(data.ddnsServices ?? []).length > 0 && (
        <div className="detail-section">
          <div className="detail-section__heading">DuckDNS / DDNS</div>
          {(data.ddnsServices ?? []).map(svc => (
            <DdnsRow key={svc.section} svc={svc} />
          ))}
        </div>
      )}

      {actions && (
        <div className="inspector-actions">
          <ActionBtn icon="◎" label="Fokus"   onClick={() => actions.onFocusNode(data.id)} />
          <ActionBtn icon="👥" label="Clients" onClick={actions.onShowClients} />
          <ActionBtn icon="⚠" label="Alarme"  onClick={actions.onShowAlerts} />
          <ActionBtn icon="▦" label="VLANs"   onClick={actions.onToggleVlan} />
        </div>
      )}
    </>
  );
}

function ChartTabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        fontSize: 10,
        padding: '1px 7px',
        borderRadius: 4,
        border: 'none',
        cursor: 'pointer',
        background: active ? 'var(--accent, #60a5fa)' : 'rgba(255,255,255,0.08)',
        color: active ? '#fff' : 'var(--text-secondary, #8899aa)',
        fontWeight: active ? 600 : 400,
      }}
    >
      {children}
    </button>
  );
}

function DdnsRow({ svc }: { svc: DdnsService }) {
  const statusColor = svc.status === 'ok'
    ? '#4ade80'
    : svc.status === 'error'
    ? '#f87171'
    : '#fb923c';

  const lastUpdateStr = svc.last_update
    ? new Date(svc.last_update * 1000).toLocaleString('de-DE', {
        day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
      })
    : null;

  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary, #e0eaf8)' }}>
          {svc.domain || svc.section}
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor, display: 'inline-block' }} />
          <span style={{ color: statusColor }}>
            {svc.status === 'ok' ? 'Aktiv' : svc.status === 'error' ? 'Fehler' : 'Unbekannt'}
          </span>
        </span>
      </div>
      {svc.ip && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary, #8899aa)' }}>
          IP: {svc.ip}
        </div>
      )}
      {lastUpdateStr && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary, #8899aa)' }}>
          Zuletzt: {lastUpdateStr}
        </div>
      )}
      {svc.service_name && (
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginTop: 1 }}>
          {svc.service_name}
        </div>
      )}
    </div>
  );
}

// ── AP detail ─────────────────────────────────────────────────────────────

function APDetail({ data, clients, actions }: { data: AccessPoint; clients: Client[]; actions?: DetailPanelActions }) {
  const q = signalQuality(data.backhaulSignal);
  return (
    <>
      <div className="detail-section">
        <div className="detail-section__heading">Allgemein</div>
        <Row label="Name"    value={data.name} />
        <Row label="Modell"  value={data.model} />
        <Row label="IP"      value={data.ip} />
        <Row label="Status"  value={<StatusDot status={data.status} />} />
        {data.firmwareVersion && <Row label="Firmware" value={data.firmwareVersion} />}
      </div>
      <div className="detail-section">
        <div className="detail-section__heading">Uplink</div>
        <Row label="Typ"     value={data.uplinkType === 'wired' ? 'Kabelgebunden' : 'Mesh'} />
        <Row label="Signal"  value={<><SignalBar dbm={data.backhaulSignal} /> {data.backhaulSignal} dBm</>} />
        <Row label="Qualität" value={q} />
      </div>
      {(data.ssids ?? []).length > 0 && (
        <div className="detail-section">
          <div className="detail-section__heading">WLAN-Netze</div>
          <SsidList ssids={data.ssids!} />
        </div>
      )}

      {(data.cpuLoad != null || data.memUsage != null) && (
        <div className="detail-section">
          <div className="detail-section__heading">System</div>
          <ResourceBars cpu={data.cpuLoad} mem={data.memUsage} />
        </div>
      )}

      <div className="detail-section">
        <div className="detail-section__heading">Clients ({clients.length})</div>
        <div className="detail-client-list">
          {clients.map(c => (
            <div className="detail-client-item" key={c.id}>
              <StatusDot status={c.status} />
              <span className="detail-client-item__name">{c.name}</span>
              <span className="detail-client-item__meta">{c.band}</span>
            </div>
          ))}
        </div>
      </div>

      {actions && (
        <div className="inspector-actions">
          <ActionBtn icon="◎" label="Fokus"   onClick={() => actions.onFocusNode(data.id)} />
          <ActionBtn icon="👥" label="Clients" onClick={actions.onShowClients} />
          <ActionBtn icon="⚠" label="Alarme"  onClick={actions.onShowAlerts} />
        </div>
      )}
    </>
  );
}

// ── Client detail ─────────────────────────────────────────────────────────

/** Construct the HA entity_id for this client's device_tracker entity.
 *  HA slugifies the entity name (hostname or MAC) by lowercasing and
 *  replacing non-alphanumeric characters with underscores.
 */
function haEntityId(mac: string, hostname: string): string {
  const name = hostname && hostname !== mac ? hostname : mac;
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
  return `device_tracker.${slug}`;
}

function ClientDetail({ data, apName, actions }: { data: Client; apName: string; actions?: DetailPanelActions }) {
  const q = signalQuality(data.signal);
  const entityId = haEntityId(data.mac, data.hostname);
  const connectedStr = data.connectedSince ? formatConnectedSince(data.connectedSince) : '';
  const leaseStr = data.dhcpExpires ? formatLeaseExpiry(data.dhcpExpires) : '';

  return (
    <>
      <div className="detail-section">
        <div className="detail-section__heading">Gerät</div>
        <Row label="Name"       value={data.name || data.mac} />
        <Row label="IP"         value={data.ip || '—'} />
        <Row label="Hostname"   value={data.hostname !== data.mac ? data.hostname : '—'} />
        <Row label="Hersteller" value={data.manufacturer ?? '—'} />
        <Row label="Status"     value={<StatusBadge status={data.status} />} />
      </div>
      <div className="detail-section">
        <div className="detail-section__heading">Netzwerk</div>
        <Row label="MAC"    value={data.mac} />
        <Row label="Band"   value={data.band || '—'} />
        <Row label="AP"     value={apName} />
        {connectedStr && <Row label="Verbunden seit" value={connectedStr} />}
        {leaseStr     && <Row label="Lease bis"      value={leaseStr} />}
      </div>
      <div className="detail-section">
        <div className="detail-section__heading">Signal</div>
        <Row label="Signal"   value={<><SignalBar dbm={data.signal} /> {data.signal} dBm</>} />
        <Row label="Qualität" value={q} />
      </div>

      {(data.rxBytes != null || data.txBytes != null) && (
        <div className="detail-section">
          <div className="detail-section__heading">Daten (Session)</div>
          <BytesBars rx={data.rxBytes ?? 0} tx={data.txBytes ?? 0} />
        </div>
      )}

      {actions && (
        <div className="inspector-actions">
          <ActionBtn icon="◎" label="AP Fokus" onClick={() => actions.onFocusNode(data.apId)} />
          <ActionBtn icon="⚠" label="Alarme"   onClick={actions.onShowAlerts} />
        </div>
      )}

      {/* ── HA entity link ── */}
      <a
        className="detail-ha-link"
        href={`/config/entities/edit/${entityId}`}
        title={`Entity: ${entityId}`}
      >
        In HA anzeigen →
      </a>
    </>
  );
}

// ── Mini traffic / resource bars ─────────────────────────────────────────

function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000)     return `${(bps / 1_000).toFixed(0)} kbps`;
  return `${bps} bps`;
}

function formatBytes(b: number): string {
  if (b >= 1_073_741_824) return `${(b / 1_073_741_824).toFixed(2)} GB`;
  if (b >= 1_048_576)     return `${(b / 1_048_576).toFixed(1)} MB`;
  if (b >= 1_024)         return `${(b / 1_024).toFixed(0)} KB`;
  return `${b} B`;
}

function MiniBar({ label, pct, color, value }: {
  label: string; pct: number; color: string; value: string;
}) {
  return (
    <div className="mini-bar">
      <span className="mini-bar__label">{label}</span>
      <div className="mini-bar__track">
        <div className="mini-bar__fill" style={{ width: `${Math.min(100, pct)}%`, background: color }} />
      </div>
      <span className="mini-bar__value">{value}</span>
    </div>
  );
}

function WanTrafficBars({ down, up }: { down: number; up: number }) {
  const max = Math.max(down, up, 1);
  return (
    <div className="mini-bar-group">
      <MiniBar label="↓" pct={down / max * 100} color="var(--accent)"  value={formatBps(down)} />
      <MiniBar label="↑" pct={up   / max * 100} color="var(--success)" value={formatBps(up)} />
    </div>
  );
}

function BytesBars({ rx, tx }: { rx: number; tx: number }) {
  const max = Math.max(rx, tx, 1);
  return (
    <div className="mini-bar-group">
      <MiniBar label="RX" pct={rx / max * 100} color="var(--accent)"  value={formatBytes(rx)} />
      <MiniBar label="TX" pct={tx / max * 100} color="var(--success)" value={formatBytes(tx)} />
    </div>
  );
}

function ResourceBars({ cpu, mem }: { cpu?: number; mem?: number }) {
  return (
    <div className="mini-bar-group">
      {cpu != null && (
        <MiniBar
          label="CPU" pct={cpu}
          color={cpu > 80 ? 'var(--danger)' : cpu > 60 ? 'var(--warning)' : 'var(--success)'}
          value={`${cpu.toFixed(0)}%`}
        />
      )}
      {mem != null && (
        <MiniBar
          label="RAM" pct={mem}
          color={mem > 85 ? 'var(--danger)' : mem > 70 ? 'var(--warning)' : 'var(--accent)'}
          value={`${mem.toFixed(0)}%`}
        />
      )}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────

function SsidList({ ssids }: { ssids: SsidInfo[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {ssids.map((s, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 11.5, color: 'var(--text-primary)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {s.ssid}
          </span>
          <span style={{ display: 'flex', gap: 5, flexShrink: 0 }}>
            {s.band && (
              <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 4, background: 'rgba(59,130,246,0.15)', color: '#93c5fd' }}>
                {s.band}
              </span>
            )}
            {s.channel && (
              <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 4, background: 'rgba(255,255,255,0.07)', color: 'var(--text-secondary)' }}>
                ch{s.channel}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

function PortList({ ports }: { ports: PortStat[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {ports.map(p => (
        <div key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
            background: p.up ? 'var(--green)' : 'var(--text-muted)',
            boxShadow: p.up ? '0 0 5px rgba(34,197,94,0.6)' : 'none',
          }} />
          <span style={{ fontSize: 11.5, color: p.up ? 'var(--text-primary)' : 'var(--text-muted)', flex: 1 }}>
            {p.name}
          </span>
          {p.up && p.speed_mbps != null && (
            <span style={{ fontSize: 10.5, color: 'var(--green)', fontWeight: 500 }}>
              {p.speed_mbps >= 1000 ? `${p.speed_mbps / 1000}G` : `${p.speed_mbps}M`}
            </span>
          )}
          {!p.up && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>no link</span>
          )}
        </div>
      ))}
    </div>
  );
}

function VlanList({ vlans }: { vlans: VlanInfo[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {vlans.map(v => (
        <div key={v.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
            background: v.status === 'up' ? 'var(--green)' : v.status === 'down' ? 'var(--red)' : 'var(--text-muted)',
          }} />
          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent, #60a5fa)', minWidth: 52 }}>
            VLAN {v.id}
          </span>
          <span style={{ fontSize: 10.5, color: 'var(--text-secondary)', flex: 1 }}>
            {v.interface}
          </span>
          <span style={{ fontSize: 10, color: v.status === 'up' ? 'var(--green)' : 'var(--text-muted)' }}>
            {v.status}
          </span>
        </div>
      ))}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <span>{value}</span>
    </div>
  );
}

/** Dot + text label — more readable than a bare 7px dot in a detail row. */
function StatusBadge({ status }: { status: NodeStatus }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
      <StatusDot status={status} />
      {statusLabel(status)}
    </span>
  );
}
