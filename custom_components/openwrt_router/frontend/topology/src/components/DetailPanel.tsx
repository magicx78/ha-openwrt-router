/**
 * DetailPanel — Slide-in right panel showing details for a selected node.
 *
 * Handles three entity types: Gateway, AccessPoint, Client.
 * All data is passed in via props; the panel has no data-fetching logic.
 */

import React, { useState } from 'react';
import { Gateway, AccessPoint, Client, NodeStatus, DdnsService } from '../types';
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

interface Props {
  entity: SelectedEntity;
  onClose: () => void;
}

export function DetailPanel({ entity, onClose }: Props) {
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
        {entity?.type === 'gateway' && <GatewayDetail data={entity.data} />}
        {entity?.type === 'ap'      && <APDetail data={entity.data} clients={entity.clients} />}
        {entity?.type === 'client'  && <ClientDetail data={entity.data} apName={entity.apName} />}
      </div>
    </div>
  );
}

// ── Gateway detail ────────────────────────────────────────────────────────

function GatewayDetail({ data }: { data: Gateway }) {
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
      </div>
      <div className="detail-section">
        <div className="detail-section__heading">Netzwerk</div>
        <Row label="LAN IP"  value={data.ip} />
        <Row label="WAN IP"  value={data.wanIp} />
        <Row label="Uptime"  value={data.uptime} />
        {hasPing && <Row label="Ping (8.8.8.8)" value={`${data.pingMs} ms`} />}
      </div>

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

      {(data.ddnsServices ?? []).length > 0 && (
        <div className="detail-section">
          <div className="detail-section__heading">DuckDNS / DDNS</div>
          {(data.ddnsServices ?? []).map(svc => (
            <DdnsRow key={svc.section} svc={svc} />
          ))}
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

function APDetail({ data, clients }: { data: AccessPoint; clients: Client[] }) {
  const q = signalQuality(data.backhaulSignal);
  return (
    <>
      <div className="detail-section">
        <div className="detail-section__heading">Allgemein</div>
        <Row label="Name"    value={data.name} />
        <Row label="Modell"  value={data.model} />
        <Row label="IP"      value={data.ip} />
        <Row label="Status"  value={<StatusDot status={data.status} />} />
      </div>
      <div className="detail-section">
        <div className="detail-section__heading">Uplink</div>
        <Row label="Typ"     value={data.uplinkType === 'wired' ? 'Kabelgebunden' : 'Mesh'} />
        <Row label="Signal"  value={<><SignalBar dbm={data.backhaulSignal} /> {data.backhaulSignal} dBm</>} />
        <Row label="Qualität" value={q} />
      </div>
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

function ClientDetail({ data, apName }: { data: Client; apName: string }) {
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

// ── Helpers ───────────────────────────────────────────────────────────────

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
