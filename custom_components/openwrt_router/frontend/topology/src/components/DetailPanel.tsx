/**
 * DetailPanel — Slide-in right panel showing details for a selected node.
 *
 * Handles three entity types: Gateway, AccessPoint, Client.
 * All data is passed in via props; the panel has no data-fetching logic.
 */

import React from 'react';
import { Gateway, AccessPoint, Client, NodeStatus } from '../types';
import { IconX } from './Icons';
import { StatusDot, statusLabel } from './StatusDot';
import { SignalBar } from './SignalBar';
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
      </div>
    </>
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
