/**
 * AlertsView — shows all devices and clients that are offline or in warning state.
 * Groups by severity section. Empty state when everything is healthy.
 */

import React from 'react';
import { TopologyData, AccessPoint, Client, NodeStatus } from '../types';
import { StatusDot } from './StatusDot';
import { IconRouter, IconAP, IconSmartphone, IconLaptop, IconIoT, IconGuest, IconOther } from './Icons';

interface Props {
  data: TopologyData;
  onSelectGateway: () => void;
  onSelectAP: (ap: AccessPoint) => void;
  onSelectClient: (client: Client) => void;
}

function ClientIcon({ category }: { category: Client['category'] }) {
  const s = 14;
  switch (category) {
    case 'smartphone': return <IconSmartphone size={s} />;
    case 'laptop':     return <IconLaptop size={s} />;
    case 'iot':        return <IconIoT size={s} />;
    case 'guest':      return <IconGuest size={s} />;
    default:           return <IconOther size={s} />;
  }
}

export function AlertsView({ data, onSelectGateway, onSelectAP, onSelectClient }: Props) {
  const offlineNodes   = data.accessPoints.filter(a => a.status === 'offline');
  const warningNodes   = data.accessPoints.filter(a => a.status === 'warning');
  const offlineClients = data.clients.filter(c => c.status === 'offline');
  const warningClients = data.clients.filter(c => c.status === 'warning');
  const gwOffline      = data.gateway.status !== 'online';

  const total = offlineNodes.length + warningNodes.length + offlineClients.length + warningClients.length + (gwOffline ? 1 : 0);

  if (total === 0) {
    return (
      <div className="topo-view">
        <div className="view-header">
          <span className="view-title">Alarme</span>
          <span className="view-count">0 Probleme</span>
        </div>
        <div className="alert-empty">
          <div className="alert-empty__icon">✓</div>
          <div className="alert-empty__text">Alle Geräte online — keine Alarme</div>
        </div>
      </div>
    );
  }

  // Build AP name lookup
  const apNames = new Map<string, string>();
  apNames.set(data.gateway.id, data.gateway.name);
  data.accessPoints.forEach(ap => apNames.set(ap.id, ap.name));

  return (
    <div className="topo-view">
      <div className="view-header">
        <span className="view-title">Alarme</span>
        <span className="view-count alert-count">{total} Problem{total !== 1 ? 'e' : ''}</span>
      </div>

      {/* Gateway offline */}
      {gwOffline && (
        <AlertSection heading={`Gateway ${data.gateway.status === 'offline' ? 'offline' : 'warnung'}`} severity={data.gateway.status}>
          <AlertNodeRow
            icon={<IconRouter size={16} />}
            name={data.gateway.name}
            sub={data.gateway.model + ' · ' + data.gateway.ip}
            status={data.gateway.status}
            onClick={onSelectGateway}
          />
        </AlertSection>
      )}

      {/* Offline APs */}
      {offlineNodes.length > 0 && (
        <AlertSection heading={`${offlineNodes.length} AP offline`} severity="offline">
          {offlineNodes.map(ap => (
            <AlertNodeRow
              key={ap.id}
              icon={<IconAP size={15} />}
              name={ap.name}
              sub={ap.model + ' · ' + ap.ip}
              status="offline"
              onClick={() => onSelectAP(ap)}
            />
          ))}
        </AlertSection>
      )}

      {/* Warning APs */}
      {warningNodes.length > 0 && (
        <AlertSection heading={`${warningNodes.length} AP mit Warnung`} severity="warning">
          {warningNodes.map(ap => (
            <AlertNodeRow
              key={ap.id}
              icon={<IconAP size={15} />}
              name={ap.name}
              sub={ap.model + ' · ' + ap.ip}
              status="warning"
              onClick={() => onSelectAP(ap)}
            />
          ))}
        </AlertSection>
      )}

      {/* Offline clients */}
      {offlineClients.length > 0 && (
        <AlertSection heading={`${offlineClients.length} Client offline`} severity="offline">
          {offlineClients.map(c => (
            <AlertClientRow
              key={c.id}
              client={c}
              apName={apNames.get(c.apId) ?? c.apId}
              onClick={() => onSelectClient(c)}
            />
          ))}
        </AlertSection>
      )}

      {/* Warning clients */}
      {warningClients.length > 0 && (
        <AlertSection heading={`${warningClients.length} Client mit Warnung`} severity="warning">
          {warningClients.map(c => (
            <AlertClientRow
              key={c.id}
              client={c}
              apName={apNames.get(c.apId) ?? c.apId}
              onClick={() => onSelectClient(c)}
            />
          ))}
        </AlertSection>
      )}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────

function AlertSection({ heading, severity, children }: {
  heading: string;
  severity: NodeStatus;
  children: React.ReactNode;
}) {
  return (
    <div className="alert-section">
      <div className={`alert-section__heading alert-section__heading--${severity}`}>{heading}</div>
      {children}
    </div>
  );
}

function AlertNodeRow({ icon, name, sub, status, onClick }: {
  icon: React.ReactNode;
  name: string;
  sub: string;
  status: NodeStatus;
  onClick: () => void;
}) {
  return (
    <div className={`alert-row alert-row--${status}`} onClick={onClick}>
      <div className="alert-row__icon">{icon}</div>
      <div className="alert-row__info">
        <div className="alert-row__name">{name}</div>
        <div className="alert-row__sub">{sub}</div>
      </div>
      <StatusDot status={status} />
    </div>
  );
}

function AlertClientRow({ client, apName, onClick }: {
  client: Client;
  apName: string;
  onClick: () => void;
}) {
  return (
    <div className={`alert-row alert-row--${client.status}`} onClick={onClick}>
      <div className="alert-row__icon">
        <ClientIcon category={client.category} />
      </div>
      <div className="alert-row__info">
        <div className="alert-row__name">{client.name !== client.mac ? client.name : client.hostname || client.mac}</div>
        <div className="alert-row__sub">{client.ip || client.mac} · {apName}</div>
      </div>
      <StatusDot status={client.status} />
    </div>
  );
}
