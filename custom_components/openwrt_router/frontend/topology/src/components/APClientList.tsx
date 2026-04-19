import React from 'react';
import { Client } from '../types';
import { StatusDot } from './StatusDot';

interface Props {
  clients: Client[];
  onSelectClient: (c: Client) => void;
}

function signalBar(dbm: number): string {
  if (dbm >= -55) return '████';
  if (dbm >= -65) return '███░';
  if (dbm >= -75) return '██░░';
  return '█░░░';
}

function signalClass(dbm: number): string {
  if (dbm >= -55) return 'sig-excellent';
  if (dbm >= -65) return 'sig-good';
  if (dbm >= -75) return 'sig-fair';
  return 'sig-poor';
}

export function APClientList({ clients, onSelectClient }: Props) {
  if (clients.length === 0) {
    return <div className="ap-client-list ap-client-list--empty">Keine Clients</div>;
  }

  return (
    <div className="ap-client-list">
      {clients.map(c => (
        <button
          key={c.id}
          className="ap-client-list__row"
          onClick={e => { e.stopPropagation(); onSelectClient(c); }}
        >
          <StatusDot status={c.status} />
          <span className="ap-client-list__name">{c.name || c.hostname}</span>
          <span className="ap-client-list__ip">{c.ip}</span>
          <span className={`ap-client-list__sig ${signalClass(c.signal)}`}>
            {signalBar(c.signal)}
          </span>
          <span className="ap-client-list__band">{c.band}</span>
        </button>
      ))}
    </div>
  );
}
