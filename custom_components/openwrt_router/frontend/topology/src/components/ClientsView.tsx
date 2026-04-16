/**
 * ClientsView — searchable, filterable list of all WiFi clients.
 * Click any row to open the DetailPanel for that client.
 */

import React, { useState, useMemo } from 'react';
import { TopologyData, Client, AccessPoint } from '../types';
import { StatusDot } from './StatusDot';
import { SignalBar } from './SignalBar';
import { IconSearch, IconSmartphone, IconLaptop, IconIoT, IconGuest, IconOther } from './Icons';

interface Props {
  data: TopologyData;
  onSelectClient: (client: Client) => void;
}

type BandFilter  = 'all' | '2.4' | '5' | '6';
type StatusFilter = 'all' | 'online' | 'offline';

function CategoryIcon({ category }: { category: Client['category'] }) {
  const s = 13;
  switch (category) {
    case 'smartphone': return <IconSmartphone size={s} />;
    case 'laptop':     return <IconLaptop size={s} />;
    case 'iot':        return <IconIoT size={s} />;
    case 'guest':      return <IconGuest size={s} />;
    default:           return <IconOther size={s} />;
  }
}

export function ClientsView({ data, onSelectClient }: Props) {
  const [search,     setSearch]     = useState('');
  const [bandFilter, setBandFilter] = useState<BandFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  // Build AP name lookup
  const apNames = useMemo<Map<string, string>>(() => {
    const m = new Map<string, string>();
    m.set(data.gateway.id, data.gateway.name);
    data.accessPoints.forEach(ap => m.set(ap.id, ap.name));
    return m;
  }, [data]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return data.clients.filter(c => {
      if (bandFilter !== 'all') {
        const band = c.band.toLowerCase();
        if (bandFilter === '2.4' && !band.includes('2.4')) return false;
        if (bandFilter === '5'   && !band.includes('5g') && !band.includes('5 ')) return false;
        if (bandFilter === '6'   && !band.includes('6'))  return false;
      }
      if (statusFilter === 'online'  && c.status !== 'online')  return false;
      if (statusFilter === 'offline' && c.status === 'online')  return false;
      if (q) {
        return (
          c.name.toLowerCase().includes(q) ||
          c.hostname.toLowerCase().includes(q) ||
          c.ip.includes(q) ||
          c.mac.toLowerCase().includes(q) ||
          (c.manufacturer ?? '').toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [data.clients, bandFilter, statusFilter, search]);

  const bands = useMemo(() => {
    const set = new Set<string>();
    data.clients.forEach(c => {
      const b = c.band.toLowerCase();
      if (b.includes('2.4')) set.add('2.4');
      else if (b.includes('6')) set.add('6');
      else if (b.includes('5')) set.add('5');
    });
    return set;
  }, [data.clients]);

  return (
    <div className="topo-view">
      {/* Header + search */}
      <div className="view-header">
        <span className="view-title">Clients</span>
        <span className="view-count">{filtered.length} / {data.clients.length}</span>
      </div>

      {/* Search */}
      <div className="view-search">
        <IconSearch size={13} />
        <input
          type="text"
          placeholder="Name, IP, MAC, Hersteller…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {/* Filters */}
      <div className="view-filters">
        {(['all', '2.4', '5', '6'] as BandFilter[])
          .filter(b => b === 'all' || bands.has(b))
          .map(b => (
            <button
              key={b}
              className={`filter-btn${bandFilter === b ? ' active' : ''}`}
              onClick={() => setBandFilter(b)}
            >
              {b === 'all' ? 'Alle Bänder' : `${b} GHz`}
            </button>
          ))}
        <span className="view-filters__sep" />
        {(['all', 'online', 'offline'] as StatusFilter[]).map(s => (
          <button
            key={s}
            className={`filter-btn${statusFilter === s ? ' active' : ''}`}
            onClick={() => setStatusFilter(s)}
          >
            {s === 'all' ? 'Alle Status' : s === 'online' ? 'Online' : 'Offline'}
          </button>
        ))}
      </div>

      {/* Client list */}
      {filtered.length === 0 ? (
        <div className="view-empty">Keine Clients gefunden</div>
      ) : (
        <div className="client-list">
          {filtered.map(client => (
            <ClientRow
              key={client.id}
              client={client}
              apName={apNames.get(client.apId) ?? client.apId}
              onClick={() => onSelectClient(client)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface ClientRowProps {
  client: Client;
  apName: string;
  onClick: () => void;
}

function ClientRow({ client, apName, onClick }: ClientRowProps) {
  return (
    <div className="client-row" onClick={onClick}>
      <div className="client-row__icon">
        <CategoryIcon category={client.category} />
      </div>
      <div className="client-row__info">
        <div className="client-row__name">{client.name !== client.mac ? client.name : client.hostname || client.mac}</div>
        <div className="client-row__sub">
          {client.ip || '—'}
          {client.manufacturer ? ` · ${client.manufacturer}` : ''}
        </div>
      </div>
      <div className="client-row__signal">
        <SignalBar dbm={client.signal} />
        <span className="client-row__dbm">{client.signal} dBm</span>
      </div>
      <span className="client-row__band">{client.band}</span>
      <span className="client-row__ap">{apName}</span>
      <StatusDot status={client.status} />
    </div>
  );
}
