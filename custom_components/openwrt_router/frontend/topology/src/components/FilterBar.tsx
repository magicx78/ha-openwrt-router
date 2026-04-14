import React from 'react';
import { FilterType } from '../types';
import { IconSearch } from './Icons';

interface Props {
  filter: FilterType;
  searchQuery: string;
  totalClients: number;
  warningCount: number;
  onFilterChange: (f: FilterType) => void;
  onSearchChange: (q: string) => void;
}

const FILTERS: { key: FilterType; label: string }[] = [
  { key: 'all',      label: 'Alle' },
  { key: 'aps',      label: 'APs' },
  { key: 'clients',  label: 'Clients' },
  { key: 'warnings', label: 'Warnungen' },
];

export function FilterBar({
  filter,
  searchQuery,
  totalClients,
  warningCount,
  onFilterChange,
  onSearchChange,
}: Props) {
  return (
    <div className="filter-bar">
      <span className="filter-bar__title">Topology</span>

      {FILTERS.map(f => (
        <button
          key={f.key}
          className={`filter-btn ${filter === f.key ? 'active' : ''}`}
          onClick={() => onFilterChange(f.key)}
        >
          {f.label}
          {f.key === 'warnings' && warningCount > 0 && (
            <span style={{
              marginLeft: 5,
              background: 'rgba(245,158,11,0.2)',
              color: '#f59e0b',
              borderRadius: 100,
              padding: '0 5px',
              fontSize: 10,
              fontWeight: 700,
            }}>
              {warningCount}
            </span>
          )}
        </button>
      ))}

      <span className="filter-bar__sep" />

      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        {totalClients} Clients
      </span>

      <div className="filter-search">
        <IconSearch size={13} />
        <input
          type="text"
          placeholder="Gerät suchen…"
          value={searchQuery}
          onChange={e => onSearchChange(e.target.value)}
        />
      </div>
    </div>
  );
}
