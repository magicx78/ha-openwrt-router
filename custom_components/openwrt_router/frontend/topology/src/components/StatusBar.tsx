import React from 'react';
import { FilterType } from '../types';
import { IconSearch, IconFitView } from './Icons';

interface Props {
  filter: FilterType;
  searchQuery: string;
  totalNodes: number;
  onlineNodes: number;
  totalClients: number;
  warningCount: number;
  pingMs: number | null | undefined;
  onFilterChange: (f: FilterType) => void;
  onSearchChange: (q: string) => void;
  onFitView: () => void;
}

const FILTERS: { key: FilterType; label: string }[] = [
  { key: 'all',      label: 'Alle' },
  { key: 'aps',      label: 'APs' },
  { key: 'clients',  label: 'Clients' },
  { key: 'warnings', label: 'Warnungen' },
];

export function StatusBar({
  filter,
  searchQuery,
  totalNodes,
  onlineNodes,
  totalClients,
  warningCount,
  pingMs,
  onFilterChange,
  onSearchChange,
  onFitView,
}: Props) {
  const allOnline = onlineNodes === totalNodes;

  return (
    <div className="status-bar">
      {/* ── Stats ──────────────────────────────────────────────── */}
      <div className="status-bar__stats">
        <span className="status-bar__stat">
          Nodes&nbsp;<strong className={allOnline ? '' : 'warn'}>{onlineNodes}/{totalNodes}</strong>
        </span>
        <span className="status-bar__stat">
          Clients&nbsp;<strong>{totalClients}</strong>
        </span>
        {warningCount > 0 && (
          <span className="status-bar__stat status-bar__stat--warn">
            <strong>{warningCount}</strong>&nbsp;Warnungen
          </span>
        )}
        {pingMs != null && (
          <span className="status-bar__stat status-bar__stat--ping">
            Ping&nbsp;<strong>{pingMs}&nbsp;ms</strong>
          </span>
        )}
      </div>

      <span className="status-bar__divider" />

      {/* ── Filters ────────────────────────────────────────────── */}
      <div className="status-bar__filters">
        {FILTERS.map(f => (
          <button
            key={f.key}
            className={`filter-btn ${filter === f.key ? 'active' : ''}`}
            onClick={() => onFilterChange(f.key)}
          >
            {f.label}
            {f.key === 'warnings' && warningCount > 0 && (
              <span className="filter-btn__badge">{warningCount}</span>
            )}
          </button>
        ))}
      </div>

      <span className="status-bar__gap" />

      {/* ── Search ─────────────────────────────────────────────── */}
      <div className="status-bar__search">
        <IconSearch size={13} />
        <input
          type="text"
          placeholder="Gerät suchen…"
          value={searchQuery}
          onChange={e => onSearchChange(e.target.value)}
        />
      </div>

      {/* ── Fit-view button ────────────────────────────────────── */}
      <button
        className="status-bar__action"
        onClick={onFitView}
        title="Ansicht anpassen"
      >
        <IconFitView size={15} />
      </button>
    </div>
  );
}
