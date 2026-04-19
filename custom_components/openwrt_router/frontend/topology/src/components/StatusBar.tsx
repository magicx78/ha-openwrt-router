import React from 'react';
import { FilterType } from '../types';
import { GroupBy } from '../TopologyView';
import { IconSearch, IconFitView, IconTraffic, IconVlan } from './Icons';

// Simple heatmap icon (signal waves)
function IconHeatmap({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="8" cy="10" r="2" />
      <path d="M5 8a4 4 0 0 1 6 0" />
      <path d="M3 6a7 7 0 0 1 10 0" />
    </svg>
  );
}

interface Props {
  filter: FilterType;
  searchQuery: string;
  totalNodes: number;
  onlineNodes: number;
  totalClients: number;
  warningCount: number;
  pingMs: number | null | undefined;
  trafficMode: boolean;
  heatmapMode: boolean;
  ghostMode: boolean;
  vlanMode: boolean;
  healthMode: boolean;
  groupBy: GroupBy;
  topologyControls?: boolean;
  onFilterChange: (f: FilterType) => void;
  onSearchChange: (q: string) => void;
  onFitView: () => void;
  onToggleTraffic: () => void;
  onToggleHeatmap: () => void;
  onToggleGhost: () => void;
  onToggleVlan: () => void;
  onToggleHealth: () => void;
  onGroupByChange: (g: GroupBy) => void;
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
  trafficMode,
  heatmapMode,
  ghostMode,
  vlanMode,
  healthMode,
  groupBy,
  topologyControls = true,
  onFilterChange,
  onSearchChange,
  onFitView,
  onToggleTraffic,
  onToggleHeatmap,
  onToggleGhost,
  onToggleVlan,
  onToggleHealth,
  onGroupByChange,
}: Props) {
  const allOnline = onlineNodes === totalNodes;
  const healthClass = warningCount === 0 ? 'health-ok' : warningCount <= 2 ? 'health-warn' : 'health-crit';
  const healthLabel = warningCount === 0 ? 'OK' : `${warningCount} Probleme`;

  return (
    <div className="status-bar">
      {/* ── Health banner ─────────────────────────────────────── */}
      <div className={`status-bar__health ${healthClass}`}>
        <span className="status-bar__health-dot" />
        <span>{healthLabel}</span>
      </div>

      <span className="status-bar__divider" />

      {/* ── Stats ──────────────────────────────────────────────── */}
      <div className="status-bar__stats">
        <span className="status-bar__stat">
          Nodes&nbsp;<strong className={allOnline ? '' : 'warn'}>{onlineNodes}/{totalNodes}</strong>
        </span>
        <span className="status-bar__stat">
          Clients&nbsp;<strong>{totalClients}</strong>
        </span>
        {pingMs != null && pingMs > 0 && (
          <span className="status-bar__stat status-bar__stat--ping">
            Ping&nbsp;<strong>{pingMs}&nbsp;ms</strong>
          </span>
        )}
      </div>

      {topologyControls && (
        <>
          <span className="status-bar__divider" />

          {/* ── Filters ──────────────────────────────────────────── */}
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

          {/* ── Search ───────────────────────────────────────────── */}
          <div className="status-bar__search">
            <IconSearch size={13} />
            <input
              type="text"
              placeholder="Gerät suchen…"
              value={searchQuery}
              onChange={e => onSearchChange(e.target.value)}
            />
          </div>

          {/* ── Health mode toggle ───────────────────────────────── */}
          <button
            className={`status-bar__action${healthMode ? ' active' : ''}`}
            onClick={onToggleHealth}
            title={healthMode ? 'Health-Modus ausschalten' : 'Health-Modus einschalten'}
          >
            <span style={{ fontSize: 13, lineHeight: 1 }}>♥</span>
          </button>

          {/* ── Heatmap toggle ───────────────────────────────────── */}
          <button
            className={`status-bar__action${heatmapMode ? ' active' : ''}`}
            onClick={onToggleHeatmap}
            title={heatmapMode ? 'Heatmap ausschalten' : 'WLAN Heatmap einschalten'}
          >
            <IconHeatmap size={15} />
          </button>

          {/* ── Ghost toggle ─────────────────────────────────────── */}
          <button
            className={`status-bar__action${ghostMode ? ' active' : ''}`}
            onClick={onToggleGhost}
            title={ghostMode ? 'Ghost-Modus ausschalten' : 'Verschwundene Geräte anzeigen'}
          >
            <span style={{ fontSize: 13, lineHeight: 1 }}>👻</span>
          </button>

          {/* ── VLAN toggle ──────────────────────────────────────── */}
          <button
            className={`status-bar__action${vlanMode ? ' active' : ''}`}
            onClick={onToggleVlan}
            title={vlanMode ? 'VLAN-Overlay ausschalten' : 'VLAN-Overlay einschalten'}
          >
            <IconVlan size={15} />
          </button>

          {/* ── Traffic toggle ───────────────────────────────────── */}
          <button
            className={`status-bar__action${trafficMode ? ' active' : ''}`}
            onClick={onToggleTraffic}
            title={trafficMode ? 'Traffic-Overlay ausschalten' : 'Traffic-Overlay einschalten'}
          >
            <IconTraffic size={15} />
          </button>

          {/* ── Grouping selector ────────────────────────────────── */}
          <select
            className={`status-bar__select${groupBy !== 'none' ? ' active' : ''}`}
            value={groupBy}
            onChange={e => onGroupByChange(e.target.value as GroupBy)}
            title="APs gruppieren"
          >
            <option value="none">Gruppe: Aus</option>
            <option value="type">Nach Typ</option>
            <option value="vlan">Nach VLAN</option>
            <option value="status">Nach Status</option>
          </select>

          {/* ── Fit-view button ──────────────────────────────────── */}
          <button
            className="status-bar__action"
            onClick={onFitView}
            title="Ansicht anpassen"
          >
            <IconFitView size={15} />
          </button>
        </>
      )}
    </div>
  );
}
