import React from 'react';
import {
  IconTopology,
  IconDevices,
  IconClients,
  IconAlerts,
  IconTraffic,
  IconSettings,
  IconChevronLeft,
  IconChevronRight,
  IconCompare,
  IconWiring,
  IconDiagnose,
  IconEnterprise,
} from './Icons';

export type SidebarTab = 'topology' | 'devices' | 'clients' | 'traffic' | 'alerts' | 'diagnose' | 'compare' | 'wiring' | 'enterprise' | 'settings';

interface NavItem {
  id: SidebarTab;
  label: string;
  Icon: React.FC<{ size?: number; className?: string }>;
  badge?: number;
}

interface Props {
  open: boolean;
  activeTab: SidebarTab;
  warningCount: number;
  /** Open root incidents (critical + warning) from the snapshot (P7); undefined hides the tab badge. */
  diagnoseCount?: number;
  /** False hides the Diagnose tab (network intelligence not running). */
  showDiagnose?: boolean;
  onToggle: () => void;
  onTabChange: (tab: SidebarTab) => void;
}

export function Sidebar({ open, activeTab, warningCount, diagnoseCount, showDiagnose = true, onToggle, onTabChange }: Props) {
  const items: NavItem[] = [
    { id: 'topology', label: 'Topologie',  Icon: IconTopology },
    { id: 'devices',  label: 'Geräte',     Icon: IconDevices },
    { id: 'wiring',   label: 'Verkabelung', Icon: IconWiring },
    { id: 'clients',  label: 'Clients',    Icon: IconClients },
    { id: 'traffic',  label: 'Traffic',    Icon: IconTraffic },
    { id: 'alerts',   label: 'Alarme',     Icon: IconAlerts,  badge: warningCount > 0 ? warningCount : undefined },
    ...(showDiagnose
      ? [{ id: 'diagnose' as const, label: 'Diagnose', Icon: IconDiagnose, badge: diagnoseCount && diagnoseCount > 0 ? diagnoseCount : undefined }]
      : []),
    { id: 'compare',  label: 'Vergleich',  Icon: IconCompare },
    { id: 'enterprise', label: 'Enterprise', Icon: IconEnterprise },
    { id: 'settings', label: 'Einst.',     Icon: IconSettings },
  ];

  return (
    <div className={`topo-sidebar${open ? ' open' : ''}`}>
      {/* Toggle button */}
      <button className="sidebar-toggle" onClick={onToggle} title={open ? 'Einklappen' : 'Ausklappen'}>
        {open ? <IconChevronLeft size={16} /> : <IconChevronRight size={16} />}
      </button>

      {/* Navigation items */}
      <nav className="sidebar-nav">
        {items.map(({ id, label, Icon, badge }) => (
          <button
            key={id}
            className={`sidebar-item${activeTab === id ? ' active' : ''}`}
            title={!open ? label : undefined}
            aria-label={badge ? `${label} (${badge})` : label}
            onClick={() => onTabChange(id)}
          >
            <span
              className="sidebar-item__icon sidebar-item__icon-badge"
              data-count={badge ?? 0}
            >
              <Icon size={18} />
            </span>
            <span className="sidebar-item__label">{label}</span>
            {badge != null && badge > 0 && (
              <span className="sidebar-badge">{badge}</span>
            )}
          </button>
        ))}
      </nav>
    </div>
  );
}
