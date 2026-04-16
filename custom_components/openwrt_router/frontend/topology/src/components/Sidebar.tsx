import React from 'react';
import {
  IconTopology,
  IconDevices,
  IconClients,
  IconAlerts,
  IconSettings,
  IconChevronLeft,
  IconChevronRight,
} from './Icons';

export type SidebarTab = 'topology' | 'devices' | 'clients' | 'alerts' | 'settings';

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
  onToggle: () => void;
  onTabChange: (tab: SidebarTab) => void;
}

export function Sidebar({ open, activeTab, warningCount, onToggle, onTabChange }: Props) {
  const items: NavItem[] = [
    { id: 'topology', label: 'Topologie',  Icon: IconTopology },
    { id: 'devices',  label: 'Geräte',     Icon: IconDevices },
    { id: 'clients',  label: 'Clients',    Icon: IconClients },
    { id: 'alerts',   label: 'Alarme',     Icon: IconAlerts,  badge: warningCount > 0 ? warningCount : undefined },
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
