/**
 * ClientStrip — Compact row of client dots below each AP/Gateway node.
 *
 * Shows up to MAX_VISIBLE client dots. Each dot is color-coded by status
 * and carries a category icon. Hovering reveals a tooltip with client info.
 * Clicking opens the detail panel (via onSelect callback).
 */

import React, { useState } from 'react';
import { Client, DeviceCategory } from '../types';
import {
  IconSmartphone,
  IconLaptop,
  IconIoT,
  IconGuest,
  IconOther,
} from './Icons';
import { signalQuality } from '../layout';

const MAX_VISIBLE = 8;

interface Props {
  clients: Client[];
  dimmed: boolean;
  onSelectClient: (client: Client) => void;
  vlanMode?: boolean;
}

export function ClientStrip({ clients, dimmed, onSelectClient, vlanMode }: Props) {
  const visible  = clients.slice(0, MAX_VISIBLE);
  const overflow = clients.length - MAX_VISIBLE;

  return (
    <div
      className="client-strip"
      style={{
        opacity:    dimmed ? 0.2 : 1,
        transition: 'opacity 0.2s ease',
      }}
    >
      {visible.map(client => (
        <ClientDot
          key={client.id}
          client={client}
          onSelect={() => onSelectClient(client)}
          vlanMode={vlanMode}
        />
      ))}
      {overflow > 0 && (
        <span className="client-dot-overflow">+{overflow}</span>
      )}
    </div>
  );
}

// ── Individual client dot ─────────────────────────────────────────────────

interface DotProps {
  client: Client;
  onSelect: () => void;
  vlanMode?: boolean;
}

function ClientDot({ client, onSelect, vlanMode }: DotProps) {
  const [showTooltip, setShowTooltip] = useState(false);
  const q = signalQuality(client.signal);

  return (
    <div
      className={`client-dot ${client.status}`}
      data-vlan={vlanMode && client.vlanId != null ? client.vlanId : undefined}
      onClick={e => { e.stopPropagation(); onSelect(); }}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <CategoryIcon category={client.category} />
      {showTooltip && (
        <div className="client-tooltip">
          <div className="client-tooltip__name">{client.name}</div>
          <div className="client-tooltip__meta">
            {client.ip} · {client.band} · {client.signal} dBm ({q})
          </div>
        </div>
      )}
    </div>
  );
}

function CategoryIcon({ category }: { category: DeviceCategory }) {
  switch (category) {
    case 'smartphone': return <IconSmartphone size={12} />;
    case 'laptop':     return <IconLaptop size={12} />;
    case 'iot':        return <IconIoT size={12} />;
    case 'guest':      return <IconGuest size={12} />;
    default:           return <IconOther size={12} />;
  }
}
