import React from 'react';
import { Gateway } from '../types';
import { StatusDot } from './StatusDot';
import { IconRouter } from './Icons';

interface Props {
  gateway: Gateway;
  selected: boolean;
  dimmed: boolean;
  onSelect: () => void;
  onHover: (id: string | null) => void;
  clientCount?: number;
}

export function GatewayNode({ gateway, selected, dimmed, onSelect, onHover, clientCount }: Props) {
  const statusClass = gateway.status === 'online'
    ? 'status-online'
    : gateway.status === 'warning'
      ? 'status-warning'
      : 'status-offline';

  const cls = [
    'node-card gateway-card',
    statusClass,
    selected ? 'selected' : '',
    dimmed ? 'dimmed' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={cls}
      onClick={onSelect}
      onMouseEnter={() => onHover(gateway.id)}
      onMouseLeave={() => onHover(null)}
    >
      <div className="gateway-card__header">
        <div className="gateway-card__icon">
          <IconRouter size={18} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="gateway-card__name">{gateway.name}</div>
          <div className="gateway-card__model">{gateway.model}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <StatusDot status={gateway.status} />
          <span className="gateway-card__role">Gateway</span>
        </div>
      </div>

      <div className="gateway-card__sep" />

      <div className="gateway-card__meta">
        <div className="gateway-card__row">
          <span>LAN</span>
          <span>{gateway.ip}</span>
        </div>
        <div className="gateway-card__row">
          <span>WAN</span>
          <span>{gateway.wanIp || '—'}</span>
        </div>
        <div className="gateway-card__row">
          <span>Uptime</span>
          <span>{gateway.uptime}</span>
        </div>
      </div>

      {clientCount != null && clientCount > 0 && (
        <>
          <div className="gateway-card__sep" />
          <div className="gateway-card__footer">
            <span>{clientCount} direkte Clients</span>
          </div>
        </>
      )}
    </div>
  );
}
