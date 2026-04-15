import React from 'react';
import { Gateway, NodeLayout } from '../types';
import { StatusDot } from './StatusDot';
import { IconRouter, IconSignal } from './Icons';

interface Props {
  gateway: Gateway;
  layout: NodeLayout;
  selected: boolean;
  dimmed: boolean;
  onSelect: () => void;
  onHover: (id: string | null) => void;
  clientCount?: number;
}

export function GatewayNode({ gateway, layout, selected, dimmed, onSelect, onHover, clientCount }: Props) {
  const cls = [
    'node-card gateway-card',
    selected ? 'selected' : '',
    dimmed ? 'dimmed' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={cls}
      style={{ left: layout.cx, top: layout.cy }}
      onClick={onSelect}
      onMouseEnter={() => onHover(gateway.id)}
      onMouseLeave={() => onHover(null)}
    >
      <div className="gateway-card__header">
        <div className="gateway-card__icon">
          <IconRouter size={18} />
        </div>
        <div>
          <div className="gateway-card__name">{gateway.name}</div>
          <div className="gateway-card__model">{gateway.model}</div>
        </div>
        <StatusDot status={gateway.status} />
      </div>
      <div className="gateway-card__meta">
        <div className="gateway-card__row">
          <span>LAN</span>
          <span>{gateway.ip}</span>
        </div>
        <div className="gateway-card__row">
          <span>WAN</span>
          <span>{gateway.wanIp}</span>
        </div>
        <div className="gateway-card__row">
          <span>Uptime</span>
          <span>{gateway.uptime}</span>
        </div>
        {clientCount != null && clientCount > 0 && (
          <div className="gateway-card__row">
            <span>Clients</span>
            <span><strong>{clientCount}</strong></span>
          </div>
        )}
      </div>
    </div>
  );
}
