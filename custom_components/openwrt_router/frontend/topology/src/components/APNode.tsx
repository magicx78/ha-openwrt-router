import React from 'react';
import { AccessPoint } from '../types';
import { StatusDot } from './StatusDot';
import { IconAP } from './Icons';
import { SignalBar } from './SignalBar';

interface Props {
  ap: AccessPoint;
  selected: boolean;
  dimmed: boolean;
  onSelect: () => void;
  onHover: (id: string | null) => void;
}

export function APNode({ ap, selected, dimmed, onSelect, onHover }: Props) {
  const iconCls = ap.status === 'warning' ? 'warning' : ap.uplinkType;

  const cls = [
    'node-card ap-card',
    selected ? 'selected' : '',
    dimmed ? 'dimmed' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      className={cls}
      onClick={onSelect}
      onMouseEnter={() => onHover(ap.id)}
      onMouseLeave={() => onHover(null)}
    >
      <div className="ap-card__header">
        <div className={`ap-card__icon ${iconCls}`}>
          <IconAP size={16} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="ap-card__name">{ap.name}</div>
          <div className="ap-card__ip">{ap.ip}</div>
        </div>
        <StatusDot status={ap.status} />
      </div>

      <div className="ap-card__footer">
        <span className={`ap-card__badge ${ap.uplinkType}`}>
          {ap.uplinkType === 'wired' ? 'Kabel' : 'Mesh'}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <SignalBar dbm={ap.backhaulSignal} />
          <span className="ap-card__clients">
            <strong>{ap.clientCount}</strong> Clients
          </span>
        </div>
      </div>
    </div>
  );
}
