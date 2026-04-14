import React from 'react';
import { signalQuality } from '../layout';

interface Props {
  dbm: number;
}

export function SignalBar({ dbm }: Props) {
  const q = signalQuality(dbm);
  const level = q === 'excellent' ? 4 : q === 'good' ? 3 : q === 'fair' ? 2 : 1;
  const heights = [6, 9, 12, 15];

  return (
    <div className="signal-bar">
      {heights.map((h, i) => (
        <div
          key={i}
          className={`signal-bar__seg ${i < level ? `active ${q}` : ''}`}
          style={{ height: h }}
        />
      ))}
    </div>
  );
}
