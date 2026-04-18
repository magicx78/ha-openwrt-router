import React from 'react';
import { IconGlobe } from './Icons';

interface Props {
  pingMs?: number | null;
}

function pingClass(ms: number): string {
  if (ms < 20)  return 'ping-excellent';
  if (ms < 50)  return 'ping-good';
  if (ms < 100) return 'ping-fair';
  return 'ping-poor';
}

export function InternetNode({ pingMs }: Props) {
  const hasPing = pingMs != null && pingMs > 0;
  const isOffline = pingMs === null;
  const cls = hasPing ? pingClass(pingMs!) : '';

  return (
    <div className={`internet-node ${cls}`}>
      <div className={`internet-node__circle${hasPing ? ' internet-node__circle--pulse' : ''}`}>
        <IconGlobe size={22} />
      </div>
      <span className="internet-node__label">Internet</span>
      {hasPing && (
        <span className={`internet-node__ping ${cls}`}>{pingMs} ms</span>
      )}
      {isOffline && (
        <span className="internet-node__ping ping-poor">offline</span>
      )}
    </div>
  );
}
