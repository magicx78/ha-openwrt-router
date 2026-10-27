import React from 'react';
import { IconGlobe } from './Icons';

interface Props {
  pingMs?: number | null;
}

export type InternetState = 'ok' | 'fair' | 'slow' | 'offline' | 'unknown';

/**
 * Internet health from the gateway ping: `null` = no answer,
 * `undefined` = not measured yet. Also drives the colour of the
 * Internet → gateway edge (class `inet-<state>` on the app root).
 */
export function internetState(pingMs: number | null | undefined): InternetState {
  if (pingMs === null) return 'offline';
  if (pingMs === undefined || pingMs <= 0) return 'unknown';
  if (pingMs < 50)  return 'ok';
  if (pingMs < 100) return 'fair';
  return 'slow';
}

const STATE_TITLE: Record<InternetState, string> = {
  ok:      'Internet erreichbar',
  fair:    'Internet erreichbar, erhöhte Latenz',
  slow:    'Internet erreichbar, hohe Latenz',
  offline: 'Internet nicht erreichbar (kein Ping)',
  unknown: 'Noch keine Messung',
};

function pingClass(ms: number): string {
  if (ms < 20)  return 'ping-excellent';
  if (ms < 50)  return 'ping-good';
  if (ms < 100) return 'ping-fair';
  return 'ping-poor';
}

export function InternetNode({ pingMs }: Props) {
  const state = internetState(pingMs);
  const hasPing = pingMs != null && pingMs > 0;

  return (
    <div className={`internet-node inet-${state}`} title={STATE_TITLE[state]}>
      <div className="internet-node__circle">
        <IconGlobe size={24} />
      </div>
      <span className="internet-node__label">Internet</span>
      {hasPing && (
        <span className={`internet-node__ping ${pingClass(pingMs!)}`}>{pingMs} ms</span>
      )}
      {state === 'offline' && (
        <span className="internet-node__ping ping-poor">offline</span>
      )}
    </div>
  );
}
