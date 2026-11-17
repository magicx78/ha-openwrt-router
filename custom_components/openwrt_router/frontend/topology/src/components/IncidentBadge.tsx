/**
 * IncidentBadge — warning symbol on a router node (P7).
 *
 * Shows the open root incidents of the router from the snapshot
 * (`attributes.incidents`); click opens the Diagnose tab for this router.
 */

import React from 'react';
import type { IncidentCounts } from '../types';
import { SEVERITY_LABEL, countsTotal, topSeverity } from '../utils/intel';

interface Props {
  counts?: IncidentCounts;
  onOpen?: () => void;
}

export function IncidentBadge({ counts, onOpen }: Props) {
  const top = topSeverity(counts);
  if (!counts || !top) return null;
  const total = countsTotal(counts);
  const parts = (['critical', 'warning', 'info'] as const)
    .filter(s => counts[s] > 0)
    .map(s => `${counts[s]} ${SEVERITY_LABEL[s]}`);
  const title = `${total} offene${total === 1 ? 's' : ''} Problem${total === 1 ? '' : 'e'}: ${parts.join(', ')} – Diagnose öffnen`;
  return (
    <button
      type="button"
      className={`incident-badge incident-badge--${top}`}
      title={title}
      aria-label={title}
      onClick={e => { e.stopPropagation(); onOpen?.(); }}
      onDoubleClick={e => e.stopPropagation()}
    >
      <span aria-hidden="true">⚠</span>
      <span>{total}</span>
    </button>
  );
}
