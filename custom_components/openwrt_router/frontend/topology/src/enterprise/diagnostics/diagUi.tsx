/**
 * diagUi.tsx — small shared pieces of the Network Diagnostics tab.
 *
 * Notice, Badge, Skeleton and Spinner come from the Configuration Manager's
 * configUi, useResource / useAction from the Security Center's securityUi
 * (imported, not copied; both are generic). The error box is this tab's own
 * because it maps DiagApiError. Everything the server sends is rendered as
 * plain text (React text nodes), never as HTML.
 */

import React from 'react';
import { errorInfo, type Chip } from './diagnosticsLogic.ts';
import type { Tone } from './diagnosticsTypes';
import { Badge } from '../config/configUi';

export { Badge, Notice, Skeleton, Spinner } from '../config/configUi';
export { useAction, useResource } from '../security/securityUi';

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const info = errorInfo(error);
  const soft = info.kind === 'network' || info.kind === 'unavailable' || info.kind === 'rate_limited' || info.kind === 'busy';
  return (
    <div className={`cfg-notice cfg-notice--${soft ? 'warn' : 'error'}`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && info.kind !== 'rate_limited' && (
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      )}
    </div>
  );
}

export function ToneBadge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return <Badge tone={tone}>{children}</Badge>;
}

/** Marker for a missing value: its own neutral style, never 0 and never green. */
export function Unknown({ text = 'unbekannt' }: { text?: string }) {
  return <span className="dg-unknown">{text}</span>;
}

/** A label / value line. */
export function Fact({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="dg-fact">
      <span className="dg-fact__name">{name}</span>
      <span className="dg-fact__value">{children}</span>
    </div>
  );
}

export function SectionBox({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="cfg-section">
      <div className="cfg-section__title">{title}</div>
      {hint && <div className="cfg-hint">{hint}</div>}
      {children}
    </section>
  );
}

/** The five stage chips of one chain: Router → Gateway → WAN → Internet → DNS. */
export function ChainRow({ chips, label }: { chips: Chip[]; label: string }) {
  return (
    <ol className="dg-chain" aria-label={label}>
      {chips.map(c => (
        <li key={c.stage} className={`dg-chip dg-chip--${c.tone} dg-chip--${c.state}`} title={c.detail ?? undefined}>
          <span className="dg-chip__name">{c.label}</span>
          <span className="dg-chip__state">{c.text}</span>
          {c.detail && <span className="dg-chip__detail">{c.detail}</span>}
        </li>
      ))}
    </ol>
  );
}
