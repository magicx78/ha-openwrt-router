/**
 * trafficUi.tsx — small shared pieces of the Traffic Analytics tab.
 *
 * The poll hook (visible page only, at most every 60 s), the section
 * boundary and the fact / box helpers come from the WiFi tab (imported,
 * not copied); Badge and Notice from the Configuration Manager. The error
 * box maps TrafficApiError. Everything the server sends is rendered as
 * plain text, never as HTML.
 */

import React from 'react';
import { Badge, Notice } from '../config/configUi';
import { Fact, SectionBox, SectionBoundary, Unknown, usePolled, type Resource } from '../wifi/wifiUi';
import { coverageView, errorInfo, reasonText, sourceName, sourceStateView, type Shown } from './trafficLogic.ts';
import type { CoverageLevel, SourceState } from './trafficTypes';

export { Badge, Notice, Fact, SectionBox, SectionBoundary, Unknown, usePolled };
export type { Resource };

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const info = errorInfo(error);
  const soft = info.kind === 'network' || info.kind === 'unavailable';
  return (
    <div className={`cfg-notice cfg-notice--${soft ? 'warn' : 'error'}`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && (
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      )}
    </div>
  );
}

/** Skeleton, error or content of one resource (last good data stays). */
export function Loaded<T>({ res, children }: { res: Resource<T>; children: (data: T) => React.ReactNode }) {
  if (res.data === null) {
    if (res.error !== null) return <ErrorBox error={res.error} onRetry={res.reload} />;
    return <div className="cfg-skeleton" aria-busy="true" aria-label="Lädt"><div className="cfg-skeleton__row" /><div className="cfg-skeleton__row" /></div>;
  }
  return (
    <>
      {res.error !== null && <ErrorBox error={res.error} onRetry={res.reload} />}
      {children(res.data)}
    </>
  );
}

export function ShownBadge({ shown }: { shown: Shown }) {
  return <Badge tone={shown.tone}>{shown.label}</Badge>;
}

export function CoverageBadge({ level, reasons = [] }: { level: CoverageLevel | null; reasons?: readonly (string | null)[] }) {
  const v = coverageView(level);
  const why = reasons.filter((r): r is string => !!r).map(reasonText).join(' · ');
  return (
    <span className="trf-cov" title={why || undefined}>
      <Badge tone={v.tone}>Abdeckung {v.label}</Badge>
      {why && <span className="wifi-muted"> {why}</span>}
    </span>
  );
}

/** A value: known plain, unknown "—" (with reason) in the muted style. */
export function V({ text, known, reason }: { text: string; known: boolean; reason?: string | null }) {
  if (known) return <span className="wifi-val">{text}</span>;
  return <Unknown text={reason ? `${text} ${reasonText(reason)}` : text} />;
}

/** Data sources with state and the reason they are not delivering. */
export function SourceList({ sources }: { sources: readonly SourceState[] }) {
  if (!sources.length) return <Unknown text="— keine Angaben" />;
  return (
    <ul className="wifi-rows">
      {sources.map(s => {
        const st = sourceStateView(s.state);
        return (
          <li key={s.name} className="wifi-row">
            <span className="wifi-row__title">{sourceName(s.name)}</span>
            <ShownBadge shown={st} />
            {s.reason && <span className="wifi-muted">{reasonText(s.reason)}</span>}
          </li>
        );
      })}
    </ul>
  );
}

export function Field({ label, value, options, onChange }: {
  label: string;
  value: string;
  options: readonly { value: string; label: string }[];
  onChange: (v: string) => void;
}) {
  return (
    <label className="wifi-field">
      {label}
      <select value={value} onChange={e => onChange(e.target.value)}>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  );
}
