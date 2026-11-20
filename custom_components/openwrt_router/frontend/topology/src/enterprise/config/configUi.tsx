/**
 * configUi.tsx — small shared pieces of the Configuration Manager tab:
 * error box (German text from the error code, never server text), loading
 * placeholders, badges, and the bounded poll used while a backup runs.
 */

import React, { useEffect, useRef } from 'react';
import { POLL_INTERVAL_MS, POLL_LIMIT_MS, RISK_LABEL, errorInfo, label } from './configLogic.ts';

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const info = errorInfo(error);
  return (
    <div className={`cfg-notice cfg-notice--${info.kind === 'busy' ? 'warn' : 'error'}`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && (
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      )}
    </div>
  );
}

export function Notice({ tone, children }: { tone: 'info' | 'warn' | 'error' | 'ok'; children: React.ReactNode }) {
  return <div className={`cfg-notice cfg-notice--${tone}`}>{children}</div>;
}

export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="cfg-skeleton" aria-busy="true" aria-label="Lädt">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="cfg-skeleton__row" />)}
    </div>
  );
}

export function Spinner({ text }: { text: string }) {
  return (
    <span className="cfg-spinner" role="status">
      <span className="cfg-spinner__dot" aria-hidden="true" />
      {text}
    </span>
  );
}

export function RiskBadge({ risk }: { risk: string | null }) {
  const key = risk ?? 'unknown';
  return <span className={`cfg-risk cfg-risk--${key}`}>{risk ? label(RISK_LABEL, risk) : 'Unbekannt'}</span>;
}

export function Badge({ tone, children }: { tone: string; children: React.ReactNode }) {
  return <span className={`cfg-badge cfg-badge--${tone}`}>{children}</span>;
}

/** Calls `fn` every 5 s while `active`, for at most 5 min (plan 8, state "Läuft"). */
export function useBoundedPoll(active: boolean, fn: () => void): void {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!active) return;
    const started = Date.now();
    const id = setInterval(() => {
      if (Date.now() - started > POLL_LIMIT_MS) {
        clearInterval(id);
        return;
      }
      ref.current();
    }, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [active]);
}

/** Re-render once per `ms` (UI clock for expiry times; no network). */
export function useClock(ms: number): number {
  const [now, setNow] = React.useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}
