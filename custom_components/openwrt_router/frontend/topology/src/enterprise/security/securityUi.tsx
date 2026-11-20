/**
 * securityUi.tsx — small shared pieces of the Security Center tab.
 *
 * Notice, Badge, Skeleton and Spinner come from the Configuration Manager's
 * configUi (imported, not copied); the error box is the security variant
 * because it maps SecurityApiError. Everything the server sends is rendered
 * as plain text (React text nodes), never as HTML.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { errorInfo, type Tone } from './securityLogic.ts';
import { Badge, Notice } from '../config/configUi';

export { Badge, Notice, Skeleton, Spinner } from '../config/configUi';

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const info = errorInfo(error);
  return (
    <div className={`cfg-notice cfg-notice--${info.kind === 'network' || info.kind === 'unavailable' ? 'warn' : 'error'}`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && (
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      )}
    </div>
  );
}

export function ToneBadge({ tone, children }: { tone: Tone | string; children: React.ReactNode }) {
  return <Badge tone={tone}>{children}</Badge>;
}

/** A label / value line. */
export function Fact({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="sec-fact">
      <span className="sec-fact__name">{name}</span>
      <span className="sec-fact__value">{children}</span>
    </div>
  );
}

export function SectionBox({ title, children, hint }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="cfg-section">
      <div className="cfg-section__title">{title}</div>
      {hint && <div className="cfg-hint">{hint}</div>}
      {children}
    </section>
  );
}

/** "Unknown" marker for a missing value (never 0, never green). */
export function Unknown({ text = 'unbekannt' }: { text?: string }) {
  return <span className="sec-unknown">{text}</span>;
}

export interface Resource<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  reload: () => void;
}

/**
 * Loads `load()` while `enabled` and whenever `key` changes; the last good
 * data stays on screen while a reload runs or fails. A stale answer (the key
 * changed meanwhile) is dropped.
 */
export function useResource<T>(load: () => Promise<T>, enabled: boolean, key: unknown): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(enabled);
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setLoading(true);
    loadRef.current().then(
      d => { if (!cancelled) { setData(d); setError(null); setLoading(false); } },
      e => { if (!cancelled) { setError(e); setLoading(false); } },
    );
    return () => { cancelled = true; };
  }, [enabled, key, tick]);

  const reload = useCallback(() => setTick(t => t + 1), []);
  return { data, error, loading, reload };
}

/** Runs one action; exposes busy and the last error. */
export function useAction(): {
  busy: boolean;
  error: unknown;
  run: (fn: () => Promise<void>) => Promise<boolean>;
  clear: () => void;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);
  const run = useCallback(async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      return true;
    } catch (e) {
      if (alive.current) setError(e);
      return false;
    } finally {
      if (alive.current) setBusy(false);
    }
  }, []);
  const clear = useCallback(() => setError(null), []);
  return { busy, error, run, clear };
}
