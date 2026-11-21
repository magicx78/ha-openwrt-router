/**
 * wifiUi.tsx — small shared pieces of the WiFi Intelligence tab.
 *
 * Badge, Notice, Skeleton and Spinner come from the Configuration Manager's
 * configUi (imported, not copied). The error box maps WifiApiError; the
 * section boundary keeps one broken view from taking the panel down; the
 * poll hook loads at most every 60 s and only while the page is visible.
 * Everything the server sends is rendered as plain text, never as HTML.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Badge, Notice } from '../config/configUi';
import {
  NOT_A_SPECTRUM_ANALYZER,
  POLL_MIN_MS,
  SCAN_WARNING,
  errorInfo,
  pollDelay,
  shouldFetch,
  type MetricView,
} from './wifiLogic.ts';
import type { Tone } from './wifiTypes';

export { Badge, Notice, Skeleton, Spinner } from '../config/configUi';

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

export function ToneBadge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return <Badge tone={tone}>{children}</Badge>;
}

/** A metric or count: known values plain, unknown "—" with reason in the muted style. */
export function Val({ v }: { v: MetricView }) {
  return v.known
    ? <span className="wifi-val">{v.text}</span>
    : <span className="wifi-unknown" title={v.reason ?? undefined}>{v.text}</span>;
}

/** Plain unknown marker (never 0, never green). */
export function Unknown({ text }: { text: string }) {
  return <span className="wifi-unknown">{text}</span>;
}

export function Fact({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="wifi-fact">
      <span className="wifi-fact__name">{name}</span>
      <span className="wifi-fact__value">{children}</span>
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

/** Survey / scan warning and the fixed "no spectrum analyser" note. */
export function ScanNotes() {
  return (
    <div className="wifi-notes">
      <div className="cfg-notice cfg-notice--warn" role="note">{SCAN_WARNING}</div>
      <div className="cfg-hint">Hinweis: {NOT_A_SPECTRUM_ANALYZER}.</div>
    </div>
  );
}

interface BoundaryProps {
  title: string;
  children: React.ReactNode;
}

/** Catches a render error of one view; the rest of the panel keeps working. */
export class SectionBoundary extends React.Component<BoundaryProps, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <Notice tone="warn">
        Die Ansicht „{this.props.title}“ konnte nicht angezeigt werden. Die anderen Bereiche funktionieren weiter.{' '}
        <button type="button" className="diag-btn cfg-btn" onClick={() => this.setState({ failed: false })}>Erneut versuchen</button>
      </Notice>
    );
  }
}

export interface Resource<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  reload: () => void;
}

function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

/**
 * Loads `load()` while `enabled`, when `key` changes and then at most every
 * POLL_MIN_MS, only while the page is visible (a hidden page catches up once
 * it becomes visible again). The component is mounted only while its tab is
 * shown, so nothing is fetched for a hidden tab. The last good data stays
 * on screen while a reload runs or fails; a stale answer is dropped.
 */
export function usePolled<T>(load: () => Promise<T>, key: unknown, enabled = true, intervalMs = POLL_MIN_MS): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(enabled);
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  const lastRef = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled) return;
    if (!pageVisible()) {
      lastRef.current = null; // fetch as soon as the page is visible again
      return;
    }
    let cancelled = false;
    lastRef.current = Date.now();
    setLoading(true);
    loadRef.current().then(
      d => { if (!cancelled) { setData(d); setError(null); setLoading(false); } },
      e => { if (!cancelled) { setError(e); setLoading(false); } },
    );
    return () => { cancelled = true; };
  }, [enabled, key, tick]);

  useEffect(() => {
    if (!enabled) return;
    const check = () => {
      if (shouldFetch({ visible: pageVisible(), lastMs: lastRef.current, nowMs: Date.now(), intervalMs })) setTick(t => t + 1);
    };
    const id = setInterval(check, pollDelay(intervalMs));
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [enabled, intervalMs]);

  const reload = useCallback(() => setTick(t => t + 1), []);
  return { data, error, loading, reload };
}

/** Skeleton, error or content of one resource. */
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
