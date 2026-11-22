/**
 * tmUi.tsx — pieces shared by the views of the "Zeitreise" tab: the frame
 * of the tab, error box, chips, spinner, the "off" box, the router select,
 * the client label, one timeline mark, and the jump button into another
 * Enterprise tab (1.52.0). Text only (React text, never HTML).
 */

import React, { createContext, useContext } from 'react';
import configCSS from '../config/config.css?inline';
import wifiCSS from '../wifi/wifi.css?inline';
import tmCSS from './timemachine.css?inline';
import {
  INTRO, OFF_HOW, OFF_TITLE, TAB_TITLE, clientLabel, clientTitle, detailText, errorInfo, groupText, isoUtc,
  routerOptionLabel, routerOptions, routerText, severityView, sourceText, standText, startText, timeText, titleOf,
  type ErrorOf, type RouterNames,
} from './tmLogic.ts';
import { DERIVED_TITLE, isClient, jumpLabel, markTarget, shownTarget } from './tmState.ts';
import type { JumpTarget, Mark } from './tmTypes';

export function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

// ── Jumps and the client filter (contexts: no prop threading) ────────────

/** What the tab may open: `canOpen` says whether this user has the tab now. */
export interface JumpApi {
  canOpen(tab: string): boolean;
  open(target: JumpTarget): void;
}

export const JumpContext = createContext<JumpApi | null>(null);
/** Set by the timeline for administrators: a click on a client label filters by it. */
export const ClientFilterContext = createContext<((client: string) => void) | null>(null);

/** "Im Tab … öffnen →": only for a target of a tab this user has, never this tab itself. */
export function JumpButton({ target }: { target: JumpTarget | null }) {
  const jump = useContext(JumpContext);
  const shown = jump ? shownTarget(target, tab => jump.canOpen(tab)) : null;
  if (!jump || !shown) return null;
  return (
    <button type="button" className="diag-btn cfg-btn tm-jump" onClick={() => jump.open(shown)}>
      {jumpLabel(shown.tab)} <span aria-hidden="true">→</span>
    </button>
  );
}

export function DerivedBadge() {
  return <span className="cfg-badge cfg-badge--info tm-derived" title={DERIVED_TITLE}>abgeleitet</span>;
}

// ── Pieces ───────────────────────────────────────────────────────────────

export function ErrorBox({ error, onRetry, of = 'timeline' }: { error: unknown; onRetry?: () => void; of?: ErrorOf }) {
  const info = errorInfo(error, of);
  return (
    <div className={`cfg-notice cfg-notice--${info.kind === 'failed' ? 'warn' : 'error'}`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && (
        <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>
      )}
    </div>
  );
}

export function Chip({ on, disabled, onClick, children, title, label }: {
  on: boolean; disabled?: boolean; onClick: () => void; children: React.ReactNode; title?: string; label?: string;
}) {
  return (
    <button type="button" className={`wifi-nav__btn tm-chip${on ? ' active' : ''}`} aria-pressed={on}
      disabled={disabled} title={title} aria-label={label} onClick={onClick}>
      {children}
    </button>
  );
}

export function Spinner({ text }: { text: string }) {
  return <div className="cfg-spinner tm-loading" aria-busy="true"><span className="cfg-spinner__dot" />{text}</div>;
}

export function OffBox() {
  return (
    <div className="cfg-notice cfg-notice--info tm-off" role="status">
      <strong>{OFF_TITLE}</strong>
      <span>{OFF_HOW}</span>
    </div>
  );
}

export function Frame({ loading, onRefresh, viewSwitch, generatedAt, children }: {
  loading: boolean; onRefresh: () => void; viewSwitch?: React.ReactNode; generatedAt: number | null | undefined;
  children: React.ReactNode;
}) {
  return (
    <div className="cfg wifi tm">
      <style>{configCSS}</style>
      <style>{wifiCSS}</style>
      <style>{tmCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={loading} onClick={onRefresh}>
          Aktualisieren
        </button>
      </div>
      {viewSwitch}
      <div className="cfg-hint">{INTRO}</div>
      {generatedAt !== undefined && generatedAt !== null && <div className="cfg-hint tm-stand">{standText(generatedAt)}</div>}
      {children}
    </div>
  );
}

export function RouterSelect({ value, routers, onChange }: { value: string | null; routers: RouterNames; onChange: (id: string | null) => void }) {
  const options = routerOptions(routers);
  if (value && !options.some(o => o.value === value)) options.push({ value, label: routerOptionLabel(value, null) });
  return (
    <label className="tm-filter tm-field">
      <span className="tm-filter__name">Router</span>
      <select value={value ?? ''} onChange={e => onChange(e.target.value || null)}>
        <option value="">Alle Router</option>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  );
}

/** A client by the server's name or the pseudonym's end; for administrators in the timeline a filter button. */
export function ClientLabel({ client, name }: { client: string | null; name: string | null }) {
  const filter = useContext(ClientFilterContext);
  const label = clientLabel(client, name);
  // the full pseudonym as title: an administrator can copy it for the forget service
  const title = clientTitle(client) ?? undefined;
  if (filter && client && isClient(client)) {
    return (
      <button type="button" className="tm-client tm-client--filter" title={title}
        aria-label={`Zeitleiste nach ${label} filtern`} onClick={() => filter(client)}>
        {label}
      </button>
    );
  }
  return <span className="tm-client" title={title}>{label}</span>;
}

/** One mark of the timeline (also the intervals of "Zustand"); its jump button below the title. */
export function MarkRow({ m, nowMs, start = false }: { m: Mark; nowMs: number; start?: boolean }) {
  const sev = severityView(m.severity);
  const detail = detailText(m, nowMs, { client: false, inBlock: start });
  const hasClient = !!(m.client || m.clientName);
  const iso = isoUtc(m.ts);
  const router = routerText(m);
  return (
    <li className="tm-mark" data-source={m.source}>
      <time className="tm-mark__time" dateTime={iso} title={iso}>{start ? startText(m.ts) : timeText(m.ts)}</time>
      <span className={`tm-mark__sev tm-sev tm-sev--${sev.tone}`}>
        <span className="tm-sev__dot" aria-hidden="true" />{sev.label}
      </span>
      <span className="tm-mark__group">
        <span className="cfg-badge cfg-badge--muted">{groupText(m.group)}</span>
        {m.derived && <span className="cfg-badge cfg-badge--info">abgeleitet</span>}
      </span>
      <span className="tm-mark__main">
        <span className="tm-mark__title">{titleOf(m)}</span>
        {(detail || hasClient) && (
          <span className="tm-mark__params">
            {hasClient && <ClientLabel client={m.client} name={m.clientName} />}
            {hasClient && detail && ' · '}
            {detail}
          </span>
        )}
        <JumpButton target={markTarget(m)} />
      </span>
      <span className="tm-mark__router" title={router}>{router}</span>
      <span className="tm-mark__source">{sourceText(m.source)}</span>
    </li>
  );
}

/** Save a Blob as a file (an object URL, revoked after the click; no token in it). */
export function saveBlob(blob: Blob, filename: string): void {
  if (typeof document === 'undefined' || typeof URL === 'undefined' || !URL.createObjectURL) return;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
