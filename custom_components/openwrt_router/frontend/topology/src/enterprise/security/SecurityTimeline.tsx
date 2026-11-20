/**
 * SecurityTimeline — event timeline with filters (period, router, category,
 * severity, optional device). Without a filter the base overview's timeline
 * is used; with a filter the overview is requested again with the backend's
 * own query (the KPI numbers stay on the unfiltered base).
 */

import React, { useMemo } from 'react';
import type { Overview, SecurityApi, TimelineEntry } from './securityTypes';
import {
  CATEGORIES,
  CATEGORY_LABEL,
  DEFAULT_FILTERS,
  RANGE_OPTIONS,
  SEVERITY_FILTER_LABEL,
  SEVERITY_LABEL,
  SEVERITY_TONE,
  TIMELINE_KIND_LABEL,
  filtersAreDefault,
  formatRelativeTs,
  formatTs,
  label,
  shortId,
  toOverviewFilters,
  type TimelineFilters,
} from './securityLogic.ts';
import { ErrorBox, Skeleton, ToneBadge, useResource } from './securityUi';

const LIMIT = 200;

function who(e: TimelineEntry): string | null {
  if (e.client) return e.client; // administrators: the plain MAC the server sent
  if (e.clientRef) return e.clientRef; // pseudonym or mask, as sent
  return e.hasClient ? 'Gerät (nicht zuordenbar)' : null;
}

export function SecurityTimeline({ api, base, filters, onFilters, routers, now, rev, onOpenIncident }: {
  api: SecurityApi;
  base: Overview;
  filters: TimelineFilters;
  onFilters: (f: TimelineFilters) => void;
  routers: string[];
  now: number;
  /** Changes on every global refresh, so the filtered request is made again. */
  rev: number;
  onOpenIncident: (id: string) => void;
}) {
  const isDefault = filtersAreDefault(filters);
  // The period is resolved when the filter changes, not on every render.
  const request = useMemo(() => toOverviewFilters(filters, Math.floor(Date.now() / 1000)), [filters, rev]);
  const filtered = useResource(
    () => api.overview({ ...request, limit: LIMIT }),
    !isDefault,
    `${rev}|${JSON.stringify(filters)}`,
  );

  const entries = isDefault ? base.timeline : (filtered.data?.timeline ?? []);
  const loading = !isDefault && filtered.loading && filtered.data === null;
  const set = (patch: Partial<TimelineFilters>) => onFilters({ ...filters, ...patch });

  return (
    <div className="cfg-stack">
      <div className="sec-filters" role="group" aria-label="Filter">
        <label className="sec-field">
          <span>Zeitraum</span>
          <select value={filters.range} onChange={e => set({ range: e.target.value })}>
            {RANGE_OPTIONS.map(r => <option key={r.id} value={r.id}>{r.label}</option>)}
          </select>
        </label>
        <label className="sec-field">
          <span>Router</span>
          <select value={filters.routerId} onChange={e => set({ routerId: e.target.value })}>
            <option value="">Alle Router</option>
            {routers.map(r => <option key={r} value={r}>{shortId(r)}</option>)}
          </select>
        </label>
        <label className="sec-field">
          <span>Kategorie</span>
          <select value={filters.category} onChange={e => set({ category: e.target.value })}>
            <option value="">Alle Kategorien</option>
            {CATEGORIES.map(c => <option key={c} value={c}>{label(CATEGORY_LABEL, c)}</option>)}
          </select>
        </label>
        <label className="sec-field">
          <span>Schwere</span>
          <select value={filters.severity} onChange={e => set({ severity: e.target.value })}>
            <option value="">Alle</option>
            {Object.entries(SEVERITY_FILTER_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
      </div>
      <div className="sec-filters__state">
        {filters.client && (
          <span className="sec-chip-btn">
            Nur ein Gerät
            <button type="button" className="diag-btn cfg-btn" onClick={() => set({ client: '' })}>Filter entfernen</button>
          </span>
        )}
        {!isDefault && (
          <button type="button" className="diag-btn cfg-btn" onClick={() => onFilters(DEFAULT_FILTERS)}>
            Alle Filter zurücksetzen
          </button>
        )}
      </div>

      {!isDefault && filtered.error !== null && (
        <ErrorBox error={filtered.error} onRetry={filtered.reload} />
      )}
      {loading && <Skeleton rows={4} />}

      {!loading && entries.length === 0 && (
        <div className="cfg-empty">
          {isDefault
            ? 'Keine Ereignisse aufgezeichnet. Das ist kein Beleg dafür, dass nichts passiert ist: es zählt nur, was die Datenquellen liefern.'
            : 'Keine Ereignisse für diese Filter.'}
        </div>
      )}

      {entries.length > 0 && (
        <ul className="sec-rows" aria-label="Ereignisse">
          {entries.map((e, idx) => {
            const person = who(e);
            return (
              <li key={`${e.ts ?? 'x'}-${idx}`} className="sec-row">
                <div className="sec-row__main">
                  <ToneBadge tone={SEVERITY_TONE[e.severity ?? ''] ?? 'muted'}>{label(SEVERITY_LABEL, e.severity)}</ToneBadge>
                  <span className="sec-row__title">{e.text ?? label(TIMELINE_KIND_LABEL, e.kind)}</span>
                </div>
                <div className="sec-row__meta">
                  <span title={formatTs(e.ts)}>{formatRelativeTs(e.ts, now)}</span>
                  <span>{label(TIMELINE_KIND_LABEL, e.kind)}</span>
                  <span>{label(CATEGORY_LABEL, e.category)}</span>
                  {e.routerId && <span className="diag-mono">{shortId(e.routerId)}</span>}
                  {person && <span className="diag-mono sec-ident">{person}</span>}
                </div>
                {e.incidentId && (
                  <button type="button" className="diag-btn cfg-btn sec-row__action" onClick={() => onOpenIncident(e.incidentId!)}>
                    Details
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {entries.length >= LIMIT && <div className="cfg-hint">Es werden höchstens {LIMIT} Einträge angezeigt.</div>}
      <div className="cfg-hint">
        Kategorie und Zeitpunkt stammen aus den Datenquellen der Router. Einträge sind Hinweise, keine Beweise.
        Der Filter „Schwere“ zeigt die gewählte Stufe und alle höheren.
      </div>
    </div>
  );
}
