/**
 * TimeMachineState — the views "Zustand" and "Vergleich" of the "Zeitreise"
 * tab (Network Time Machine, Phases D–F, 1.52.0, read only).
 *
 * - "Zustand": the reconstructed state at one moment (GET …/state). A
 *   `datetime-local` field in local time (default: now), "Jetzt", "−1 h",
 *   "−24 h" and the router select; a change loads after a short pause, an
 *   older answer never overwrites a newer one. Reloaded every 60 s only while
 *   "Jetzt" is chosen and the page is visible. Without a known state one box
 *   says why, and no router card is drawn.
 * - "Vergleich": two moments (GET …/compare), a table per router
 *   "Merkmal | Vorher | Nachher"; unchanged rows collapsed, unknown rows
 *   never coloured as a change.
 *
 * Both are for every user; what only administrators see (configuration
 * versions, clients) the server leaves out for others, and the tab never asks
 * for a client page unless the user is an administrator. Text only.
 */

import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import {
  CLIENTS_OFF_HOW, CLIENTS_OFF_TITLE, POLL_MIN_MS, aroundWindow, customWindow, groupText, rememberRouters, severityView,
  shouldFetch, startText, unavailableText, type RouterNames,
} from './tmLogic.ts';
import {
  COMPARE_INIT, COMPARE_LOADING_TEXT, COMPARE_PICKS, COMPARE_PICK_TEXT, SECTION_CLIENTS, SECTION_COMPARE_CONFIG,
  SECTION_COMPARE_INCIDENTS, SECTION_CONFIG, SECTION_EVENTS, SECTION_INCIDENTS, SECTION_INTERVALS, SECTION_TRAFFIC,
  STATE_INIT, STATE_LOADING_TEXT, STATE_PICK_TEXT, STATE_STEPS, STATE_UNAVAILABLE_TEXT, UNKNOWN, UNKNOWN_TITLE,
  clientRowText, compareReducer, compareRows, compareSummary, configTitle, deltaText, fromLocalInput, globalReasonText,
  hourText, incidentTitle, moreClientsQuery, otherSourcesText, parseLocalInput, partStateText, radioBandText, radioView,
  radiosView, reachableView, roleView, routerName, sinceText, stateLoadAt, stateReasonText, stateReducer, toLocalInput, uplinkView,
  loadDelay, utilizationText, waitingBody, wanText,
  type CompareRow, type CompareView, type StateView, type ValueView,
} from './tmState.ts';
import type {
  CompareAnswer, ConfigItem, CustomWindow, IncidentItem, Part, RouterChange, RouterState, StateAnswer, TmApi,
} from './tmTypes';
import {
  Chip, ClientLabel, DerivedBadge, ErrorBox, Frame, JumpButton, MarkRow, OffBox, RouterSelect, Spinner, pageVisible,
} from './tmUi';
import { errorInfo } from './tmLogic.ts';

const CHECK_MS = Math.min(15_000, POLL_MIN_MS);

// ── Pieces ───────────────────────────────────────────────────────────────

/** A value in words: "unbekannt" muted with its reason, "nicht erreichbar" as a warning in words. */
export function Value({ v }: { v: ValueView }) {
  if (v.unknown) {
    return (
      <span className="tm-value tm-value--unknown">
        {UNKNOWN}{v.reason && <span className="tm-reason"> · {v.reason}</span>}
      </span>
    );
  }
  return (
    <span className={`tm-value${v.tone === 'warn' ? ' tm-value--warn' : ''}`}>
      {v.text}{v.derived && <> <DerivedBadge /></>}
    </span>
  );
}

function PartNote({ p }: { p: Part }) {
  return <span className="tm-value tm-value--unknown">{partStateText(p)}</span>;
}

/**
 * What the field's own value says on a clock change: the hour the clock
 * skips is an error, the hour it repeats a note (the first one is shown).
 */
export function LocalNote({ value }: { value: string }) {
  const p = parseLocalInput(value);
  if (p.error) return <span className="tm-field__error" role="alert">{p.error}</span>;
  if (p.note) return <span className="tm-field__note cfg-hint">{p.note}</span>;
  return null;
}

/** The error of a field, right under it (400 of the server in plain words). */
function FieldError({ error, fields }: { error: unknown; fields: readonly string[] }) {
  const info = error !== null ? errorInfo(error, 'state') : null;
  if (!info || !info.field || !fields.includes(info.field)) return null;
  return <span className="tm-field__error" role="alert">{info.message}</span>;
}

function fieldError(error: unknown, of: 'state' | 'compare', fields: readonly string[]): boolean {
  const info = error !== null ? errorInfo(error, of) : null;
  return !!info?.field && fields.includes(info.field);
}

function Section({ title, children, className = '' }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`tm-section ${className}`.trim()} aria-label={title}>
      <h3 className="cfg-subtitle tm-section__title">{title}</h3>
      {children}
    </section>
  );
}

function Name({ r }: { r: { routerId: string | null; routerName: string | null } }) {
  const name = routerName(r);
  return <span className="tm-name" title={name}>{name}</span>;
}

function IncidentRow({ i, what }: { i: IncidentItem; what?: string }) {
  const sev = severityView(i.severity);
  const when = i.at ?? i.since;
  return (
    <li className="tm-item">
      <span className={`tm-sev tm-sev--${sev.tone}`}><span className="tm-sev__dot" aria-hidden="true" />{sev.label}</span>
      <span className="tm-item__main">
        <span className="tm-item__title">{what ? `${what}: ` : ''}{incidentTitle(i)}</span>
        <span className="tm-item__meta">
          {i.fleet ? 'alle Router' : <Name r={i} />}
          {' · '}{what ? (when !== null ? startText(when) : 'Zeit unbekannt') : sinceText(when)}
          {i.state === 'unknown' && <span className="tm-value--unknown"> · Zustand {UNKNOWN} · {stateReasonText(i.reason)}</span>}
        </span>
        <JumpButton target={i.target} />
      </span>
    </li>
  );
}

function ConfigRow({ c }: { c: ConfigItem }) {
  return (
    <li className="tm-item">
      <span className="tm-item__main">
        <span className="tm-item__title">{configTitle(c)}</span>
        <span className="tm-item__meta"><Name r={c} />{' · '}{c.createdAt !== null ? startText(c.createdAt) : 'Zeit unbekannt'}</span>
        <JumpButton target={c.target} />
      </span>
    </li>
  );
}

// ── "Zustand" (pure: everything from props) ──────────────────────────────

function RouterCard({ r }: { r: RouterState }) {
  const radios = r.radios;
  const rv = radiosView(radios);
  return (
    <section className="tm-card" aria-label={routerName(r)}>
      <h4 className="tm-card__title">{routerName(r)}</h4>
      <dl className="tm-facts">
        <div className="tm-fact"><dt>Erreichbar</dt><dd><Value v={reachableView(r.reachable)} /></dd></div>
        <div className="tm-fact"><dt>Rolle</dt><dd><Value v={roleView(r.role)} /></dd></div>
        <div className="tm-fact"><dt>Uplink</dt><dd><Value v={uplinkView(r.uplink)} /></dd></div>
        <div className="tm-fact">
          <dt>Funk</dt>
          <dd>
            {rv.whole
              ? <Value v={{ text: UNKNOWN, unknown: true, reason: rv.reason, derived: false, tone: null }} />
              : (
                <ul className="tm-radios">
                  {radios.items.map(x => (
                    <li key={x.key}><span className="tm-radios__band">{radioBandText(x.band)}</span> <Value v={radioView(x, radios.derived)} /></li>
                  ))}
                </ul>
              )}
            {rv.note && <span className="tm-reason"> · {rv.note}</span>}
          </dd>
        </div>
      </dl>
    </section>
  );
}

function TrafficBlock({ routers }: { routers: RouterState[] }) {
  if (!routers.length) return null;
  const hour = routers[0].traffic.hour ?? routers[0].utilization.hour;
  return (
    <Section title={SECTION_TRAFFIC} className="tm-traffic">
      <div className="cfg-hint">Stunde {hourText(hour)}</div>
      <ul className="tm-items">
        {routers.map(r => (
          <li key={r.routerId} className="tm-item">
            <span className="tm-item__main">
              <span className="tm-item__title"><Name r={r} /></span>
              <span className="tm-item__meta">
                Verkehr: {r.traffic.state !== 'ok'
                  ? <PartNote p={r.traffic} />
                  : r.traffic.wan.length ? r.traffic.wan.map(wanText).join(' / ') : 'kein WAN-Messpunkt'}
              </span>
              <span className="tm-item__meta">
                Funkauslastung: {r.utilization.state !== 'ok'
                  ? <PartNote p={r.utilization} />
                  : r.utilization.radios.length ? r.utilization.radios.map(utilizationText).join(' / ') : '—'}
              </span>
            </span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

export interface StateScreenProps {
  state: StateView;
  /** The value of the field (local time, "YYYY-MM-DDTHH:MM:SS"). */
  input: string;
  live: boolean;
  routerId: string | null;
  routers: RouterNames;
  nowMs: number;
  isAdmin: boolean;
  viewSwitch?: React.ReactNode;
  onInput: (value: string) => void;
  onNow: () => void;
  onStep: (seconds: number) => void;
  onRouter: (id: string | null) => void;
  onRefresh: () => void;
  onMore: () => void;
  onShowWindow: (w: CustomWindow) => void;
}

export function StateScreen({
  state, input, live, routerId, routers, nowMs, isAdmin, viewSwitch, onInput, onNow, onStep, onRouter, onRefresh, onMore,
  onShowWindow,
}: StateScreenProps) {
  const a = state.answer;
  const atError = fieldError(state.error, 'state', ['at']);
  const body = (() => {
    if (a === null) {
      if (state.error !== null && !atError) return <ErrorBox of="state" error={state.error} onRetry={onRefresh} />;
      if (atError) return null;
      // 1.52.1: the hint only for an empty field; the prefilled one loads (it opened the view)
      const wait = waitingBody(live ? [] : [input], state.loading);
      if (wait === 'none') return null;
      return wait === 'loading' ? <Spinner text={STATE_LOADING_TEXT} /> : <div className="cfg-hint">{STATE_PICK_TEXT}</div>;
    }
    const error = state.error !== null && !atError && <ErrorBox of="state" error={state.error} onRetry={onRefresh} />;
    if (a.status === 'off') return <>{error}<OffBox /></>;
    if (a.status === 'unavailable') {
      return <>{error}<div className="cfg-notice cfg-notice--warn tm-unavailable" role="status">{STATE_UNAVAILABLE_TEXT} {unavailableText(a.reason).replace(/^[^.]*\. /, '')}</div></>;
    }
    const around = a.at !== null ? aroundWindow(a.at, nowMs) : null;
    const show = around && (
      <button type="button" className="diag-btn cfg-btn tm-show" onClick={() => onShowWindow(around)}>In der Zeitleiste zeigen</button>
    );
    const head = (
      <div className="tm-at">
        <span className="tm-at__text">Zustand am {a.at !== null ? startText(a.at) : UNKNOWN}{a.at !== null && `:${String(new Date(a.at * 1000).getSeconds()).padStart(2, '0')}`}</span>
        {show}
      </div>
    );
    if (!a.known) {
      return (
        <>
          {error}
          {head}
          <div className="cfg-notice cfg-notice--info tm-off tm-unknown" role="status">
            <strong>{UNKNOWN_TITLE}</strong>
            <span>{globalReasonText(a.unknownReason)}</span>
          </div>
        </>
      );
    }
    const clients = a.clients;
    return (
      <>
        {error}
        {state.loading && <Spinner text={STATE_LOADING_TEXT} />}
        {head}
        {a.status === 'partial' && <div className="cfg-notice cfg-notice--warn" role="note">Mindestens ein Teil war nicht lesbar; der Zustand ist unvollständig.</div>}
        <div className="tm-state">
          <div className="tm-cards">
            {a.routers.map(r => <RouterCard key={r.routerId} r={r} />)}
          </div>
          {!a.routers.length && <div className="cfg-empty tm-empty">Keine Router zu diesem Zeitpunkt.</div>}
          {a.routersTruncated && <div className="cfg-hint" role="note">Weitere Router wurden gekürzt.</div>}
        </div>
        <Section title={SECTION_INTERVALS}>
          {a.intervals.length
            ? (
              <div className="tm-timeline">
                <ol className="tm-rows">{a.intervals.map(m => <MarkRow key={m.id} m={m} nowMs={nowMs} start />)}</ol>
              </div>
            )
            : <div className="cfg-hint">Zu diesem Zeitpunkt lief kein aufgezeichneter Ausfall und keine Lücke.</div>}
          {a.intervalsTruncated && <div className="cfg-hint" role="note">Weitere laufende Ausfälle und Lücken wurden gekürzt.</div>}
        </Section>
        {a.incidents && (
          <Section title={SECTION_INCIDENTS}>
            {a.incidents.state !== 'ok' && a.incidents.state !== 'partial'
              ? <div className="cfg-hint"><PartNote p={a.incidents} /></div>
              : a.incidents.items.length
                ? <ul className="tm-items">{a.incidents.items.map((i, n) => <IncidentRow key={i.id ?? n} i={i} />)}</ul>
                : <div className="cfg-hint">Keine offenen Vorfälle bekannt.</div>}
            {a.incidents.state === 'partial' && <div className="cfg-hint" role="note">{partStateText(a.incidents)}</div>}
            {a.incidents.truncated && <div className="cfg-hint" role="note">Weitere Vorfälle wurden gekürzt.</div>}
          </Section>
        )}
        <TrafficBlock routers={a.routers} />
        {isAdmin && a.config && a.config.reason !== 'admin_only' && (
          <Section title={SECTION_CONFIG}>
            {a.config.state !== 'ok' && a.config.state !== 'partial'
              ? <div className="cfg-hint"><PartNote p={a.config} /></div>
              : a.config.items.length
                ? <ul className="tm-items">{a.config.items.map((c, n) => <ConfigRow key={c.versionId ?? n} c={c} />)}</ul>
                : <div className="cfg-hint">Keine gespeicherte Version aus der Zeit davor.</div>}
            {a.config.state === 'partial' && <div className="cfg-hint" role="note">{partStateText(a.config)}</div>}
          </Section>
        )}
        {isAdmin && clients && clients.reason !== 'admin_only' && (
          <Section title={SECTION_CLIENTS} className="tm-clients">
            {clients.state === 'off' && clients.reason === 'clients_off' && (
              <div className="cfg-notice cfg-notice--info tm-off" role="status">
                <strong>{CLIENTS_OFF_TITLE}</strong><span>{CLIENTS_OFF_HOW}</span>
              </div>
            )}
            {(clients.state === 'unknown' || (clients.state === 'off' && clients.reason !== 'clients_off') || clients.state === 'unreadable') && (
              <div className="cfg-hint"><PartNote p={clients} /></div>
            )}
            {(clients.state === 'ok' || clients.state === 'partial') && (
              <>
                {clients.state === 'partial' && <div className="cfg-hint" role="note">{partStateText(clients)}</div>}
                <div className="cfg-hint tm-per-router">
                  {clients.total === 1 ? '1 Client' : `${clients.total} Clients`}
                  {clients.perRouter.length > 0 && ': '}
                  {clients.perRouter.map((p, n) => (
                    <span key={p.routerId}>{n > 0 && ' · '}<Name r={p} /> {p.clients}</span>
                  ))}
                </div>
                {state.clients.length
                  ? (
                    <ul className="tm-items tm-client-rows">
                      {state.clients.map(c => {
                        const t = clientRowText(c);
                        return (
                          <li key={c.id} className="tm-item tm-client-row">
                            <span className="tm-client-row__client"><ClientLabel client={c.client} name={c.clientName} />{c.derived && <> <DerivedBadge /></>}</span>
                            <span className="tm-client-row__router" title={routerName(c)}>{routerName(c)}</span>
                            <span className="tm-client-row__band">{t.band}</span>
                            <span className="tm-client-row__since">{sinceText(c.start)}</span>
                          </li>
                        );
                      })}
                    </ul>
                  )
                  : <div className="cfg-hint">Zu diesem Zeitpunkt war kein Client verbunden.</div>}
                {state.moreError !== null && <ErrorBox of="state" error={state.moreError} onRetry={onMore} />}
                {state.clientsCursor !== null && (
                  <div className="tm-more">
                    <button type="button" className="diag-btn cfg-btn" disabled={state.loadingMore} onClick={onMore}>Weitere laden</button>
                    {state.loadingMore && <span className="cfg-spinner"><span className="cfg-spinner__dot" />lädt …</span>}
                  </div>
                )}
              </>
            )}
          </Section>
        )}
      </>
    );
  })();

  return (
    <Frame loading={state.loading} onRefresh={onRefresh} viewSwitch={viewSwitch} generatedAt={a?.generatedAt}>
      <div className="tm-filters" role="group" aria-label="Zeitpunkt des Zustands">
        <label className="tm-filter tm-field">
          <span className="tm-filter__name">Zeitpunkt</span>
          <input type="datetime-local" step="1" value={input} aria-invalid={atError || !!parseLocalInput(input).error || undefined}
            onChange={e => onInput(e.target.value)} />
          <LocalNote value={input} />
          <FieldError error={state.error} fields={['at']} />
        </label>
        <div className="tm-filter">
          <span className="tm-filter__name">Schnellwahl</span>
          <div className="tm-chips">
            <Chip on={live} onClick={onNow}>Jetzt</Chip>
            {STATE_STEPS.map(s => (
              <Chip key={s.id} on={false} onClick={() => onStep(s.seconds)} label={`${s.label.replace('−', 'minus ')} zurück`}>{s.label}</Chip>
            ))}
          </div>
        </div>
        <RouterSelect value={routerId} routers={routers} onChange={onRouter} />
      </div>
      {body}
    </Frame>
  );
}

// ── "Vergleich" (pure) ───────────────────────────────────────────────────

function CompareCell({ text, row }: { text: string; row: CompareRow }) {
  const unknown = text === UNKNOWN;
  return (
    <span className={`tm-crow__v${unknown ? ' tm-value--unknown' : ''}`}>
      {text}{unknown && row.reason && <span className="tm-reason"> · {row.reason}</span>}
    </span>
  );
}

function CompareTable({ r, a, isAdmin, showSame, onToggleSame }: {
  r: RouterChange; a: CompareAnswer; isAdmin: boolean; showSame: boolean; onToggleSame: () => void;
}) {
  const rows = compareRows(r, a, isAdmin);
  const same = rows.filter(x => x.state === 'same');
  const shown = rows.filter(x => x.state !== 'same' || showSame);
  return (
    <section className="tm-card tm-ccard" aria-label={routerName(r)}>
      <h4 className="tm-card__title">{routerName(r)}</h4>
      <div className="tm-ctable" role="table" aria-label={`Vergleich ${routerName(r)}`}>
        <div className="tm-crow tm-crow--head" role="row">
          <span role="columnheader">Merkmal</span><span role="columnheader">Vorher</span>
          <span role="columnheader">Nachher</span><span role="columnheader"><span className="tm-sr">Änderung</span></span>
        </div>
        {shown.map(x => (
          <div key={x.key} className={`tm-crow tm-crow--${x.state}`} role="row">
            <span className="tm-crow__label" role="rowheader">{x.label}</span>
            <span role="cell"><span className="tm-crow__k">Vorher: </span><CompareCell text={x.before} row={x} /></span>
            <span role="cell"><span className="tm-crow__k">Nachher: </span><CompareCell text={x.after} row={x} /></span>
            <span role="cell" className="tm-crow__badge">
              {x.state === 'changed' && <span className="cfg-badge cfg-badge--warn tm-changed">geändert</span>}
              {x.key === 'clients' && r.clients && x.state === 'changed' && <span className="tm-delta"> {deltaText(r.clients)}</span>}
            </span>
          </div>
        ))}
        {!shown.length && <div className="cfg-hint">Alle Merkmale sind unverändert.</div>}
      </div>
      {same.length > 0 && (
        <button type="button" className="diag-btn cfg-btn tm-same" aria-expanded={showSame} onClick={onToggleSame}>
          {showSame ? 'Unverändertes ausblenden' : `Unverändertes zeigen (${same.length})`}
        </button>
      )}
    </section>
  );
}

function sideText(label: string, s: StateAnswer | null): string | null {
  if (!s || s.known) return null;
  return `${label}: ${globalReasonText(s.unknownReason)}`;
}

export interface CompareScreenProps {
  state: CompareView;
  from: string;
  until: string;
  routerId: string | null;
  routers: RouterNames;
  nowMs: number;
  isAdmin: boolean;
  viewSwitch?: React.ReactNode;
  showSame: Record<string, boolean>;
  onFrom: (v: string) => void;
  onUntil: (v: string) => void;
  onPick: (seconds: number) => void;
  onRouter: (id: string | null) => void;
  onRefresh: () => void;
  onToggleSame: (routerId: string) => void;
  onShowWindow: (w: CustomWindow) => void;
}

export function CompareScreen({
  state, from, until, routerId, routers, nowMs, isAdmin, viewSwitch, showSame, onFrom, onUntil, onPick, onRouter, onRefresh,
  onToggleSame, onShowWindow,
}: CompareScreenProps) {
  const a = state.answer;
  const fieldErr = fieldError(state.error, 'compare', ['t1', 't2', 'window']);
  const errorAt = (fields: string[]) => state.error !== null && (() => {
    const info = errorInfo(state.error, 'compare');
    return info.field && fields.includes(info.field)
      ? <span className="tm-field__error" role="alert">{info.message}</span> : null;
  })();
  const body = (() => {
    if (a === null) {
      if (state.error !== null && !fieldErr) return <ErrorBox of="compare" error={state.error} onRetry={onRefresh} />;
      if (fieldErr) return null;
      // 1.52.1: the hint only for an empty field; the prefilled ones load (they opened the view)
      const wait = waitingBody([from, until], state.loading);
      if (wait === 'none') return null;
      return wait === 'loading' ? <Spinner text={COMPARE_LOADING_TEXT} /> : <div className="cfg-hint">{COMPARE_PICK_TEXT}</div>;
    }
    const error = state.error !== null && !fieldErr && <ErrorBox of="compare" error={state.error} onRetry={onRefresh} />;
    if (a.status === 'off') return <>{error}<OffBox /></>;
    if (a.status === 'unavailable') {
      return <>{error}<div className="cfg-notice cfg-notice--warn tm-unavailable" role="status">{STATE_UNAVAILABLE_TEXT} {unavailableText(a.reason).replace(/^[^.]*\. /, '')}</div></>;
    }
    const band = [sideText('„Von“', a.before), sideText('„Bis“', a.after)].filter((x): x is string => !!x);
    const win = a.t1 !== null && a.t2 !== null ? customWindow(a.t1, a.t2, nowMs) : null;
    const listed = new Set(a.routers.map(r => r.routerId));
    const quiet = (a.after?.routers ?? a.before?.routers ?? []).filter(r => !listed.has(r.routerId)).length;
    const groups = Object.entries(a.marks.byGroup).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
    const others = otherSourcesText(a.otherSources);
    return (
      <>
        {error}
        {state.loading && <Spinner text={COMPARE_LOADING_TEXT} />}
        {band.length > 0 && (
          <div className="cfg-notice cfg-notice--warn tm-sides" role="note">
            <strong>Nicht für beide Zeitpunkte ist ein Zustand bekannt.</strong>
            {band.map(t => <span key={t}>{t}</span>)}
          </div>
        )}
        {a.status === 'partial' && <div className="cfg-notice cfg-notice--warn" role="note">Mindestens ein Teil war nicht lesbar; der Vergleich ist unvollständig.</div>}
        <div className="cfg-hint tm-summary" role="status">{compareSummary(a, isAdmin)}</div>
        <div className="tm-compare">
          {a.routers.map(r => (
            <CompareTable key={r.routerId} r={r} a={a} isAdmin={isAdmin} showSame={!!showSame[r.routerId]}
              onToggleSame={() => onToggleSame(r.routerId)} />
          ))}
          {quiet > 0 && <div className="cfg-hint">{quiet === 1 ? '1 Router ohne Unterschied ist' : `${quiet} Router ohne Unterschied sind`} nicht aufgeführt.</div>}
        </div>
        <Section title={SECTION_EVENTS}>
          <div className="tm-events">
            <span className="tm-events__count">{a.marks.count === 1 ? '1 Ereignis' : `${a.marks.count} Ereignisse`}</span>
            {groups.length > 0 && (
              <ul className="tm-groups" aria-label="Ereignisse je Art">
                {groups.map(([g, n]) => <li key={g} className="cfg-badge cfg-badge--muted">{groupText(g)}: {n}</li>)}
              </ul>
            )}
            {win && <button type="button" className="diag-btn cfg-btn tm-show" onClick={() => onShowWindow(win)}>In der Zeitleiste zeigen</button>}
          </div>
          {others && <div className="cfg-hint tm-others" role="note">{others}</div>}
        </Section>
        <Section title={SECTION_COMPARE_INCIDENTS}>
          {a.incidents.state !== 'ok' && a.incidents.state !== 'partial'
            ? <div className="cfg-hint"><PartNote p={a.incidents} /></div>
            : a.incidents.opened.length + a.incidents.resolved.length
              ? (
                <ul className="tm-items">
                  {a.incidents.opened.map((i, n) => <IncidentRow key={`o${i.id ?? n}`} i={i} what="eröffnet" />)}
                  {a.incidents.resolved.map((i, n) => <IncidentRow key={`r${i.id ?? n}`} i={i} what="behoben" />)}
                </ul>
              )
              : <div className="cfg-hint">Dazwischen wurde kein Vorfall eröffnet oder behoben.</div>}
          {a.incidents.truncated && <div className="cfg-hint" role="note">Weitere Vorfälle wurden gekürzt.</div>}
        </Section>
        {isAdmin && a.configVersions.reason !== 'admin_only' && (
          <Section title={SECTION_COMPARE_CONFIG}>
            {a.configVersions.state !== 'ok' && a.configVersions.state !== 'partial'
              ? <div className="cfg-hint"><PartNote p={a.configVersions} /></div>
              : a.configVersions.items.length
                ? (
                  <>
                    <div className="cfg-hint">
                      {a.configVersions.total === 1 ? '1 neue Version' : `${a.configVersions.total} neue Versionen`} dazwischen.
                    </div>
                    <ul className="tm-items">{a.configVersions.items.map((c, n) => <ConfigRow key={c.versionId ?? n} c={c} />)}</ul>
                  </>
                )
                : <div className="cfg-hint">Dazwischen wurde keine Version gespeichert.</div>}
            {a.configVersions.state === 'partial' && <div className="cfg-hint" role="note">{partStateText(a.configVersions)}</div>}
            {a.configVersions.truncated && <div className="cfg-hint" role="note">Weitere Versionen wurden gekürzt.</div>}
          </Section>
        )}
      </>
    );
  })();

  return (
    <Frame loading={state.loading} onRefresh={onRefresh} viewSwitch={viewSwitch} generatedAt={a?.generatedAt}>
      <div className="tm-filters" role="group" aria-label="Zeitpunkte des Vergleichs">
        <label className="tm-filter tm-field">
          <span className="tm-filter__name">Von</span>
          <input type="datetime-local" step="1" value={from} aria-invalid={!!parseLocalInput(from).error || undefined}
            onChange={e => onFrom(e.target.value)} />
          <LocalNote value={from} />
          {errorAt(['t1', 'window'])}
        </label>
        <label className="tm-filter tm-field">
          <span className="tm-filter__name">Bis</span>
          <input type="datetime-local" step="1" value={until} aria-invalid={!!parseLocalInput(until).error || undefined}
            onChange={e => onUntil(e.target.value)} />
          <LocalNote value={until} />
          {errorAt(['t2'])}
        </label>
        <div className="tm-filter">
          <span className="tm-filter__name">Schnellwahl</span>
          <div className="tm-chips">
            {COMPARE_PICKS.map(p => <Chip key={p.id} on={false} onClick={() => onPick(p.seconds)}>{p.label}</Chip>)}
          </div>
        </div>
        <RouterSelect value={routerId} routers={routers} onChange={onRouter} />
      </div>
      {body}
    </Frame>
  );
}

// ── Containers ───────────────────────────────────────────────────────────

function routersOf(answers: (StateAnswer | null | undefined)[], prev: RouterNames): RouterNames {
  let next = prev;
  for (const a of answers) {
    if (!a) continue;
    next = rememberRouters(next, a.routers.map(r => ({ routerId: r.routerId, routerName: r.routerName })) as never);
  }
  return next;
}

type Flag = { current: boolean };

/**
 * The load of an effect of "Zustand" or "Vergleich" (1.52.1): at once when
 * the view has just been opened, after a short pause for a changed field, on
 * a hidden page not now but when it is shown (`due`). Returns the cleanup.
 */
function openOrChange(active: boolean, opened: Flag, due: Flag, load: () => void): (() => void) | undefined {
  if (!active) {
    opened.current = false;
    due.current = false;
    return undefined;
  }
  const delay = loadDelay(!opened.current, pageVisible());
  opened.current = true;
  if (delay === null) {
    due.current = true;
    return undefined;
  }
  if (delay === 0) {
    load();
    return undefined;
  }
  const id = setTimeout(load, delay);
  return () => clearTimeout(id);
}

/** A load that was due on a hidden page runs when the page is shown again. */
function loadWhenShown(active: boolean, due: Flag, load: () => void): (() => void) | undefined {
  if (!active || typeof document === 'undefined') return undefined;
  const onShow = () => {
    if (due.current && pageVisible()) load();
  };
  document.addEventListener('visibilitychange', onShow);
  return () => document.removeEventListener('visibilitychange', onShow);
}

/** "Zustand": loads only while `active`; reloads every 60 s only while "Jetzt" is chosen. */
export function StateContainer({ api, active, viewSwitch, isAdmin = false, onShowWindow }: {
  api: TmApi; active: boolean; viewSwitch?: React.ReactNode; isAdmin?: boolean; onShowWindow: (w: CustomWindow) => void;
}) {
  const [input, setInput] = useState(() => toLocalInput(Date.now() / 1000));
  const [live, setLive] = useState(true);
  const [routerId, setRouterId] = useState<string | null>(null);
  const [routers, setRouters] = useState<RouterNames>({});
  const [state, dispatch] = useReducer(stateReducer, STATE_INIT);
  const seq = useRef(0);
  const lastMs = useRef<number | null>(null);
  const opened = useRef(false);
  const due = useRef(false);
  const ref = useRef({ input, live, routerId, active, state, isAdmin });
  ref.current = { input, live, routerId, active, state, isAdmin };

  const load = useCallback(() => {
    due.current = false;
    if (!api.state) return;
    const r = ref.current;
    // "Jetzt" asks for the server's now (no future moment by a clock difference),
    // and the field follows it (browser review: back in the view, the field kept the old time)
    const { at, input: shown } = stateLoadAt(r.live, r.input, Date.now() / 1000);
    if (at === null) return;
    if (shown !== r.input) {
      ref.current = { ...r, input: shown };
      setInput(shown);
    }
    const q = { at, routerId: r.routerId, clientsCursor: null };
    const n = ++seq.current;
    lastMs.current = Date.now();
    dispatch({ type: 'start', seq: n });
    api.state(q).then(
      answer => dispatch({ type: 'done', seq: n, answer, query: q }),
      error => dispatch({ type: 'fail', seq: n, error }),
    );
  }, [api]);

  const more = useCallback(() => {
    const r = ref.current;
    const q = api.state ? moreClientsQuery(r.state, r.isAdmin) : null;
    if (!api.state || q === null) return;
    const n = ++seq.current;
    dispatch({ type: 'moreStart', seq: n });
    api.state(q).then(
      answer => dispatch({ type: 'moreDone', seq: n, answer }),
      error => dispatch({ type: 'moreFail', seq: n, error }),
    );
  }, [api]);

  // Opening the view loads at once (1.52.1), a change after a short pause
  // (typing in the field); only while shown. Under "Jetzt" the field follows
  // the load, so its value is no reason to load.
  const typed = live ? null : input;
  useEffect(() => openOrChange(active, opened, due, load), [typed, live, routerId, active, load]);
  useEffect(() => loadWhenShown(active, due, load), [active, load]);

  // "Jetzt": like the timeline, at most every 60 s while visible
  useEffect(() => {
    if (!active || !live) return;
    const check = () => {
      if (!ref.current.active || !ref.current.live) return;
      if (shouldFetch({ visible: pageVisible(), lastMs: lastMs.current, nowMs: Date.now(), intervalMs: POLL_MIN_MS })) {
        // one fetch; load() sets the field to the moment it asks for
        load();
      }
    };
    const id = setInterval(check, CHECK_MS);
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [active, live, load]);

  useEffect(() => { setRouters(prev => routersOf([state.answer], prev)); }, [state.answer]);

  if (!active) return null;
  return (
    <StateScreen state={state} input={input} live={live} routerId={routerId} routers={routers} nowMs={Date.now()} isAdmin={isAdmin}
      viewSwitch={viewSwitch}
      onInput={v => { setLive(false); setInput(v); }}
      onNow={() => { setLive(true); setInput(toLocalInput(Date.now() / 1000)); }}
      onStep={sec => {
        const base = live ? Math.floor(Date.now() / 1000) : fromLocalInput(input) ?? Math.floor(Date.now() / 1000);
        setLive(false);
        setInput(toLocalInput(base - sec));
      }}
      onRouter={setRouterId} onRefresh={load} onMore={more} onShowWindow={onShowWindow} />
  );
}

/** "Vergleich": loads only while `active`, after a change; no automatic reload. */
export function CompareContainer({ api, active, viewSwitch, isAdmin = false, onShowWindow }: {
  api: TmApi; active: boolean; viewSwitch?: React.ReactNode; isAdmin?: boolean; onShowWindow: (w: CustomWindow) => void;
}) {
  const [from, setFrom] = useState(() => toLocalInput(Date.now() / 1000 - 86_400));
  const [until, setUntil] = useState(() => toLocalInput(Date.now() / 1000 - 1));
  const [routerId, setRouterId] = useState<string | null>(null);
  const [routers, setRouters] = useState<RouterNames>({});
  const [showSame, setShowSame] = useState<Record<string, boolean>>({});
  const [state, dispatch] = useReducer(compareReducer, COMPARE_INIT);
  const seq = useRef(0);
  const opened = useRef(false);
  const due = useRef(false);
  const ref = useRef({ from, until, routerId });
  ref.current = { from, until, routerId };

  const load = useCallback(() => {
    due.current = false;
    if (!api.compare) return;
    const t1 = fromLocalInput(ref.current.from);
    const t2 = fromLocalInput(ref.current.until);
    if (t1 === null || t2 === null) return;
    const n = ++seq.current;
    dispatch({ type: 'start', seq: n });
    api.compare({ t1, t2, routerId: ref.current.routerId }).then(
      answer => dispatch({ type: 'done', seq: n, answer }),
      error => dispatch({ type: 'fail', seq: n, error }),
    );
  }, [api]);

  // opening the view loads at once (1.52.1), a change after a short pause
  useEffect(() => openOrChange(active, opened, due, load), [from, until, routerId, active, load]);
  useEffect(() => loadWhenShown(active, due, load), [active, load]);

  useEffect(() => {
    setRouters(prev => routersOf([state.answer?.before, state.answer?.after], prev));
  }, [state.answer]);

  if (!active) return null;
  return (
    <CompareScreen state={state} from={from} until={until} routerId={routerId} routers={routers} nowMs={Date.now()} isAdmin={isAdmin}
      viewSwitch={viewSwitch} showSame={showSame}
      onFrom={setFrom} onUntil={setUntil}
      onPick={sec => {
        const now = Math.floor(Date.now() / 1000) - 1;
        setFrom(toLocalInput(now - sec));
        setUntil(toLocalInput(now));
      }}
      onRouter={setRouterId} onRefresh={load}
      onToggleSame={id => setShowSame(s => ({ ...s, [id]: !s[id] }))}
      onShowWindow={onShowWindow} />
  );
}
