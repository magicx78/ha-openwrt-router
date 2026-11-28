/**
 * SelfHealingView — Enterprise sub-tab "Self-Healing" (Self-Healing Center,
 * package J of Phase 7). READ ONLY: 1.53.0 observes and proposes; it never
 * calls a router, never executes and never changes a configuration. This
 * tab therefore has no control that changes anything: the only buttons are
 * "Aktualisieren", "Details anzeigen/schließen", "Erneut versuchen" and the
 * list filters, all of which only read (GET, shApi.ts).
 *
 * From top to bottom: the observe-only notice (in every state), the
 * overview (counts, last activity, the rollback line), routers and modes
 * (configured and effective mode, holds, fleet pause), the records (open
 * and closed, newest first) with the detail of one record opened in place
 * (history, explanation, the candidate labelled "Kandidat – nicht
 * ausgeführt", what would block), and the settings as stored (display only).
 * Non-administrators get the counts only (the server masks everything else).
 *
 * Truth or unknown: a missing value reads "unbekannt" (with the reason
 * where one is known), never 0, "nein" or green; a failed request shows an
 * error, never an empty "all fine"; "no records yet" is a state of its own.
 * Everything the server sends is rendered as React text, never as HTML;
 * the tab adds no address, host name or client name.
 *
 * Polling: when opened, on "Aktualisieren", and then at most every 60 s
 * while the page is visible (the other tabs' rule); EnterpriseView mounts
 * only the active tab, so a hidden tab sends nothing.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import configCSS from '../config/config.css?inline';
import wifiCSS from '../wifi/wifi.css?inline';
import shCSS from './selfhealing.css?inline';
import {
  CANDIDATE_LABEL, CANDIDATE_NOTE, DEFAULT_LIST_FILTERS, EMPTY_TEXT, EMPTY_TITLE, LOADING_TEXT, MASKED_TEXT,
  NO_CANDIDATE_TEXT, OBSERVE_TEXT, OBSERVE_TITLE, OFF_HOW, OFF_TITLE, POLL_MIN_MS, ROLLBACK_LINE, TAB_TITLE, UNKNOWN,
  actionText, actorText, approvalText, causeLevelText, causeStatusText, causeText, changeText, checkText, componentText,
  countText, cutText, durationText, errorInfo, factText, familyText, filterRows, holdText, impactLines, incidentText,
  isoUtc, modeText, modeWhy, outcomeView, permissionText, playbookText, pointsText, reasonText, riskView,
  rollbackMechanismText, rollbackStatusText, routerIdsOf, routerText, scoreText, shouldPoll, standText, stateCounts,
  stateText, stateView, tiles, timeText, verificationText, whyCodes, yesNo,
  type ListFilter, type ListFilters, type Tone,
} from './shLogic.ts';
import type {
  ActionList, ActionRow, Candidate, Detail, Explanation, Gate, Overview, Plan, Policy, RouterRow, Settings, ShApi,
} from './shTypes';

const CHECK_MS = Math.min(15_000, POLL_MIN_MS);

export function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

// ── Small pieces ─────────────────────────────────────────────────────────

function Badge({ tone, children, title }: { tone: Tone; children: React.ReactNode; title?: string }) {
  return <span className={`cfg-badge cfg-badge--${tone} sh-badge`} title={title}>{children}</span>;
}

function Unknown({ why }: { why?: string | null }) {
  return <span className="sh-unknown">{UNKNOWN}{why ? ` – ${why}` : ''}</span>;
}

function ErrorBox({ error, of, onRetry }: { error: unknown; of: 'overview' | 'list' | 'record'; onRetry?: () => void }) {
  const info = errorInfo(error, of);
  return (
    <div className={`cfg-notice cfg-notice--${info.kind === 'failed' ? 'warn' : 'error'} sh-error`} role="alert">
      <span>{info.message}</span>
      {onRetry && info.retry && <button type="button" className="diag-btn cfg-btn" onClick={onRetry}>Erneut versuchen</button>}
    </div>
  );
}

function Spinner({ text }: { text: string }) {
  return <div className="cfg-spinner sh-loading" aria-busy="true"><span className="cfg-spinner__dot" />{text}</div>;
}

function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" className={`wifi-nav__btn sh-chip${on ? ' active' : ''}`} aria-pressed={on} onClick={onClick}>
      {children}
    </button>
  );
}

function Time({ ts }: { ts: number | null | undefined }) {
  const iso = isoUtc(ts);
  return iso ? <time dateTime={iso} title={iso}>{timeText(ts)}</time> : <Unknown />;
}

/** A list of reason codes as German sentences (an unknown code stays raw). */
function Reasons({ codes, empty }: { codes: readonly string[]; empty: string }) {
  if (!codes.length) return <span className="sh-muted">{empty}</span>;
  return (
    <ul className="sh-reasons">
      {codes.map((c, i) => <li key={`${c}-${i}`} data-code={c}>{reasonText(c)}</li>)}
    </ul>
  );
}

function Fact({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="sh-fact">
      <dt>{name}</dt>
      <dd>{children}</dd>
    </div>
  );
}

// ── The notice at the top (every state) ──────────────────────────────────

export function ObserveNotice({ overview }: { overview: Overview | null }) {
  // the server's own word on the release; anything else than "observe only" is said, never hidden
  const other = overview !== null && (overview.releaseMode !== 'observe_only' || overview.writePath !== false);
  return (
    <div className="cfg-notice cfg-notice--info sh-observe" role="note">
      <strong>{OBSERVE_TITLE}</strong>
      <span>{OBSERVE_TEXT}</span>
      {other && (
        <span className="sh-observe__other">
          Der Server meldet einen anderen Stand (Betriebsart {overview.releaseMode ?? UNKNOWN}, Schreibweg {yesNo(overview.writePath)}).
          Dieser Tab zeigt trotzdem nur an.
        </span>
      )}
    </div>
  );
}

export function Frame({ loading, onRefresh, overview, children }: {
  loading: boolean; onRefresh: () => void; overview: Overview | null; children: React.ReactNode;
}) {
  return (
    <div className="cfg wifi sh">
      <style>{configCSS}</style>
      <style>{wifiCSS}</style>
      <style>{shCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={loading} onClick={onRefresh}>
          Aktualisieren
        </button>
      </div>
      <ObserveNotice overview={overview} />
      {overview?.generatedAt != null && <div className="cfg-hint sh-stand">{standText(overview.generatedAt)}</div>}
      {children}
    </div>
  );
}

export function OffBox() {
  return (
    <div className="cfg-notice cfg-notice--info sh-off" role="status">
      <strong>{OFF_TITLE}</strong>
      <span>{OFF_HOW}</span>
    </div>
  );
}

// ── Overview ─────────────────────────────────────────────────────────────

export function OverviewSection({ ov, masked }: { ov: Overview; masked: boolean }) {
  const counts = stateCounts(ov);
  return (
    <section className="cfg-section sh-section" aria-labelledby="sh-overview">
      <h3 className="cfg-section__title" id="sh-overview">Übersicht</h3>
      <ul className="sh-tiles">
        {tiles(ov).map(t => (
          <li key={t.id} className={`sh-tile${t.value === null ? ' sh-tile--unknown' : ''}`} data-tile={t.id}>
            <span className="sh-tile__value">{t.value === null ? UNKNOWN : t.value}</span>
            <span className="sh-tile__label">{t.label}</span>
            <span className="sh-tile__note">{t.note}</span>
          </li>
        ))}
      </ul>
      <dl className="sh-facts">
        <Fact name="Letzte Aktivität">
          {ov.lastActivity !== null ? <Time ts={ov.lastActivity} /> : <Unknown why="noch kein Datensatz" />}
          {masked && ov.lastActivity !== null && <span className="sh-muted"> (auf die Minute)</span>}
        </Fact>
        <Fact name="Datensätze gespeichert">{countText(ov.counts.total)}</Fact>
        <Fact name="Router">{countText(ov.counts.routers)}{ov.counts.routersHeld ? `, davon gesperrt: ${ov.counts.routersHeld}` : ''}</Fact>
        {!masked && <Fact name="Wartende Vorfälle">{ov.pendingIncidents === null ? <Unknown /> : `${ov.pendingIncidents} (warten, bis ihr Router frei ist)`}</Fact>}
        <Fact name="Nach Zustand">
          {Object.keys(ov.counts.byState).length === 0
            ? <Unknown why="Zahl vom Server nicht geliefert" />
            : counts.length === 0
              ? <span className="sh-muted">in keinem Zustand ein Datensatz</span>
              : <span>{counts.map(c => `${stateText(c.state)}: ${c.n}`).join(' · ')} <span className="sh-muted">(alle anderen: 0)</span></span>}
        </Fact>
      </dl>
      <div className="cfg-hint sh-rollback" role="note">
        {ov.automaticRollback === 'not_available' ? ROLLBACK_LINE : `Automatischer Rollback: ${ov.automaticRollback ?? UNKNOWN} (vom Server gemeldet).`}
      </div>
      {masked && <div className="cfg-hint sh-masked" role="note">{MASKED_TEXT}</div>}
    </section>
  );
}

// ── Routers and modes ────────────────────────────────────────────────────

function RouterCard({ r, ov, settings }: { r: RouterRow; ov: Overview; settings: Settings | null }) {
  const why = modeWhy(r, ov);
  const allow = settings?.routers[r.routerId]?.allowlist ?? null;
  return (
    <li className="sh-card" data-router={r.routerId}>
      <h4 className="sh-card__title" title={r.routerId}>{routerText(r.routerId)}</h4>
      <dl className="sh-facts">
        <Fact name="Eingestellt">{r.configuredMode ? modeText(r.configuredMode) : <Unknown />}</Fact>
        <Fact name="Gilt jetzt">
          {r.effectiveMode ? <strong>{modeText(r.effectiveMode)}</strong> : <Unknown />}
          {why && <span className="sh-muted"> ({why})</span>}
        </Fact>
        <Fact name="Gesperrt">
          {r.held === null ? <Unknown /> : r.held
            ? <span className="sh-warn">{r.hold ? holdText(r.hold) : 'ja (Sperre der Flotte)'}</span>
            : 'nein'}
        </Fact>
        <Fact name="Geladen">{r.loaded === null ? <Unknown /> : r.loaded ? 'ja' : 'nein (nur gespeicherte Datensätze)'}</Fact>
        <Fact name="Offene Datensätze">{countText(r.open)}</Fact>
        {allow !== null && allow.length > 0 && (
          <Fact name="Allowlist">{allow.map(a => `${actionText(a.actionType)} bis ${riskView(a.maxRisk).label}`).join(' · ')}</Fact>
        )}
      </dl>
    </li>
  );
}

export function RoutersSection({ ov, settings }: { ov: Overview; settings: Settings | null }) {
  const routers = ov.routers ?? [];
  const f = ov.fleet;
  return (
    <section className="cfg-section sh-section" aria-labelledby="sh-routers">
      <h3 className="cfg-section__title" id="sh-routers">Router und Modus</h3>
      <dl className="sh-facts sh-fleet">
        <Fact name="Flotte pausiert">
          {f.paused === null ? <Unknown /> : f.paused
            ? <span className="sh-warn">
                ja – {reasonText(f.pauseReason)}{f.pauseRemainingS !== null ? ` – endet in ${durationText(f.pauseRemainingS)}` : ''}
              </span>
            : 'nein'}
        </Fact>
        <Fact name="Flotte gesperrt">
          {f.held === null ? <Unknown /> : f.held
            ? <span className="sh-warn">{f.hold ? `ja – ${holdText(f.hold)}` : 'ja'}</span>
            : 'nein'}
        </Fact>
      </dl>
      {routers.length === 0
        ? <div className="cfg-hint">Kein Router in Self-Healing bekannt.</div>
        : <ul className="sh-cards">{routers.map(r => <RouterCard key={r.routerId} r={r} ov={ov} settings={settings} />)}</ul>}
    </section>
  );
}

// ── Records ──────────────────────────────────────────────────────────────

const SHOW: { id: ListFilter; label: string }[] = [
  { id: 'all', label: 'Alle' },
  { id: 'open', label: 'Offen' },
  { id: 'closed', label: 'Abgeschlossen' },
];

function RecordRow({ row, open, onToggle, children }: {
  row: ActionRow; open: boolean; onToggle: () => void; children?: React.ReactNode;
}) {
  const st = stateView(row.state);
  const risk = riskView(row.riskClass);
  const dec = outcomeView(row.decision);
  return (
    <li className={`sh-record${open ? ' sh-record--open' : ''}`} data-action={row.actionId}>
      <div className="sh-row">
        <span className="sh-row__time"><Time ts={row.createdAt} /></span>
        <span className="sh-row__state"><Badge tone={st.tone}>{st.label}</Badge></span>
        <span className="sh-row__main">
          <span className="sh-row__title">{incidentText(row.incidentType)}</span>
          <span className="sh-row__meta">
            {routerText(row.routerId)} · Ursache: {causeText(row.causeCode)}
            {row.causeLevel ? ` (${causeLevelText(row.causeLevel)})` : ''}
          </span>
        </span>
        <span className="sh-row__decision">
          <Badge tone={dec.tone}>{dec.label}</Badge>
          <span className="sh-muted"> {actionText(row.actionType)}</span>
        </span>
        <span className="sh-row__risk"><Badge tone={risk.tone}>{risk.label}</Badge></span>
        <span className="sh-row__open">
          <button type="button" className="diag-btn cfg-btn sh-toggle" aria-expanded={open} onClick={onToggle}>
            {open ? 'Details schließen' : 'Details anzeigen'}
          </button>
        </span>
      </div>
      {open && children}
    </li>
  );
}

export interface ListProps {
  list: ActionList | null;
  listError: unknown;
  ov: Overview;
  filters: ListFilters;
  selected: string | null;
  onFilters: (f: ListFilters) => void;
  onSelect: (id: string | null) => void;
  onRetry: () => void;
  detail?: React.ReactNode;
}

export function RecordsSection({ list, listError, ov, filters, selected, onFilters, onSelect, onRetry, detail }: ListProps) {
  const rows = list ? filterRows(list.actions, filters) : [];
  const routers = list ? routerIdsOf(list.actions, ov) : [];
  const cut = list ? cutText(list) : null;
  const body = (() => {
    if (list === null) {
      if (listError !== null) return <ErrorBox error={listError} of="list" onRetry={onRetry} />;
      return <Spinner text={LOADING_TEXT} />;
    }
    if (list.actions.length === 0) {
      return (
        <div className="cfg-empty sh-empty" role="status">
          <strong>{EMPTY_TITLE}</strong>
          <span>{EMPTY_TEXT}</span>
        </div>
      );
    }
    return (
      <>
        {rows.length === 0
          ? <div className="cfg-empty sh-empty">Keine Datensätze mit diesem Filter.</div>
          : (
            <ol className="sh-records">
              {rows.map(r => (
                <RecordRow key={r.actionId} row={r} open={selected === r.actionId}
                  onToggle={() => onSelect(selected === r.actionId ? null : r.actionId)}>
                  {detail}
                </RecordRow>
              ))}
            </ol>
          )}
        {cut && <div className="cfg-hint" role="note">{cut}</div>}
      </>
    );
  })();
  return (
    <section className="cfg-section sh-section" aria-labelledby="sh-records">
      <h3 className="cfg-section__title" id="sh-records">Datensätze</h3>
      <div className="cfg-hint">Ein Datensatz je Wurzelvorfall und Router, neueste zuerst. Offene stehen bei „Vorgeschlagen“ und gehen in dieser Version nie weiter.</div>
      {list !== null && list.actions.length > 0 && (
        <div className="sh-filters" role="group" aria-label="Filter der Datensätze">
          <div className="sh-chips">
            {SHOW.map(s => <Chip key={s.id} on={filters.show === s.id} onClick={() => onFilters({ ...filters, show: s.id })}>{s.label}</Chip>)}
          </div>
          {routers.length > 1 && (
            <label className="sh-field">
              <span className="sh-field__name">Router</span>
              <select value={filters.routerId ?? ''} onChange={e => onFilters({ ...filters, routerId: e.target.value || null })}>
                <option value="">Alle Router</option>
                {routers.map(id => <option key={id} value={id}>{routerText(id)}</option>)}
              </select>
            </label>
          )}
        </div>
      )}
      {list !== null && listError !== null && <ErrorBox error={listError} of="list" onRetry={onRetry} />}
      {body}
    </section>
  );
}

// ── Detail of one record ─────────────────────────────────────────────────

function GateBlock({ gate }: { gate: Gate | null }) {
  if (!gate) return <Fact name="Erlaubnis"><Unknown why="keine Antwort des Gates" /></Fact>;
  return (
    <>
      <Fact name="Erlaubnis">{permissionText(gate.permission)}</Fact>
      <Fact name="Geltender Modus">{modeText(gate.effectiveMode)}</Fact>
      <Fact name="Ausführbar jetzt">{gate.executableNow === true ? 'ja' : gate.executableNow === false ? 'nein' : <Unknown />}</Fact>
      <Fact name="Gründe des Gates"><Reasons codes={gate.reasons} empty="keine genannt" /></Fact>
    </>
  );
}

function ScoreLines({ policy }: { policy: Policy }) {
  if (!policy.contributions.length) return null;
  return (
    <ul className="sh-score">
      {policy.contributions.map((c, i) => (
        <li key={`${c.factor}-${i}`}>
          <span className="sh-score__factor">{reasonText(c.factor)}</span>
          <span className="sh-score__points">{pointsText(c.points)}</span>
          <span className="sh-score__reason">{reasonText(c.reason)}</span>
        </li>
      ))}
    </ul>
  );
}

function PolicyBlock({ policy }: { policy: Policy }) {
  const risk = riskView(policy.riskClass);
  const impact = impactLines(policy.impact);
  return (
    <>
      <Fact name="Ergebnis"><Badge tone={outcomeView(policy.outcome).tone}>{outcomeView(policy.outcome).label}</Badge></Fact>
      <Fact name="Begründung"><Reasons codes={whyCodes(policy)} empty="keine genannt" /></Fact>
      <Fact name="Konfidenz">{policy.scoreTotal === null ? <Unknown /> : `${policy.scoreTotal} von 100`}</Fact>
      <Fact name="Risiko">
        <Badge tone={risk.tone}>{risk.label}</Badge>
        {policy.riskAssessed === false && <span className="sh-warn"> nicht bewertet</span>}
        <Reasons codes={policy.riskReasons} empty="keine Risikogründe genannt" />
        {policy.riskMissing.length > 0 && <span className="sh-muted">Fehlende Angaben: {policy.riskMissing.map(factText).join(', ')}</span>}
      </Fact>
      {impact.length > 0 && (
        <Fact name="Erwartete Auswirkung">
          <ul className="sh-reasons">{impact.map(l => <li key={l.key}>{l.label}: {l.value === UNKNOWN ? <Unknown /> : l.value}</li>)}</ul>
        </Fact>
      )}
      {policy.recovery && (
        <Fact name="Wiederherstellung">
          {reasonText(policy.recovery.statement)}
          {/* the rollback kind only when the statement does not already say it (read_only / read_only_nothing_changes) */}
          {policy.recovery.rollback && !(policy.recovery.statement ?? '').startsWith(policy.recovery.rollback) && (
            <span className="sh-muted"> ({reasonText(policy.recovery.rollback)})</span>
          )}
        </Fact>
      )}
    </>
  );
}

export function CandidateBlock({ candidate }: { candidate: Candidate | null }) {
  if (!candidate) {
    return (
      <div className="sh-candidate sh-candidate--none" data-candidate="none">
        <h5 className="sh-sub">{CANDIDATE_LABEL}</h5>
        <p className="sh-p">{NO_CANDIDATE_TEXT}</p>
      </div>
    );
  }
  return (
    <div className="sh-candidate" data-candidate={candidate.actionType ?? 'unknown'}>
      <h5 className="sh-sub">
        <span className="cfg-badge cfg-badge--warn sh-candidate__label">{CANDIDATE_LABEL}</span>{' '}
        {actionText(candidate.actionType)}
      </h5>
      <p className="sh-p sh-muted">{CANDIDATE_NOTE}</p>
      {candidate.error ? (
        <p className="sh-p sh-warn">Die Bewertung des Kandidaten ist gescheitert ({candidate.error}). Am Datensatz ändert das nichts.</p>
      ) : (
        <dl className="sh-facts">
          <Fact name="Playbook">
            {candidate.playbookId ? `${playbookText(candidate.playbookId)}${candidate.playbookVersion !== null ? ` (Fassung ${candidate.playbookVersion})` : ''}` : <Unknown why="keines genannt" />}
          </Fact>
          {candidate.policy ? <PolicyBlock policy={candidate.policy} /> : <Fact name="Ergebnis">{outcomeView(candidate.outcome).label}</Fact>}
          <Fact name="Geplante Änderung (nicht ausgeführt)">
            {candidate.plannedChanges.length
              ? <ul className="sh-reasons">{candidate.plannedChanges.map((c, i) => <li key={i}>{changeText(c)}</li>)}</ul>
              : <span className="sh-muted">keine</span>}
          </Fact>
          <GateBlock gate={candidate.gate} />
          {candidate.facts && candidate.facts.unknown.length > 0 && (
            <Fact name="Nicht bekannte Fakten">{candidate.facts.unknown.map(factText).join(', ')}</Fact>
          )}
        </dl>
      )}
      {candidate.policy && candidate.policy.contributions.length > 0 && (
        <>
          <h5 className="sh-sub">Beiträge zur Konfidenz</h5>
          <ScoreLines policy={candidate.policy} />
        </>
      )}
    </div>
  );
}

function Blockers({ plan }: { plan: Plan | null; }) {
  if (!plan) return <Unknown why="kein Plan vom Server" />;
  return (
    <>
      <p className="sh-p">
        Ausführbar: <strong>{plan.executable === true ? 'ja' : plan.executable === false ? 'nein' : UNKNOWN}</strong>
      </p>
      <Reasons codes={plan.blockers} empty="Der Server nennt nichts, das sperrt." />
    </>
  );
}

function ExplanationBlock({ explanation }: { explanation: Explanation | null }) {
  if (!explanation) return <Unknown why="keine Erklärung vom Server" />;
  return (
    <dl className="sh-facts">
      {explanation.policy ? <PolicyBlock policy={explanation.policy} /> : <Fact name="Richtlinie"><Unknown why="keine Entscheidung der Richtlinie" /></Fact>}
      <GateBlock gate={explanation.gate} />
      {explanation.facts && (
        <Fact name="Nicht bekannte Fakten">
          {explanation.facts.unknown.length ? explanation.facts.unknown.map(factText).join(', ') : <span className="sh-muted">keine</span>}
          <span className="sh-muted"> (bekannt: {explanation.facts.known.length})</span>
        </Fact>
      )}
    </dl>
  );
}

export interface DetailProps {
  detail: Detail | null;
  detailError: unknown;
  plan: Plan | null;
  planError: unknown;
  loading: boolean;
  onRetry: () => void;
}

export function DetailPanel({ detail, detailError, plan, planError, loading, onRetry }: DetailProps) {
  if (detail === null) {
    return (
      <div className="sh-detail">
        {detailError !== null ? <ErrorBox error={detailError} of="record" onRetry={onRetry} /> : <Spinner text="Datensatz wird geladen …" />}
      </div>
    );
  }
  const a = detail.action;
  const d = a.decisionDetail;
  const risk = riskView(a.risk?.riskClass ?? null);
  const explanation = plan?.explanation ?? null;
  return (
    <div className="sh-detail" aria-busy={loading || undefined}>
      {detailError !== null && <ErrorBox error={detailError} of="record" onRetry={onRetry} />}

      <div className="sh-block">
        <h4 className="sh-block__title">Vorfall und Ursache</h4>
        <dl className="sh-facts">
          <Fact name="Vorfall">{incidentText(a.incidentType)} <span className="sh-muted">({a.incidentId ?? UNKNOWN}{a.incidentReopen ? `, ${a.incidentReopen}-mal wieder geöffnet` : ''})</span></Fact>
          <Fact name="Router">{routerText(a.routerId)}</Fact>
          <Fact name="Ursache">
            {a.cause ? (
              <span>
                {causeText(a.cause.code)} – Stufe {causeLevelText(a.cause.level)}, {causeStatusText(a.cause.status)}
                {a.cause.confidence !== null ? `, Konfidenz ${Math.round(a.cause.confidence * 100)} %` : ', Konfidenz unbekannt'}
                {a.cause.sourceFamilies.length > 0 && <span className="sh-muted"> · Quellen: {a.cause.sourceFamilies.map(familyText).join(', ')}</span>}
              </span>
            ) : 'keine Ursache gemeldet'}
          </Fact>
          <Fact name="Zustand"><Badge tone={stateView(a.state).tone}>{stateText(a.state)}</Badge></Fact>
          <Fact name="Geltender Modus">{detail.effectiveMode ? modeText(detail.effectiveMode) : <Unknown />}</Fact>
          <Fact name="Sperre des Routers">{detail.routerHold ? <span className="sh-warn">{holdText(detail.routerHold)}</span> : 'keine'}</Fact>
          {(a.flags.inMaintenance || a.flags.interrupted) && (
            <Fact name="Markierungen">
              {[a.flags.inMaintenance ? 'in Wartung' : null, a.flags.interrupted ? 'durch Neustart unterbrochen' : null].filter(Boolean).join(', ')}
            </Fact>
          )}
        </dl>
      </div>

      <div className="sh-block">
        <h4 className="sh-block__title">Entscheidung des Datensatzes</h4>
        <dl className="sh-facts">
          <Fact name="Aktion">{actionText(a.actionType)}</Fact>
          <Fact name="Ergebnis">{d ? <Badge tone={outcomeView(d.outcome).tone}>{outcomeView(d.outcome).label}</Badge> : <Unknown why="keine Entscheidung gespeichert" />}</Fact>
          {d && <Fact name="Begründung"><Reasons codes={whyCodes(d)} empty="keine genannt" /></Fact>}
          {d && <Fact name="Konfidenz bei der Entscheidung">{scoreText(d.score)}</Fact>}
          {d && d.factors.length > 0 && (
            <Fact name="Beiträge zur Konfidenz">
              <ul className="sh-score">
                {d.factors.map((f, i) => (
                  <li key={`${f.factor}-${i}`}>
                    <span className="sh-score__factor">{reasonText(f.factor)}</span>
                    <span className="sh-score__points">{pointsText(f.value === null ? null : Math.round(f.value * 100))}</span>
                    <span className="sh-score__reason">{reasonText(f.reason)}</span>
                  </li>
                ))}
              </ul>
            </Fact>
          )}
          <Fact name="Risiko"><Badge tone={risk.tone}>{risk.label}</Badge><Reasons codes={a.risk?.reasons ?? []} empty="keine Risikogründe genannt" /></Fact>
          <Fact name="Geplante Änderung">
            {a.plannedChanges.length ? <ul className="sh-reasons">{a.plannedChanges.map((c, i) => <li key={i}>{changeText(c)}</li>)}</ul> : 'keine'}
          </Fact>
        </dl>
      </div>

      <div className="sh-block">
        <h4 className="sh-block__title">Erklärung der Richtlinie (mit den Fakten von jetzt)</h4>
        {planError !== null ? <ErrorBox error={planError} of="record" onRetry={onRetry} /> : <ExplanationBlock explanation={explanation} />}
      </div>

      <div className="sh-block">
        {planError !== null
          ? <><h4 className="sh-block__title">{CANDIDATE_LABEL}</h4><Unknown why="Plan nicht geladen" /></>
          : <CandidateBlock candidate={explanation?.candidate ?? null} />}
      </div>

      <div className="sh-block">
        <h4 className="sh-block__title">Was würde blockieren</h4>
        {planError !== null ? <Unknown why="Plan nicht geladen" /> : <Blockers plan={plan} />}
        <h5 className="sh-sub">Vorabprüfungen des Datensatzes</h5>
        {a.preflight === null
          ? <Unknown why="vom Server nicht geliefert" />
          : a.preflight.length === 0
            ? <span className="sh-muted">Keine Vorabprüfung gespeichert (in 1.53.0 laufen keine).</span>
            : (
              <ul className="sh-reasons">
                {a.preflight.map((c, i) => (
                  <li key={i} data-outcome={c.outcome ?? 'unknown'}>
                    {reasonText(c.check)}: <strong className={c.outcome === 'fail' ? 'sh-warn' : undefined}>{checkText(c.outcome)}</strong>
                    {c.reason ? ` – ${reasonText(c.reason)}` : ''}
                  </li>
                ))}
              </ul>
            )}
      </div>

      <div className="sh-block">
        <h4 className="sh-block__title">Zähler</h4>
        <dl className="sh-facts">
          <Fact name="Vorfall wieder geöffnet">{a.incidentReopen === null ? <Unknown /> : a.incidentReopen === 0 ? 'nie' : `${a.incidentReopen}-mal`}</Fact>
          <Fact name="Ausführungsversuche">{a.executionAttempt === null ? <Unknown /> : String(a.executionAttempt)}</Fact>
          <Fact name="Frühere Versuche (Richtlinie)">
            {(() => {
              const f = d?.factors.find(x => x.factor === 'prior_attempts');
              return f ? reasonText(f.reason) : <Unknown why="nicht in der Entscheidung" />;
            })()}
          </Fact>
          <Fact name="Schritte im Verlauf">{String(a.history.length)}</Fact>
          <Fact name="Versuche je Router in 24 h"><Unknown why="keine lesende Route liefert diese Zahl" /></Fact>
        </dl>
      </div>

      <div className="sh-block">
        <h4 className="sh-block__title">Verlauf</h4>
        {a.history.length === 0 ? <Unknown why="kein Verlauf geliefert" /> : (
          <ol className="sh-history">
            {a.history.map((h, i) => (
              <li key={i} className="sh-history__item">
                <span className="sh-history__time"><Time ts={h.ts} /></span>
                <span className="sh-history__step">{h.fromState ? `${stateText(h.fromState)} → ` : ''}{stateText(h.toState)}</span>
                <span className="sh-history__actor">{actorText(h.actor)}</span>
                <span className="sh-history__reason">{reasonText(h.reason)}</span>
              </li>
            ))}
          </ol>
        )}
      </div>

      <div className="sh-block">
        <h4 className="sh-block__title">Weitere Angaben</h4>
        <dl className="sh-facts">
          <Fact name="Playbook">{a.playbookId ? playbookText(a.playbookId) : 'keines'}</Fact>
          <Fact name="Freigabe">{approvalText(a.approvalStatus)}</Fact>
          <Fact name="Sicherung">
            {a.backupVersionId ? a.backupVersionId : a.backupReason ? reasonText(a.backupReason) : 'keine Sicherung verknüpft'}
          </Fact>
          <Fact name="Ausführung">{a.executionAttempt === 0 ? 'nie ausgeführt' : a.executionAttempt === null ? <Unknown /> : `Versuch ${a.executionAttempt}`}</Fact>
          <Fact name="Nachprüfung">{a.verificationResult ? verificationText(a.verificationResult) : 'keine Nachprüfung'}</Fact>
          <Fact name="Rollback">
            {rollbackStatusText(a.rollbackStatus)} <span className="sh-muted">(Mechanismus: {rollbackMechanismText(a.rollbackMechanism)}{a.rollbackStatement ? `; ${reasonText(a.rollbackStatement)}` : ''})</span>
          </Fact>
          <Fact name="Erwartete Auswirkung">
            {impactLines(a.expectedImpact).length === 0
              ? <Unknown why="nicht erfasst" />
              : <ul className="sh-reasons">{impactLines(a.expectedImpact).map(l => <li key={l.key}>{l.label}: {l.value === UNKNOWN ? <Unknown /> : l.value}</li>)}</ul>}
          </Fact>
          <Fact name="Bauteile">
            {a.components.length ? a.components.map(c => `${componentText(c.kind)} ${c.name ?? ''}`.trim()).join(', ') : 'keine (der Router selbst)'}
          </Fact>
          <Fact name="Angelegt / geändert"><Time ts={a.createdAt} /> / <Time ts={a.updatedAt} /></Fact>
        </dl>
      </div>
    </div>
  );
}

// ── Settings (display only) ──────────────────────────────────────────────

export function SettingsSection({ settings, error }: { settings: Settings | null; error: unknown }) {
  return (
    <section className="cfg-section sh-section" aria-labelledby="sh-settings">
      <h3 className="cfg-section__title" id="sh-settings">Einstellungen (nur Anzeige)</h3>
      {error !== null && <ErrorBox error={error} of="list" />}
      {settings === null ? (error === null ? <Spinner text={LOADING_TEXT} /> : null) : (
        <dl className="sh-facts">
          <Fact name="Schalter in den Optionen">{settings.moduleSwitch === null ? <Unknown /> : settings.moduleSwitch ? 'an' : 'aus'}</Fact>
          <Fact name="Modul im Speicher">{settings.enabled === null ? <Unknown /> : settings.enabled ? 'an' : 'aus'}</Fact>
          <Fact name="Abklingzeit">{durationText(settings.limits.cooldown_s ?? null)}</Fact>
          <Fact name="Versuche je 24 h">{countText(settings.limits.max_attempts_24h ?? null)}</Fact>
          <Fact name="Flotten-Pause nach Fehlern">{durationText(settings.limits.fleet_pause_s ?? null)}</Fact>
          <Fact name="Aufbewahrung abgeschlossener Datensätze">{durationText(settings.retentionS)}</Fact>
          <Fact name="Höchstens gespeichert">{countText(settings.maxActions)}</Fact>
        </dl>
      )}
    </section>
  );
}

// ── The screen (pure: everything from props) ─────────────────────────────

export interface ShState {
  overview: Overview | null;
  overviewError: unknown;
  list: ActionList | null;
  listError: unknown;
  settings: Settings | null;
  settingsError: unknown;
  detail: Detail | null;
  detailError: unknown;
  plan: Plan | null;
  planError: unknown;
  loading: boolean;
}

export const SH_INIT: ShState = {
  overview: null, overviewError: null, list: null, listError: null, settings: null, settingsError: null,
  detail: null, detailError: null, plan: null, planError: null, loading: false,
};

export interface ScreenProps {
  state: ShState;
  isAdmin: boolean;
  filters: ListFilters;
  selected: string | null;
  onRefresh: () => void;
  onFilters: (f: ListFilters) => void;
  onSelect: (id: string | null) => void;
}

/** True when the tab must show "off": the route is missing or not running, or the module is off. */
export function isOff(state: ShState): boolean {
  if (state.overview?.status === 'module_disabled') return true;
  return state.overview === null && state.overviewError !== null && errorInfo(state.overviewError).kind === 'off';
}

export function SelfHealingScreen({ state, isAdmin, filters, selected, onRefresh, onFilters, onSelect }: ScreenProps) {
  const ov = state.overview;
  const body = (() => {
    if (isOff(state)) {
      return (
        <>
          {state.overviewError !== null && errorInfo(state.overviewError).kind !== 'off' && <ErrorBox error={state.overviewError} of="overview" onRetry={onRefresh} />}
          <OffBox />
          {state.overviewError !== null && <div className="cfg-hint" role="note">{errorInfo(state.overviewError).message}</div>}
        </>
      );
    }
    if (ov === null) {
      if (state.overviewError !== null) return <ErrorBox error={state.overviewError} of="overview" onRetry={onRefresh} />;
      return <Spinner text={LOADING_TEXT} />;
    }
    // an answer from before stays on screen, the failed refresh is said above it
    const stale = state.overviewError !== null && <ErrorBox error={state.overviewError} of="overview" onRetry={onRefresh} />;
    const masked = !isAdmin || ov.routers === null;
    if (masked) {
      return <>{stale}<OverviewSection ov={ov} masked /></>;
    }
    const detail = selected ? (
      <DetailPanel detail={state.detail?.action.actionId === selected ? state.detail : null} detailError={state.detailError}
        plan={state.plan?.actionId === selected ? state.plan : null} planError={state.planError} loading={state.loading} onRetry={onRefresh} />
    ) : null;
    return (
      <>
        {stale}
        <OverviewSection ov={ov} masked={false} />
        <RoutersSection ov={ov} settings={state.settings} />
        <RecordsSection list={state.list} listError={state.listError} ov={ov} filters={filters} selected={selected}
          onFilters={onFilters} onSelect={onSelect} onRetry={onRefresh} detail={detail} />
        <SettingsSection settings={state.settings} error={state.settingsError} />
      </>
    );
  })();
  return (
    <Frame loading={state.loading} onRefresh={onRefresh} overview={ov}>
      {state.loading && ov !== null && <Spinner text="Aktualisiere …" />}
      {body}
    </Frame>
  );
}

// ── Container (fetching and polling; GET only, through ShApi) ────────────

type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

function settle<T>(p: Promise<T>): Promise<Settled<T>> {
  return p.then(value => ({ ok: true as const, value }), error => ({ ok: false as const, error }));
}

/** Merge one load into the state: a new answer replaces, a failure keeps the last answer and says so. */
export function applyLoad(prev: ShState, r: {
  overview: Settled<Overview>; list?: Settled<ActionList>; settings?: Settled<Settings>;
  detail?: Settled<Detail>; plan?: Settled<Plan | null>; selected: string | null;
}): ShState {
  const next: ShState = { ...prev, loading: false };
  if (r.overview.ok) { next.overview = r.overview.value; next.overviewError = null; } else {
    next.overviewError = r.overview.error;
    // off or gone: nothing from before is shown as current
    const kind = errorInfo(r.overview.error).kind;
    if (kind === 'off' || kind === 'forbidden' || kind === 'gone') next.overview = null;
  }
  if (r.list) { if (r.list.ok) { next.list = r.list.value; next.listError = null; } else next.listError = r.list.error; }
  if (r.settings) { if (r.settings.ok) { next.settings = r.settings.value; next.settingsError = null; } else next.settingsError = r.settings.error; }
  if (r.selected === null) {
    next.detail = null; next.detailError = null; next.plan = null; next.planError = null;
  } else {
    if (r.detail) {
      if (r.detail.ok) { next.detail = r.detail.value; next.detailError = null; } else {
        next.detailError = r.detail.error;
        if (prev.detail?.action.actionId !== r.selected) next.detail = null;
      }
    }
    if (r.plan) {
      if (r.plan.ok) { next.plan = r.plan.value; next.planError = null; } else {
        next.planError = r.plan.error;
        if (prev.plan?.actionId !== r.selected) next.plan = null;
      }
    }
  }
  return next;
}

export function SelfHealingView({ api, isAdmin = false }: { api: ShApi; isAdmin?: boolean }) {
  const [state, setState] = useState<ShState>(SH_INIT);
  const [filters, setFilters] = useState<ListFilters>(DEFAULT_LIST_FILTERS);
  const [selected, setSelected] = useState<string | null>(null);
  const stateRef = useRef(state);
  stateRef.current = state;
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const seq = useRef(0);
  const lastMs = useRef<number | null>(null);

  const load = useCallback(() => {
    const n = ++seq.current;
    const sel = selectedRef.current;
    lastMs.current = Date.now();
    setState(s => ({ ...s, loading: true }));
    const overview = settle(api.overview());
    const admin = isAdmin;
    const list = admin ? settle(api.actions()) : undefined;
    const settings = admin ? settle(api.settings()) : undefined;
    const detail = admin && sel ? settle(api.action(sel)) : undefined;
    const plan = admin && sel ? settle(api.plan(sel)) : undefined;
    void Promise.all([overview, list, settings, detail, plan]).then(([o, l, st, d, p]) => {
      if (n !== seq.current) return; // a newer load is on its way
      setState(prev => applyLoad(prev, { overview: o, list: l, settings: st, detail: d, plan: p, selected: sel }));
    });
  }, [api, isAdmin]);

  // open: load now; a new selection loads its record (and everything else) at once
  useEffect(() => {
    if (pageVisible()) load();
    else lastMs.current = null;
  }, [load, selected]);

  // at most every 60 s while visible; nothing while off, forbidden or gone
  useEffect(() => {
    const check = () => {
      const s = stateRef.current;
      const kind = s.overview === null && s.overviewError !== null ? errorInfo(s.overviewError).kind : null;
      const stopped = kind === 'forbidden' || kind === 'gone' || kind === 'off' || s.overview?.status === 'module_disabled';
      if (shouldPoll({ visible: pageVisible(), lastMs: lastMs.current, nowMs: Date.now(), stopped })) load();
    };
    const id = setInterval(check, CHECK_MS);
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [load]);

  const onSelect = useCallback((id: string | null) => setSelected(id), []);
  return (
    <SelfHealingScreen state={state} isAdmin={isAdmin} filters={filters} selected={selected}
      onRefresh={load} onFilters={setFilters} onSelect={onSelect} />
  );
}
