/**
 * SecurityOverview — health score, active / critical findings, unknown
 * devices, coverage of the data sources and the current findings.
 *
 * Unknown is never shown as healthy: a null score is "Keine Bewertung
 * möglich", counts that cannot be trusted are "unbekannt", and "no findings"
 * is accompanied by the coverage so it is not read as "all clear". Not ready
 * (no module key: nothing is recorded) is "Nicht bereit", never "keine
 * Hinweise" and never green.
 */

import React from 'react';
import type { Coverage, Overview } from './securityTypes';
import {
  ASSESSMENT_LABEL,
  CATEGORY_LABEL,
  FACTOR_LABEL,
  LOG_PATH_LABEL,
  SEVERITY_LABEL,
  SEVERITY_TONE,
  STATUS_LABEL,
  STATUS_TONE,
  coverageFleetText,
  devicesObserved,
  factorText,
  flaggedDeviceCount,
  formatRelativeTs,
  incidentCounts,
  isActiveIncident,
  label,
  limitLines,
  rateLimitedText,
  reasonText,
  scoreReasonText,
  scoreView,
  shortId,
  sourceName,
  unknownDeviceCount,
} from './securityLogic.ts';
import { Fact, SectionBox, ToneBadge, Unknown } from './securityUi';

const MAX_LISTED = 20;

function Kpi({ name, value, sub, tone }: { name: string; value: React.ReactNode; sub?: React.ReactNode; tone?: string }) {
  return (
    <div className="sec-kpi">
      <div className="sec-kpi__name">{name}</div>
      <div className={`sec-kpi__value${tone ? ` sec-tone-${tone}` : ''}`}>{value}</div>
      {sub && <div className="sec-kpi__sub">{sub}</div>}
    </div>
  );
}

function ScoreCard({ overview }: { overview: Overview }) {
  const view = scoreView(overview.score, overview.ready);
  const reason = scoreReasonText(overview.score.reason);
  return (
    <SectionBox title="Sicherheits-Bewertung">
      <div className="sec-score">
        <div className={`sec-score__value sec-tone-${view.tone}${view.known ? '' : ' sec-score__value--text'}`}>
          {view.headline}
          {view.known && <span className="sec-score__max"> / 100</span>}
        </div>
        <div className="sec-score__text">
          {view.note && <div>{view.note}</div>}
          {reason && <div className="cfg-hint">{reason}</div>}
          <div className="cfg-hint">
            Die Bewertung fasst Hinweise zusammen. Sie ist eine Orientierung, kein Nachweis über den Zustand des Netzes.
          </div>
        </div>
      </div>
      {overview.score.factors.length > 0 && (
        <details className="sec-details">
          <summary>Wie die Bewertung entsteht</summary>
          <ul className="sec-factors">
            {overview.score.factors.map(f => {
              const t = factorText(f);
              return (
                <li key={f.id} className="sec-factor">
                  <span className="sec-factor__name">{label(FACTOR_LABEL, f.id)}</span>
                  <span className={`sec-tone-${t.tone}`}>{t.text}</span>
                  {f.limitations.length > 0 && (
                    <span className="cfg-hint sec-factor__note">Einschränkung: {reasonText(f.limitations)}</span>
                  )}
                  {!f.assessable && f.missing.length > 0 && (
                    <span className="cfg-hint sec-factor__note">Fehlende Quelle: {f.missing.map(sourceName).join(', ')}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </details>
      )}
    </SectionBox>
  );
}

function CoverageCard({ overview }: { overview: Overview }) {
  const { coverage } = overview;
  const value = coverage.value;
  return (
    <SectionBox title="Abdeckung der Datenquellen" hint="Ohne Datenquelle kann eine Erkennung nichts melden. Fehlende Meldungen sind dann kein Zeichen für Unbedenklichkeit.">
      <div className="sec-coverage">
        {value === null ? (
          <Unknown text="Abdeckung unbekannt" />
        ) : (
          <>
            <div className="sec-bar" role="img" aria-label={`Abdeckung ${value} Prozent`}>
              <div className="sec-bar__fill" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
            </div>
            <span className="sec-coverage__pct">{value} %</span>
          </>
        )}
      </div>
      <div className="sec-sources">
        <SourceGroup title="Liefern Daten" tone="ok" sources={coverage.available} coverage={coverage} empty="keine" />
        <SourceGroup title="Veraltet" tone="warn" sources={coverage.stale} coverage={coverage} empty="keine" />
        <SourceGroup title="Nicht verfügbar" tone="muted" sources={coverage.missing} coverage={coverage} empty="keine" />
      </div>
      {overview.logPath.setting !== null && (
        <Fact name="Log-Pfad">{label(LOG_PATH_LABEL, overview.logPath.setting)}</Fact>
      )}
      {rateLimitedText(overview.logPath.rateLimitedRouters) && (
        <div className="cfg-notice cfg-notice--warn">{rateLimitedText(overview.logPath.rateLimitedRouters)}</div>
      )}
    </SectionBox>
  );
}

function LimitsCard({ overview }: { overview: Overview }) {
  const lines = limitLines(overview.limits);
  if (lines.length === 0) return null;
  return (
    <SectionBox
      title="Speichergrenzen der Hinweise"
      hint="Hinweise aus Logzeilen (Firewall, DNS) und Hinweise aus allen anderen Quellen (WLAN, Konfiguration, Geräte) haben je eine feste Zahl von Plätzen, weil sich beide von außen auslösen lassen. Ist eine Quote voll, wird nur der neue Hinweis dieser Quelle nicht gespeichert und gezählt; die andere bleibt unberührt."
    >
      {lines.map(l => (
        <Fact key={l.name} name={l.name}><span className={`sec-tone-${l.tone}`}>{l.value}</span></Fact>
      ))}
    </SectionBox>
  );
}

function SourceGroup({ title, tone, sources, coverage, empty }: {
  title: string; tone: string; sources: string[]; coverage: Coverage; empty: string;
}) {
  return (
    <div className="sec-sources__group">
      <div className="cfg-subtitle">{title}</div>
      {sources.length === 0
        ? <span className="cfg-hint">{empty}</span>
        : (
          <div className="sec-chips">
            {sources.map(s => {
              // Fleet sources (firewall / DNS log): honest "von N von M Routern".
              const fleet = coverageFleetText(coverage, s);
              return (
                <ToneBadge key={s} tone={tone}>
                  {sourceName(s)}{fleet ? ` (${fleet})` : ''}
                </ToneBadge>
              );
            })}
          </div>
        )}
    </div>
  );
}

export function SecurityOverview({ overview, now, onOpenIncident }: {
  overview: Overview;
  now: number;
  onOpenIncident: (id: string) => void;
}) {
  const counts = incidentCounts(overview.incidents);
  // Not ready: nothing is recorded, so counts of hints say nothing (never 0 / "keine").
  const notReady = !overview.ready;
  const observed = devicesObserved(overview.coverage);
  const unknownDevices = observed ? unknownDeviceCount(overview.deviceCounts) : null;
  const flagged = observed ? flaggedDeviceCount(overview.deviceCounts) : null;
  const incomplete = overview.coverage.value === null || overview.coverage.value < 100;
  // No usable source at all: "0 findings" would only mean "nothing is watching".
  const noData = (overview.coverage.value ?? 0) === 0;
  const active = overview.incidents
    .filter(isActiveIncident)
    .sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0));
  const resolved = overview.incidents.filter(i => !isActiveIncident(i)).length;

  return (
    <div className="cfg-stack">
      <ScoreCard overview={overview} />

      <div className="sec-kpis">
        <Kpi
          name="Aktive Hinweise"
          value={notReady ? <Unknown text="nicht bereit" /> : counts.active === 0 && noData ? <Unknown text="keine Daten" /> : counts.active}
          sub={!notReady && incomplete ? 'bei unvollständiger Überwachung' : undefined}
        />
        <Kpi
          name="Davon kritisch"
          value={notReady ? <Unknown text="nicht bereit" /> : counts.critical === 0 && noData ? <Unknown text="keine Daten" /> : counts.critical}
          tone={!notReady && counts.critical > 0 ? 'critical' : undefined}
        />
        <Kpi
          name="Unbekannte Geräte"
          value={unknownDevices === null ? <Unknown /> : unknownDevices}
          sub={flagged === null ? 'Geräteliste nicht beobachtet' : `davon ${flagged} mit mehreren Indikatoren`}
          tone={flagged !== null && flagged > 0 ? 'critical' : undefined}
        />
      </div>
      {!notReady && incomplete && counts.active === 0 && (
        <div className="cfg-notice cfg-notice--info">
          Es liegen keine aktiven Hinweise vor, die Überwachung ist aber nicht vollständig. Das ist kein Beleg dafür, dass nichts passiert.
        </div>
      )}

      <CoverageCard overview={overview} />

      <SectionBox title="Aktuelle Hinweise">
        {notReady && active.length === 0 ? (
          <div className="cfg-hint">Nicht bereit: zurzeit werden keine Befunde aufgezeichnet. Das ist keine Entwarnung.</div>
        ) : active.length === 0 ? (
          <div className="cfg-hint">Keine aktiven Hinweise{resolved > 0 ? ` (${resolved} erledigt)` : ''}.</div>
        ) : (
          <ul className="sec-rows">
            {active.slice(0, MAX_LISTED).map(i => (
              <li key={i.id} className="sec-row">
                <div className="sec-row__main">
                  <ToneBadge tone={SEVERITY_TONE[i.severity ?? ''] ?? 'muted'}>{label(SEVERITY_LABEL, i.severity)}</ToneBadge>
                  <span className="sec-row__title">{i.title ?? i.detector ?? i.id}</span>
                </div>
                <div className="sec-row__meta">
                  <ToneBadge tone={STATUS_TONE[i.status ?? ''] ?? 'muted'}>{label(STATUS_LABEL, i.status)}</ToneBadge>
                  {i.fromLogs && <ToneBadge tone="muted">aus Logzeilen</ToneBadge>}
                  <span>{label(CATEGORY_LABEL, i.category)}</span>
                  {i.assessment && <span>{label(ASSESSMENT_LABEL, i.assessment)}</span>}
                  {i.routerId && <span className="diag-mono">{shortId(i.routerId)}</span>}
                  <span>zuletzt {formatRelativeTs(i.lastSeen, now)}</span>
                </div>
                <button type="button" className="diag-btn cfg-btn sec-row__action" onClick={() => onOpenIncident(i.id)}>
                  Details
                </button>
              </li>
            ))}
          </ul>
        )}
        {active.length > MAX_LISTED && (
          <div className="cfg-hint">{active.length - MAX_LISTED} weitere Hinweise: siehe Zeitleiste.</div>
        )}
      </SectionBox>

      <LimitsCard overview={overview} />
    </div>
  );
}
