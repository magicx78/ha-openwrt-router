/**
 * DiagOverview — quality score with coverage, active findings, module state,
 * last run, and the diagnosis chain per measurement point (Home Assistant and
 * every router): Router → Gateway → WAN → Internet → DNS.
 *
 * Unknown / not measured is shown with its own neutral style and text; the
 * score always carries its coverage.
 */

import React from 'react';
import type { Overview, PointView } from './diagnosticsTypes';
import {
  chainChips, findingView, formatAge, formatMs, formatPct, formatTs, moduleView, pointScoreView,
  pointStateView, scoreView,
} from './diagnosticsLogic.ts';
import { ChainRow, Fact, SectionBox, ToneBadge, Unknown } from './diagUi';

function Kpi({ name, tone, children, sub }: { name: string; tone?: string; children: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div className="dg-kpi">
      <span className="dg-kpi__name">{name}</span>
      <span className={`dg-kpi__value${tone ? ` dg-tone-${tone}` : ''}`}>{children}</span>
      {sub && <span className="dg-kpi__sub">{sub}</span>}
    </div>
  );
}

function PointCard({ point }: { point: PointView }) {
  const name = point.kind === 'ha' ? 'Home Assistant' : `Router ${point.id}`;
  const state = pointStateView(point);
  const finding = findingView(point.finding);
  const score = point.kind === 'router' ? pointScoreView(point.score) : null;
  return (
    <li className="dg-point">
      <div className="dg-point__head">
        <span className="dg-point__name">{name}</span>
        <ToneBadge tone={state.tone}>{state.label}</ToneBadge>
        {point.settling && <ToneBadge tone="info">stabilisiert sich</ToneBadge>}
        {state.reasonText && state.tone === 'muted' && <span className="dg-muted">{state.reasonText}</span>}
      </div>
      <ChainRow chips={chainChips(point.chain)} label={`Diagnosekette ${name}`} />
      {finding ? (
        <div className="dg-finding">
          <ToneBadge tone={finding.tone}>{finding.text}</ToneBadge>
          {finding.causeText && (
            <span className="dg-muted">Ursache: <span className={`dg-tone-${finding.causeTone}`}>{finding.causeText}</span></span>
          )}
          {finding.unmeasuredText && <span className="dg-muted">{finding.unmeasuredText}</span>}
          {finding.recommendation && <span className="dg-finding__rec">{finding.recommendation}</span>}
        </div>
      ) : (
        <div className="dg-finding"><Unknown text="Noch keine Aussage (kein Befund geliefert)" /></div>
      )}
      <div className="dg-point__meta">
        {score && (
          <span>
            Wert: {score.value === null ? <Unknown text="keine Bewertung" /> : <span className={`dg-tone-${score.tone}`}>{score.value}</span>}
            {' · '}{score.coverageText}{score.low && score.value !== null ? ' (geringe Aussagekraft)' : ''}
          </span>
        )}
        {point.restarts24h !== null && <span>Neustarts (24 Std.): {point.restarts24h}</span>}
        {point.downInterfaces !== null && point.downInterfaces > 0 && <span>Schnittstellen ohne Verbindung: {point.downInterfaces}</span>}
      </div>
    </li>
  );
}

export function DiagOverview({ overview, nowMs }: { overview: Overview; nowMs: number }) {
  const module = moduleView(overview.state, overview.reasons);
  const fleet = overview.fleet;
  const score = scoreView(fleet);
  const lastTs = overview.lastRun?.ts ?? null;
  const age = formatAge(lastTs, nowMs);
  const points: PointView[] = [...(overview.ha ? [overview.ha] : []), ...overview.routers];

  return (
    <div className="cfg-stack">
      <div className="dg-kpis">
        <Kpi name="Qualitätswert" tone={score.tone}
          sub={<>{score.coverageText}{score.note ? ` – ${score.note}` : ''}</>}>
          {score.value === null ? <Unknown text={score.text} /> : <>{score.value}<span className="dg-kpi__max"> / 100</span></>}
        </Kpi>
        <Kpi name="Aktive Befunde" sub={fleet && fleet.routersUnknown ? `${fleet.routersUnknown} Router ohne Daten` : undefined}>
          {fleet === null || fleet.findingsActive === null ? <Unknown /> : fleet.findingsActive}
        </Kpi>
        <Kpi name="Modul" tone={module.tone} sub={module.reasons.length > 0 ? module.reasons.join(' · ') : undefined}>
          {module.label}
        </Kpi>
        <Kpi name="Letzte Messung" sub={lastTs !== null && overview.lastRun?.probes !== null ? `${overview.lastRun?.probes} Messungen` : undefined}>
          {lastTs === null ? <Unknown text="noch keine" /> : <>{formatTs(lastTs)}{age ? <span className="dg-kpi__max"> ({age})</span> : null}</>}
        </Kpi>
      </div>

      {fleet && (
        <SectionBox title="Home Assistant zum Internet" hint="Letzte Messrunde von Home Assistant aus. „k. A.“ heißt: nicht gemessen, nicht null.">
          <Fact name="Latenz">{formatMs(fleet.haLatencyMs)}</Fact>
          <Fact name="Paketverlust (24 Std.)">{formatPct(fleet.haLossPct)}</Fact>
          <Fact name="DNS-Antwortzeit">{formatMs(fleet.dnsMs)}</Fact>
        </SectionBox>
      )}

      <SectionBox title="Diagnosekette" hint="Von innen nach außen: Router, Gateway, WAN, Internet, DNS. Grau heißt unbekannt oder nicht zutreffend, nie gesund.">
        {points.length === 0
          ? <Unknown text="Noch keine Messpunkte vorhanden" />
          : <ul className="dg-points">{points.map(p => <PointCard key={`${p.kind}-${p.id}`} point={p} />)}</ul>}
      </SectionBox>
    </div>
  );
}
