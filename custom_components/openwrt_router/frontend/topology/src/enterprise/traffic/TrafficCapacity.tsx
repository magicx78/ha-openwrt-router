/**
 * TrafficCapacity — "Kapazität": average, peak and P95 per direction
 * against the link speed, a cautious trend (an estimate, never a forecast)
 * and the possible bottlenecks with their measurements, possible causes and
 * what to check. Nothing here changes a router.
 */

import React from 'react';
import type { CapacityList, CapacityRow, Finding, Recommendations, TrafficApi } from './trafficTypes';
import {
  CAUSE_TEXT, DASH, INDICATOR_TEXT, RECOMMENDATION_TEXT, VERDICT_TEXT, assessmentView, capacityStateView, codeText,
  durationText, fmtCount, fmtNum, fmtPct, fmtRate, fmtShare, pointLabel, reasonText, reasonsText, routerName, trendText, unitSuffix,
} from './trafficLogic.ts';
import { Fact, Loaded, SectionBox, ShownBadge, SourceList, Unknown, V, usePolled } from './trafficUi';

const DIR_NAME: Record<string, string> = { download: 'Download', upload: 'Upload' };

function CapacityCard({ r }: { r: CapacityRow }) {
  return (
    <li className="wifi-card">
      <div className="wifi-card__head">
        <span className="wifi-card__title">{routerName(r.routerId)} · {pointLabel(r)}</span>
        <ShownBadge shown={capacityStateView(r.state)} />
      </div>
      <Fact name="Link">{r.linkMbps === null ? <Unknown text={`${DASH} ${reasonText('link_speed_unknown')}`} /> : `${fmtCount(r.linkMbps)} Mbit/s${r.duplex ? ` · ${r.duplex === 'full' ? 'Vollduplex' : r.duplex === 'half' ? 'Halbduplex' : r.duplex}` : ''}`}</Fact>
      {r.directions.map(d => {
        const name = (d.meaning && DIR_NAME[d.meaning]) || (d.counter === 'rx' ? 'Empfangen (rx)' : 'Gesendet (tx)');
        const why = (f: string) => d.unavailable.find(u => u.field === f)?.reason ?? null;
        return (
          <Fact key={d.counter} name={name}>
            Ø <V text={fmtRate(d.avgBps)} known={d.avgBps !== null} reason={why('avg_bps')} />
            {' · '}Spitze <V text={fmtRate(d.peakBps)} known={d.peakBps !== null} />
            {' · '}P95 <V text={fmtPct(d.p95Pct, 1)} known={d.p95Pct !== null} reason={why('p95_pct')} />
          </Fact>
        );
      })}
      {r.sharedP95Pct !== null && <Fact name="P95 geteilt (Halbduplex)">{fmtPct(r.sharedP95Pct, 1)}</Fact>}
      <Fact name="Tage nahe der Kapazität">{fmtCount(r.nearCapacityDays)}</Fact>
      <Fact name="Trend (Schätzung)">{trendText(r.trend)}</Fact>
      <Fact name="Zeitraum">{durationText(r.windowS)} · Zeitabdeckung {fmtShare(r.timeCoverage)}{r.p95Estimated ? ' · P95 geschätzt' : ''}</Fact>
      {r.reasons.length > 0 && <div className="wifi-muted">{reasonsText(r.reasons)}</div>}
    </li>
  );
}

export function CapacityCards({ list }: { list: CapacityList }) {
  if (!list.rows.length) return <Unknown text="— kein Messpunkt mit Kapazitätsdaten" />;
  return <ul className="wifi-cards">{list.rows.map(r => <CapacityCard key={r.pointId} r={r} />)}</ul>;
}

function FindingCard({ f }: { f: Finding }) {
  const a = assessmentView(f.assessment);
  return (
    <li className="wifi-card">
      <div className="wifi-card__head">
        <span className="wifi-card__title">{a.label}</span>
        <ShownBadge shown={{ label: `Sicherheit ${fmtShare(f.confidence)}`, tone: 'info' }} />
      </div>
      <Fact name="Wo">{routerName(f.routerId)}{f.scope ? ` · ${pointLabel({ scope: f.scope, device: null, vlanId: null })}` : ''}</Fact>
      <Fact name="Zeitraum">{durationText(f.windowS)}</Fact>
      {f.observations.length > 0 && (
        <ul className="wifi-rows">
          {f.observations.map((o, i) => (
            <li key={`${o.indicator}-${i}`} className="wifi-row">
              <span className="wifi-row__title">{codeText(INDICATOR_TEXT, o.indicator)}</span>
              <span>{o.value === null ? <Unknown text={DASH} /> : fmtNum(o.value, 1)}{unitSuffix(o.unit)}</span>
              {o.threshold !== null && <span className="wifi-muted">Schwelle {fmtNum(o.threshold, 1)}{unitSuffix(o.unit)}</span>}
              {o.elevated && <ShownBadge shown={{ label: 'erhöht', tone: 'warn' }} />}
            </li>
          ))}
        </ul>
      )}
      {f.possibleCauses.length > 0 && <Fact name="Mögliche Ursachen">{f.possibleCauses.map(c => codeText(CAUSE_TEXT, c)).join(' · ')}</Fact>}
      {f.recommendations.length > 0
        ? <Fact name="Prüfen">{f.recommendations.map(c => codeText(RECOMMENDATION_TEXT, c)).join(' · ')}</Fact>
        : f.recommendationWithheld && <Fact name="Prüfen"><Unknown text={`${DASH} ${reasonText(f.recommendationWithheld)}`} /></Fact>}
      {f.unmeasured.length > 0 && <div className="wifi-muted">Nicht gemessen: {f.unmeasured.map(u => reasonText(u.reason || u.field)).join(' · ')}</div>}
    </li>
  );
}

export function RecommendationsView({ data }: { data: Recommendations }) {
  const verdict = (data.verdict && VERDICT_TEXT[data.verdict]) || { label: 'unbekannt', tone: 'muted' as const };
  return (
    <>
      <div className="wifi-card__head">
        <ShownBadge shown={verdict} />
        <span className="wifi-muted">{fmtCount(data.pointsEvaluated)} Messpunkte bewertet, {fmtCount(data.pointsInsufficient)} mit zu wenigen Daten</span>
      </div>
      <div className="cfg-hint">Mögliche Engpässe, keine bestätigten. Hohe Bandbreite allein ist kein Engpass. Das Modul ändert nichts am Router.</div>
      {data.findings.length > 0 && <ul className="wifi-cards">{data.findings.map(f => <FindingCard key={f.findingId} f={f} />)}</ul>}
      <SectionBox title="Quellen der Bewertung"><SourceList sources={data.sources} /></SectionBox>
    </>
  );
}

export function TrafficCapacity({ api, rev }: { api: TrafficApi; rev: number }) {
  const cap = usePolled(() => api.capacity(), rev);
  const rec = usePolled(() => api.recommendations(), rev);
  return (
    <>
      <SectionBox title="Auslastung und Reserve" hint="Letzte 7 Tage; P95 aus Stunden- oder Tageswerten. Ein Trend ist eine vorsichtige Schätzung, keine Vorhersage.">
        <Loaded res={cap}>{l => <CapacityCards list={l} />}</Loaded>
      </SectionBox>
      <SectionBox title="Mögliche Engpässe und Empfehlungen">
        <Loaded res={rec}>{d => <RecommendationsView data={d} />}</Loaded>
      </SectionBox>
    </>
  );
}
