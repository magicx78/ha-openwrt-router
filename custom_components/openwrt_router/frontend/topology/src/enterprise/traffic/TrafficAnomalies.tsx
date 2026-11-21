/**
 * TrafficAnomalies — "Anomalien": anomaly candidates (never incidents, never
 * an attack) with observed value, baseline and threshold, and which
 * detection families run or why one cannot.
 */

import React from 'react';
import type { AnomalyList, TrafficApi } from './trafficTypes';
import {
  FAMILY_LABEL, anomalyKindText, anomalyStateView, anomalyValueText, clientLabel, durationText, fmtShare, formatTs,
  reasonText, routerName, sourceStateView,
} from './trafficLogic.ts';
import { CoverageBadge, Fact, Loaded, SectionBox, ShownBadge, Unknown, usePolled } from './trafficUi';

export function AnomalyView({ list }: { list: AnomalyList }) {
  return (
    <>
      <div className="cfg-hint">Kandidaten sind Abweichungen vom gewohnten Verkehr, kein Angriff und kein Vorfall.</div>
      <SectionBox title="Kandidaten">
        {list.rows.length ? (
          <ul className="wifi-cards">
            {list.rows.map(a => (
              <li key={a.candidateId} className="wifi-card">
                <div className="wifi-card__head">
                  <span className="wifi-card__title">{anomalyKindText(a.kind)}</span>
                  <ShownBadge shown={anomalyStateView(a.state)} />
                  <CoverageBadge level={a.coverage} />
                </div>
                <Fact name="Wo">{routerName(a.routerId)}{a.clientRef ? ` · ${clientLabel(a.clientRef)}` : ''}</Fact>
                <Fact name="Beobachtet / üblich / Schwelle">
                  {anomalyValueText(a.kind, a.observed)} / {anomalyValueText(a.kind, a.baselineMedian)} / {anomalyValueText(a.kind, a.threshold)}
                </Fact>
                <Fact name="Fenster">{durationText(a.windowS)}</Fact>
                <Fact name="Sicherheit">{fmtShare(a.confidence)}</Fact>
                <Fact name="Seit / zuletzt">{formatTs(a.started)} / {formatTs(a.lastSeen)}</Fact>
                {a.suppressedReason && <div className="wifi-muted">Unterdrückt: {reasonText(a.suppressedReason)}</div>}
              </li>
            ))}
          </ul>
        ) : <Unknown text="— keine Kandidaten in den erfassten Daten" />}
      </SectionBox>
      <SectionBox title="Erkennung">
        <ul className="wifi-rows">
          {list.families.map(f => (
            <li key={f.family} className="wifi-row">
              <span className="wifi-row__title">{FAMILY_LABEL[f.family] ?? f.family}</span>
              <ShownBadge shown={sourceStateView(f.state)} />
              {f.reason && <span className="wifi-muted">{reasonText(f.reason)}</span>}
            </li>
          ))}
        </ul>
      </SectionBox>
    </>
  );
}

export function TrafficAnomalies({ api, rev }: { api: TrafficApi; rev: number }) {
  const res = usePolled(() => api.anomalies(), rev);
  return <Loaded res={res}>{l => <AnomalyView list={l} />}</Loaded>;
}
