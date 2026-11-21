/**
 * WifiRecommendations — what an administrator might check: text,
 * reason (Begründung), evidence (Nachweis) and level (Stufe), plus load per
 * AP and the client distribution. The module never changes the WLAN, so
 * there is no apply or switch button here.
 */

import React from 'react';
import type { Recommendations } from './wifiTypes';
import {
  DASH, OBSERVE_ONLY, bandLabel, fmtNum, fmtShare, loadView, reasonText, recommendationView, routerLabel,
} from './wifiLogic.ts';
import { Fact, Notice, SectionBox, ToneBadge, Unknown } from './wifiUi';
import { NotReadyNotice, OffNotice } from './WifiOverview';

export function WifiRecommendations({ data }: { data: Recommendations }) {
  if (data.status === 'off') return <OffNotice />;
  const recs = data.recommendations.map(recommendationView);
  const dist = data.distribution;
  return (
    <div className="cfg-stack">
      {data.status === 'not_ready' && <NotReadyNotice reasons={data.reasons.map(reasonText)} />}
      <Notice tone="info">{OBSERVE_ONLY}</Notice>
      <SectionBox title="Empfehlungen">
        {recs.length === 0 ? (
          <Unknown text={data.status === 'ready'
            ? 'Zurzeit keine Empfehlung. Das ist keine Aussage, dass das WLAN gesund ist: es fließen nur gemessene Werte ein.'
            : `${DASH} keine Auswertung`} />
        ) : (
          <ul className="wifi-cards">
            {recs.map((r, i) => (
              <li key={i} className="wifi-card">
                <div className="wifi-card__head">
                  <span className="wifi-card__title">{r.title}</span>
                  <ToneBadge tone={r.levelTone}>Stufe: {r.level}</ToneBadge>
                  <ToneBadge tone="muted">{r.confidence}</ToneBadge>
                </div>
                <Fact name="Betrifft">{r.target}</Fact>
                <Fact name="Begründung">{r.reason}</Fact>
                <Fact name="Erwartete Wirkung">{r.effect}</Fact>
                <Fact name="Nachweis">
                  {r.evidence.length === 0
                    ? <Unknown text={`${DASH} kein Nachweis geliefert`} />
                    : <span className="wifi-mono">{r.evidence.join(' · ')}</span>}
                </Fact>
                {r.risks.length > 0 && <Fact name="Risiken">{r.risks.join(' · ')}</Fact>}
                {r.requires.length > 0 && <Fact name="Würde helfen">{r.requires.join(' · ')}</Fact>}
              </li>
            ))}
          </ul>
        )}
      </SectionBox>
      <SectionBox title="Last je Access Point">
        {data.load.length === 0
          ? <Unknown text={`${DASH} keine Daten`} />
          : (
            <ul className="wifi-rows">
              {data.load.map(a => {
                const v = loadView(a.status);
                return (
                  <li key={a.routerId} className="wifi-row">
                    <span className="wifi-row__title">{routerLabel(a.routerId)}</span>
                    {a.status === null || a.status === 'unknown'
                      ? <Unknown text={v.label} />
                      : <span className={`wifi-tone-${v.tone}`}>{v.label}</span>}
                  </li>
                );
              })}
            </ul>
          )}
      </SectionBox>
      <SectionBox title="Verteilung der Clients">
        {dist === null ? <Unknown text={`${DASH} keine Daten`} /> : (
          <>
            <Fact name="Clients gesamt">{dist.total === null ? <Unknown text={`${DASH} keine Daten`} /> : fmtNum(dist.total)}</Fact>
            {dist.perBand.map(b => (
              <Fact key={b.band} name={bandLabel(b.band)}>{b.clients === null ? <Unknown text={`${DASH} keine Daten`} /> : fmtNum(b.clients)}</Fact>
            ))}
            <Fact name="Größter Anteil eines APs">{dist.largestShare === null ? <Unknown text={`${DASH} keine Daten`} /> : fmtShare(dist.largestShare)}</Fact>
          </>
        )}
      </SectionBox>
    </div>
  );
}
