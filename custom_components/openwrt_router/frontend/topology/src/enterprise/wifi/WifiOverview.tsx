/**
 * WifiOverview — health score of the network, module state (off /
 * not_ready / ready) with its reasons, monitoring coverage, counts, and one
 * line per router. Off explains how to switch RF on; not_ready never reads
 * as an all-clear; a score is shown only while ready.
 */

import React from 'react';
import type { Overview, RouterRow } from './wifiTypes';
import {
  DASH, OFF_HINT, fmtNum, fmtShare, formatTs, healthView, overviewCounts, reasonText, routerLabel, statusView,
} from './wifiLogic.ts';
import { Fact, Notice, SectionBox, ToneBadge, Unknown } from './wifiUi';

const READ_LABEL: Record<string, string> = {
  get_status: 'Kanalauslastung (hostapd)',
  assoclist: 'Client-Zähler (assoclist)',
  freqlist: 'Kanalliste',
  txpowerlist: 'Sendeleistungsliste',
  survey: 'Survey',
};

function Kpi({ name, tone, sub, children }: { name: string; tone?: string; sub?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="wifi-kpi">
      <span className="wifi-kpi__name">{name}</span>
      <span className={`wifi-kpi__value${tone ? ` wifi-tone-${tone}` : ''}`}>{children}</span>
      {sub && <span className="wifi-kpi__sub">{sub}</span>}
    </div>
  );
}

export function OffNotice() {
  return (
    <Notice tone="info">
      <strong>WLAN-Funkanalyse ist aus.</strong> {OFF_HINT}
    </Notice>
  );
}

export function NotReadyNotice({ reasons }: { reasons: string[] }) {
  return (
    <Notice tone="warn">
      <strong>Nicht bereit.</strong>{' '}
      {reasons.length > 0 ? `Grund: ${reasons.join(' · ')}.` : 'Der Grund ist nicht bekannt.'}{' '}
      Angaben können fehlen; das ist keine Entwarnung.
    </Notice>
  );
}

function RouterLine({ row, status }: { row: RouterRow; status: Overview['status'] }) {
  const health = healthView(row.health, status);
  return (
    <li className="wifi-card">
      <div className="wifi-card__head">
        <span className="wifi-card__title">{routerLabel(row.routerId)}</span>
        <ToneBadge tone={row.status === 'ok' ? 'info' : row.status === null ? 'muted' : 'warn'}>
          {row.status ? reasonText(row.status) : `${DASH} unbekannt`}
        </ToneBadge>
        {row.enabled === false && <ToneBadge tone="muted">aus</ToneBadge>}
      </div>
      {row.reason && <Fact name="Grund">{reasonText(row.reason)}</Fact>}
      <Fact name="Health Score">
        {health.value === null ? <Unknown text={health.text} /> : <span className={`wifi-tone-${health.tone}`}>{health.text}</span>}
      </Fact>
      <Fact name="Radios">{row.radios === null ? <Unknown text={`${DASH} keine Daten`} /> : fmtNum(row.radios)}</Fact>
      <Fact name="Zusätzliche Abfragen">
        {row.reads.length > 0 ? row.reads.map(r => READ_LABEL[r] ?? r).join(', ') : 'keine (nur die normale Abfrage)'}
        {row.everyNPolls !== null && row.reads.length > 0 ? `, alle ${fmtNum(row.everyNPolls)} Abfragen` : ''}
      </Fact>
      <Fact name="Letzte Abfrage">{row.lastPollAt === null ? <Unknown text={`${DASH} noch keine`} /> : formatTs(row.lastPollAt)}</Fact>
    </li>
  );
}

export function WifiOverview({ overview }: { overview: Overview }) {
  const st = statusView(overview.status, overview.reasons);
  if (overview.status === 'off') return <OffNotice />;
  const health = healthView(overview.networkHealth, overview.status);
  return (
    <div className="cfg-stack">
      {overview.status === 'not_ready' && <NotReadyNotice reasons={st.reasons} />}
      {overview.status === null && (
        <Notice tone="warn">Der Zustand der WLAN-Funkanalyse ist unbekannt. Angaben können fehlen; das ist keine Entwarnung.</Notice>
      )}
      <div className="wifi-kpis">
        <Kpi name="Health Score" tone={health.value === null ? undefined : health.tone} sub={health.note}>
          {health.value === null ? <Unknown text={health.text} /> : health.text}
        </Kpi>
        <Kpi name="Zustand" sub={st.reasons.length > 0 ? `Grund: ${st.reasons.join(' · ')}` : undefined}>
          {st.label}
        </Kpi>
        <Kpi name="Überwachungsabdeckung" sub="Anteil der Messwerte, die die Radios wirklich liefern">
          {overview.monitoringCoverage === null ? <Unknown text={`${DASH} keine Daten`} /> : fmtShare(overview.monitoringCoverage)}
        </Kpi>
      </div>
      <SectionBox title="Zahlen">
        {overviewCounts(overview).map(c => (
          <Fact key={c.name} name={c.name}>{c.known ? c.text : <Unknown text={c.text} />}</Fact>
        ))}
      </SectionBox>
      <SectionBox title="Router" hint="Je Router der Zustand der Funkanalyse und welche zusätzlichen Abfragen eingeschaltet sind.">
        {overview.routers.length === 0
          ? <Unknown text={`${DASH} noch kein Router ausgewertet`} />
          : <ul className="wifi-cards">{overview.routers.map(r => <RouterLine key={r.routerId} row={r} status={overview.status} />)}</ul>}
      </SectionBox>
    </div>
  );
}
