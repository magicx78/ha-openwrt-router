/**
 * TrafficTalkers — "Top Talkers": the busiest clients or infrastructure
 * points by volume in a window, by current rate, or by recurring peaks.
 * Every row says what it measured (area, coverage); a share is shown only
 * against a fully covered reference.
 */

import React, { useState } from 'react';
import type { TalkerList, TalkerQuery, TrafficApi } from './trafficTypes';
import {
  DASH, DIRECTIONS, DIRECTION_LABEL, SCOPE_LABEL, TALKER_KINDS, TALKER_KIND_LABEL, TALKER_LIMIT, TALKER_SCOPES,
  TALKER_WINDOWS, WINDOW_LABEL, clientLabel, fmtBytes, fmtPct, fmtRate, fmtShare, formatTs, pointLabel, reasonText,
  reasonsText, routerName, talkerValue,
} from './trafficLogic.ts';
import { CoverageBadge, Fact, Field, Loaded, Unknown, V, usePolled } from './trafficUi';

export function TalkerCards({ list }: { list: TalkerList }) {
  if (!list.rows.length) {
    return <Unknown text={`${DASH} ${reasonText(list.reason ?? 'no_data_for_window')}`} />;
  }
  return (
    <>
      {list.partial && list.partialReasons.length > 0 && (
        <div className="wifi-muted">Teilweise: {reasonsText(list.partialReasons)}</div>
      )}
      <ol className="wifi-cards">
        {list.rows.map(r => (
          <li key={r.pointId} className="wifi-card">
            <div className="wifi-card__head">
              <span className="wifi-card__title">{r.rank ?? DASH}. {r.clientRef ? clientLabel(r.clientRef) : pointLabel(r)}</span>
              <CoverageBadge level={r.coverage} reasons={r.coverageReasons} />
            </div>
            <Fact name={TALKER_KIND_LABEL[list.kind ?? 'window'] ?? 'Wert'}><V text={talkerValue(list.metric, r.value)} known={r.value !== null} /></Fact>
            <Fact name="Anteil"><V text={fmtPct(r.sharePct, 1)} known={r.sharePct !== null} reason={r.shareReason} /></Fact>
            {list.metric !== 'bytes' && <Fact name="Datenmenge"><V text={fmtBytes(r.observedBytes)} known={r.observedBytes !== null} /></Fact>}
            <Fact name="Spitze"><V text={fmtRate(r.peakBps)} known={r.peakBps !== null} /></Fact>
            <Fact name="Router">{routerName(r.routerId)}</Fact>
            <Fact name="VLAN">{r.vlanId === null ? <Unknown text={DASH} /> : r.vlanId}</Fact>
            <Fact name="Zuletzt aktiv">{r.lastActive === null ? <Unknown text={DASH} /> : formatTs(r.lastActive)}</Fact>
            <Fact name="Gemessen über">{r.measuringArea ? reasonText(r.measuringArea) : <Unknown text={DASH} />} · Zeitabdeckung {fmtShare(r.timeCoverage)}</Fact>
          </li>
        ))}
      </ol>
      {list.omitted.length > 0 && (
        <div className="wifi-muted">Nicht gereiht: {list.omitted.map(o => `${reasonText(o.code)} (${o.count})`).join(' · ')}</div>
      )}
    </>
  );
}

const opts = (values: readonly string[], labels: Record<string, string>) => values.map(v => ({ value: v, label: labels[v] ?? v }));

export function TrafficTalkers({ api, rev }: { api: TrafficApi; rev: number }) {
  const [q, setQ] = useState<TalkerQuery>({ kind: 'window', scope: 'client', window: '24h', direction: 'download', limit: TALKER_LIMIT });
  const set = (k: keyof TalkerQuery) => (v: string) => setQ(prev => ({ ...prev, [k]: v }));
  const res = usePolled(() => api.talkers(q), `${rev}|${q.kind}|${q.scope}|${q.window}|${q.direction}`);
  return (
    <>
      <div className="wifi-filters">
        <Field label="Rangliste" value={q.kind} options={opts(TALKER_KINDS, TALKER_KIND_LABEL)} onChange={set('kind')} />
        <Field label="Bereich" value={q.scope} options={opts(TALKER_SCOPES, SCOPE_LABEL)} onChange={set('scope')} />
        {q.kind !== 'current' && <Field label="Zeitraum" value={q.window} options={opts(TALKER_WINDOWS, WINDOW_LABEL)} onChange={set('window')} />}
        <Field label="Richtung" value={q.direction} options={opts(DIRECTIONS, DIRECTION_LABEL)} onChange={set('direction')} />
      </div>
      <Loaded res={res}>{list => <TalkerCards list={list} />}</Loaded>
    </>
  );
}
