/**
 * WifiTimeline — stored RF history per radio: window (1 h / 24 h / 7 d /
 * 30 d), series and an optional radio filter, drawn as a plain SVG line (no
 * chart library). A gap is a break in the line, never 0; a series without
 * any value says so.
 */

import React, { useState } from 'react';
import type { Timeline, TimelineRadio, WifiApi } from './wifiTypes';
import {
  DASH, SERIES_IDS, SERIES_INFO, WINDOWS, WINDOW_LABEL, fmtShare, fmtValue, formatTs, isRadioId, isRouterId,
  linePath, radioLabel, reasonText,
} from './wifiLogic.ts';
import { Loaded, Unknown, usePolled } from './wifiUi';
import { NotReadyNotice, OffNotice } from './WifiOverview';

const W = 300;
const H = 100;

function Chart({ radio, series }: { radio: TimelineRadio; series: string }) {
  const s = radio.series[series];
  const info = SERIES_INFO[series] ?? { label: series, kind: 'count' as const };
  const name = `${info.label} ${radioLabel(radio)}`;
  if (!s || s.points.length === 0) {
    return <li className="wifi-chart"><div className="wifi-chart__title">{radioLabel(radio)}</div><Unknown text={`${DASH} keine Daten in diesem Fenster`} /></li>;
  }
  const line = linePath(s.points, W, H);
  const first = s.points[0].ts;
  const last = s.points[s.points.length - 1].ts;
  return (
    <li className="wifi-chart">
      <div className="wifi-chart__title">
        {radioLabel(radio)}
        <span className="wifi-muted"> · Abdeckung {fmtShare(s.coverage)}</span>
      </div>
      {!line.known ? (
        <Unknown text={`${DASH} keine Daten in diesem Fenster`} />
      ) : (
        <>
          {/* max. above the line's top edge, min. below its bottom edge (the scale is min..max). */}
          <div className="wifi-chart__axis">
            <span>max. {line.max === null ? DASH : fmtValue(line.max, info.kind)}</span>
          </div>
          <svg className="wifi-chart__svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={name}>
            <rect x="0" y="0" width={W} height={H} className="wifi-chart__bg" />
            {line.segments.map((pts, i) => (
              <polyline key={i} points={pts} className="wifi-chart__line" fill="none" vectorEffect="non-scaling-stroke" />
            ))}
            {line.dots.map((d, i) => <circle key={`d${i}`} cx={d.x} cy={d.y} r="1.8" className="wifi-chart__dot" />)}
          </svg>
          <div className="wifi-chart__axis wifi-chart__axis--min">
            <span>min. {line.min === null ? DASH : fmtValue(line.min, info.kind)}</span>
          </div>
          <div className="wifi-chart__axis">
            <span>{formatTs(first)}</span>
            <span>{formatTs(last)}</span>
          </div>
        </>
      )}
    </li>
  );
}

export function WifiTimelineChart({ timeline, series }: { timeline: Timeline; series: string }) {
  if (timeline.status === 'off') return <OffNotice />;
  return (
    <div className="cfg-stack">
      {timeline.status === 'not_ready' && <NotReadyNotice reasons={timeline.reasons.map(reasonText)} />}
      {timeline.radios.length === 0
        ? <Unknown text={`${DASH} noch kein Verlauf gespeichert`} />
        : <ul className="wifi-charts">{timeline.radios.map(r => <Chart key={`${r.routerId}/${r.radioId}`} radio={r} series={series} />)}</ul>}
    </div>
  );
}

/** Radio filter value "router|radio"; anything that is not a valid id pair is "all". */
function splitFilter(v: string): { routerId: string; radioId: string } | null {
  const [routerId, radioId] = v.split('|');
  return isRouterId(routerId) && isRadioId(radioId) ? { routerId, radioId } : null;
}

export function WifiTimeline({ api, rev }: { api: WifiApi; rev: number }) {
  const [win, setWin] = useState('24h');
  const [series, setSeries] = useState('utilization');
  const [filter, setFilter] = useState('');
  const [known, setKnown] = useState<{ value: string; label: string }[]>([]);
  const ref = splitFilter(filter);
  const res = usePolled(async () => {
    const t = await api.timeline({ window: win, series, radioId: ref?.radioId ?? null, routerId: ref?.routerId ?? null });
    if (!ref) setKnown(t.radios.map(r => ({ value: `${r.routerId}|${r.radioId}`, label: radioLabel(r) })));
    return t;
  }, `${win}|${series}|${filter}|${rev}`);
  return (
    <div className="cfg-stack">
      <div className="wifi-filters">
        <label className="wifi-field">Fenster
          <select value={win} onChange={e => setWin(e.target.value)}>
            {WINDOWS.map(w => <option key={w} value={w}>{WINDOW_LABEL[w]}</option>)}
          </select>
        </label>
        <label className="wifi-field">Messwert
          <select value={series} onChange={e => setSeries(e.target.value)}>
            {SERIES_IDS.map(s => <option key={s} value={s}>{SERIES_INFO[s].label}</option>)}
          </select>
        </label>
        <label className="wifi-field">Radio
          <select value={filter} onChange={e => setFilter(e.target.value)}>
            <option value="">alle</option>
            {known.map(k => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
        </label>
      </div>
      <Loaded res={res}>{t => <WifiTimelineChart timeline={t} series={series} />}</Loaded>
    </div>
  );
}
