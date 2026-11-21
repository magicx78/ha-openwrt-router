/**
 * TrafficHistory — "Verlauf": one measuring point over 1 h … 90 d from the
 * stored history (at most 500 buckets), drawn as a plain SVG line (no chart
 * library). Download and upload are separate lines, never added up; a gap
 * is a break in the line, never 0. Daily buckets are UTC days, labelled in
 * local time with a note that says so.
 */

import React, { useState } from 'react';
import type { PointList, PointRow, Series, TrafficApi } from './trafficTypes';
import {
  DASH, SERIES_WINDOWS, WINDOW_LABEL, bucketLabel, durationText, fmtBytes, fmtShare, historyPoints, isPointId,
  linePath, pointLabel, reasonText, reasonsText, routerName, seriesCharts, utcDayNote, windowFacts, type SeriesChart,
} from './trafficLogic.ts';
import { CoverageBadge, Fact, Field, Loaded, SectionBox, Unknown, V, usePolled } from './trafficUi';

const W = 300;
const H = 100;

export function SeriesLine({ chart, utcDays, up = false }: { chart: SeriesChart; utcDays: boolean; up?: boolean }) {
  const line = linePath(chart.points, W, H);
  if (!line.known || chart.points.length === 0) {
    return <li className="wifi-chart"><div className="wifi-chart__title">{chart.label}</div><Unknown text={`${DASH} keine Daten in diesem Zeitraum`} /></li>;
  }
  const first = chart.points[0].ts;
  const last = chart.points[chart.points.length - 1].ts;
  return (
    <li className="wifi-chart">
      <div className="wifi-chart__title">{chart.label} je Intervall <span className="wifi-muted">· höchster Wert {fmtBytes(line.max)}</span></div>
      <svg className="wifi-chart__svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
        aria-label={`${chart.label}: ${chart.known} von ${chart.points.length} Intervallen mit Wert`}>
        <rect className="wifi-chart__bg" x="0" y="0" width={W} height={H} />
        {line.segments.map((pts, i) => (
          <polyline key={i} className={`wifi-chart__line${up ? ' trf-chart__line--up' : ''}`} fill="none" points={pts} vectorEffect="non-scaling-stroke" />
        ))}
        {line.dots.map((d, i) => <circle key={i} className={`wifi-chart__dot${up ? ' trf-chart__dot--up' : ''}`} cx={d.x} cy={d.y} r="1.6" />)}
      </svg>
      <div className="wifi-chart__axis"><span>{bucketLabel(first, utcDays)}</span><span>{bucketLabel(last, utcDays)}</span></div>
    </li>
  );
}

export function SeriesView({ series: s }: { series: Series }) {
  if (s.state !== 'available' || !s.summary) {
    return <Unknown text={`${DASH} ${reasonText(s.reason ?? 'no_data')}`} />;
  }
  const charts = seriesCharts(s);
  const days = s.utcDays ? s.buckets.slice(-14).reverse() : [];
  const dl = s.summary.download;
  return (
    <>
      <div className="wifi-card__head">
        <CoverageBadge level={s.summary.coverage} />
        <span className="wifi-muted">Zeitabdeckung {fmtShare(s.summary.timeCoverage)} · Auflösung {durationText(s.resolutionS)}</span>
      </div>
      {s.windowReasons.length > 0 && <div className="wifi-muted">{reasonsText(s.windowReasons)}</div>}
      {s.utcDays && <div className="cfg-notice cfg-notice--info" role="note">{utcDayNote(s.buckets[0]?.ts)}</div>}
      <ul className="wifi-charts">
        {charts.map((c, i) => <SeriesLine key={c.label} chart={c} utcDays={s.utcDays} up={i === 1} />)}
      </ul>
      <div className="trf-grid">
        {windowFacts(s.summary).map(f => <Fact key={f.name} name={f.name}><V text={f.text} known={f.known} /></Fact>)}
      </div>
      {days.length > 0 && (
        <SectionBox title="Tageswerte (UTC-Tage)">
          <ul className="trf-days">
            {days.map(b => {
              const down = dl === 'tx' ? b.txBytes : dl === 'rx' ? b.rxBytes : null;
              const up = dl === 'tx' ? b.rxBytes : dl === 'rx' ? b.txBytes : null;
              return (
                <li key={b.ts} className="trf-day">
                  <span className="trf-day__ts">{bucketLabel(b.ts, true)}</span>
                  {dl ? (
                    <>
                      <span>Download <V text={fmtBytes(down)} known={down !== null} /></span>
                      <span>Upload <V text={fmtBytes(up)} known={up !== null} /></span>
                    </>
                  ) : (
                    <>
                      <span>rx <V text={fmtBytes(b.rxBytes)} known={b.rxBytes !== null} /></span>
                      <span>tx <V text={fmtBytes(b.txBytes)} known={b.txBytes !== null} /></span>
                    </>
                  )}
                  <span className="wifi-muted">Abdeckung {fmtShare(b.coverage)}</span>
                </li>
              );
            })}
          </ul>
        </SectionBox>
      )}
    </>
  );
}

function pointOption(p: PointRow): { value: string; label: string } {
  return { value: p.pointId, label: `${routerName(p.routerId)} · ${pointLabel(p)}` };
}

function SeriesSection({ api, rev, pointId, window }: { api: TrafficApi; rev: number; pointId: string; window: string }) {
  const res = usePolled(() => api.series({ pointId, window }), `${rev}|${pointId}|${window}`);
  return <Loaded res={res}>{s => <SeriesView series={s} />}</Loaded>;
}

export function HistoryPicker({ list, api, rev }: { list: PointList; api: TrafficApi; rev: number }) {
  const points = historyPoints(list);
  const [pointId, setPointId] = useState<string>(points[0]?.pointId ?? '');
  const [window, setWindow] = useState<string>('24h');
  if (!points.length) return <Unknown text="— noch kein Messpunkt mit Verlauf" />;
  const chosen = isPointId(pointId) && points.some(p => p.pointId === pointId) ? pointId : points[0].pointId;
  return (
    <>
      <div className="wifi-filters">
        <Field label="Messpunkt" value={chosen} options={points.map(pointOption)} onChange={setPointId} />
        <Field label="Zeitraum" value={window} options={SERIES_WINDOWS.map(w => ({ value: w, label: WINDOW_LABEL[w] ?? w }))} onChange={setWindow} />
      </div>
      {list.truncated && <div className="wifi-muted">Nur die ersten {list.points.length} Messpunkte werden angeboten.</div>}
      <SeriesSection api={api} rev={rev} pointId={chosen} window={window} />
    </>
  );
}

export function TrafficHistory({ api, rev }: { api: TrafficApi; rev: number }) {
  const res = usePolled(() => api.points(), rev);
  return <Loaded res={res}>{list => <HistoryPicker list={list} api={api} rev={rev} />}</Loaded>;
}
