/**
 * StabilityCharts — small SVG charts of the client stability detail (B6).
 *
 * No chart library: each plot is an SVG stretched to the card width
 * (`preserveAspectRatio="none"`, strokes do not scale); axis labels are HTML
 * so the text stays sharp on phone and desktop.
 */

import React from 'react';
import type { StabilitySegment } from '../types';

const W = 600;
const H = 100;

function timeLabel(ts: number, long: boolean): string {
  return new Date(ts * 1000).toLocaleString('de-DE', long
    ? { day: '2-digit', month: '2-digit' }
    : { hour: '2-digit', minute: '2-digit' });
}

function Axis({ start, end }: { start: number; end: number }) {
  const long = end - start > 2 * 86400;
  return (
    <div className="stab-axis">
      <span>{timeLabel(start, long)}</span>
      <span>{timeLabel(start + (end - start) / 2, long)}</span>
      <span>{timeLabel(end, long)}</span>
    </div>
  );
}

function xOf(t: number, start: number, end: number): number {
  return ((t - start) / Math.max(1, end - start)) * W;
}

export interface Marker {
  t: number;
  label: string;
  incidentId: string | null;
}

/** Online (green), offline (red), gap (hatched), unknown (faint) segments. */
export function TimelineBar({
  segments,
  start,
  end,
  markers,
  onOpenIncident,
}: {
  segments: StabilitySegment[];
  start: number;
  end: number;
  markers: Marker[];
  onOpenIncident?: (id: string) => void;
}) {
  return (
    <div className="stab-chart">
      <svg className="stab-svg stab-svg--bar" viewBox={`0 0 ${W} 24`} preserveAspectRatio="none" role="img"
        aria-label="Verbindungszeitleiste">
        <defs>
          <pattern id="stab-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="6" height="6" className="stab-gap-bg" />
            <line x1="0" y1="0" x2="0" y2="6" className="stab-gap-line" />
          </pattern>
        </defs>
        {segments.map(s => {
          const x = xOf(Math.max(s.start, start), start, end);
          const w = Math.max(0.5, xOf(Math.min(s.end, end), start, end) - x);
          return (
            <rect key={`${s.start}-${s.state}`} x={x} y={4} width={w} height={16}
              className={`stab-seg stab-seg--${s.state}`}
              fill={s.state === 'gap' ? 'url(#stab-hatch)' : undefined}>
              <title>{`${s.state} · ${timeLabel(s.start, false)}–${timeLabel(s.end, false)}`}</title>
            </rect>
          );
        })}
      </svg>
      {markers.length > 0 && (
        <div className="stab-markers">
          {markers.map((m, i) => (
            <button key={`${m.t}-${i}`} type="button" className="stab-marker"
              style={{ left: `${(xOf(m.t, start, end) / W) * 100}%` }}
              title={m.label} disabled={!m.incidentId || !onOpenIncident}
              onClick={() => m.incidentId && onOpenIncident?.(m.incidentId)}>
              ▲
            </button>
          ))}
        </div>
      )}
      <Axis start={start} end={end} />
    </div>
  );
}

export interface LinePoint {
  t: number;
  y: number | null;
  lo?: number | null;
  hi?: number | null;
}

/** Line with an optional min/max band; gaps (null) break the line. */
export function LineChart({
  points,
  start,
  end,
  min,
  max,
  unit,
  label,
}: {
  points: LinePoint[];
  start: number;
  end: number;
  min: number;
  max: number;
  unit: string;
  label: string;
}) {
  const yOf = (v: number) => H - ((Math.min(max, Math.max(min, v)) - min) / (max - min)) * H;
  const runs: LinePoint[][] = [];
  let run: LinePoint[] = [];
  for (const p of points) {
    if (p.y == null) {
      if (run.length) runs.push(run);
      run = [];
    } else {
      run.push(p);
    }
  }
  if (run.length) runs.push(run);
  const path = (pts: LinePoint[], key: 'y' | 'lo' | 'hi') =>
    pts.map((p, i) => `${i ? 'L' : 'M'}${xOf(p.t, start, end).toFixed(1)},${yOf(p[key] ?? p.y!).toFixed(1)}`).join('');
  const band = (pts: LinePoint[]) =>
    `${path(pts, 'hi')}${pts.slice().reverse().map(p => `L${xOf(p.t, start, end).toFixed(1)},${yOf(p.lo ?? p.y!).toFixed(1)}`).join('')}Z`;
  const hasData = runs.length > 0;
  return (
    <div className="stab-chart">
      <div className="stab-chart__head">
        <span>{label}</span>
        <span className="stab-chart__range">{max} … {min} {unit}</span>
      </div>
      {hasData ? (
        <svg className="stab-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={label}>
          {[0.25, 0.5, 0.75].map(f => <line key={f} x1={0} x2={W} y1={H * f} y2={H * f} className="stab-grid" />)}
          {runs.map((r, i) => (
            <g key={i}>
              {r.some(p => p.lo != null && p.hi != null) && <path d={band(r)} className="stab-band" />}
              {r.length === 1
                ? <circle cx={xOf(r[0].t, start, end)} cy={yOf(r[0].y!)} r={2.5} className="stab-dot" />
                : <path d={path(r, 'y')} className="stab-line" />}
            </g>
          ))}
        </svg>
      ) : (
        <div className="stab-chart__empty">Keine Werte in diesem Zeitraum</div>
      )}
      <Axis start={start} end={end} />
    </div>
  );
}

export interface BarPoint {
  t: number;
  share: number | null;
  problems: number;
}

/** Online share per hour/day (bars) with problem disconnects as red ticks. */
export function AvailabilityBars({
  points,
  start,
  end,
  step,
}: {
  points: BarPoint[];
  start: number;
  end: number;
  step: number;
}) {
  const w = Math.max(1, (step / Math.max(1, end - start)) * W - 1);
  return (
    <div className="stab-chart">
      <div className="stab-chart__head">
        <span>Online-Anteil und Abbrüche</span>
        <span className="stab-chart__range">100 … 0 %</span>
      </div>
      <svg className="stab-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
        aria-label="Online-Anteil und Abbrüche">
        {points.map(p => {
          const x = xOf(p.t, start, end);
          const h = p.share == null ? H : p.share * H;
          return (
            <g key={p.t}>
              <rect x={x} y={H - h} width={w} height={h}
                className={p.share == null ? 'stab-bar stab-bar--none' : 'stab-bar'}>
                <title>{`${timeLabel(p.t, step >= 86400)}: ${p.share == null ? 'keine Messung' : `${Math.round(p.share * 100)} % online`}${p.problems ? ` · ${p.problems} Abbrüche` : ''}`}</title>
              </rect>
              {p.problems > 0 && <rect x={x} y={0} width={w} height={6} className="stab-tick" />}
            </g>
          );
        })}
      </svg>
      <Axis start={start} end={end} />
    </div>
  );
}
