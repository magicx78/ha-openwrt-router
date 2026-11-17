/**
 * StabilityCharts — small SVG charts of the client stability detail (B6).
 *
 * 1.43: real bars for disconnects and reconnects, the coarse 7 d / 30 d
 * strip and the AP/band strip with roam and flap marks.
 *
 * No chart library: each plot is an SVG stretched to the card width
 * (`preserveAspectRatio="none"`, strokes do not scale); axis labels are HTML
 * so the text stays sharp on phone and desktop.
 */

import React from 'react';
import type { StabilitySegment, StabilityStripCell } from '../types';

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
}

/** Online share per hour/day (bars); disconnects have their own chart (1.43). */
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
        <span>Online-Anteil</span>
        <span className="stab-chart__range">100 … 0 %</span>
      </div>
      <svg className="stab-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
        aria-label="Online-Anteil">
        {points.map(p => {
          const x = xOf(p.t, start, end);
          const h = p.share == null ? H : p.share * H;
          return (
            <rect key={p.t} x={x} y={H - h} width={w} height={h}
              className={p.share == null ? 'stab-bar stab-bar--none' : 'stab-bar'}>
              <title>{`${timeLabel(p.t, step >= 86400)}: ${p.share == null ? 'keine Messung' : `${Math.round(p.share * 100)} % online`}`}</title>
            </rect>
          );
        })}
      </svg>
      <Axis start={start} end={end} />
    </div>
  );
}

// ── 1.43: event bars, coarse strip, AP strip ───────────────────────────

export interface CountPoint {
  t: number;
  disconnects: number;
  /** null = not known at this resolution or no system log */
  reconnects: number | null;
}

/** Disconnects (red) and reconnects (amber) per bin as real bars. */
export function CountBars({
  points,
  start,
  end,
  step,
  note,
}: {
  points: CountPoint[];
  start: number;
  end: number;
  step: number;
  note?: string;
}) {
  const max = Math.max(0, ...points.map(p => Math.max(p.disconnects, p.reconnects ?? 0)));
  const half = Math.max(0.5, ((step / Math.max(1, end - start)) * W - 1) / 2);
  const long = step >= 86400;
  return (
    <div className="stab-chart">
      <div className="stab-chart__head">
        <span>Abbrüche und Reconnects je {long ? 'Tag' : step >= 3600 ? 'Stunde' : `${Math.round(step / 60)} min`}</span>
        <span className="stab-chart__range">{max ? `0 … ${max}` : ''}</span>
      </div>
      {max > 0 ? (
        <svg className="stab-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
          aria-label="Abbrüche und Reconnects">
          {points.map(p => {
            const x = xOf(p.t, start, end);
            const hd = (p.disconnects / max) * H;
            const hr = ((p.reconnects ?? 0) / max) * H;
            return (
              <g key={p.t}>
                <title>{`${timeLabel(p.t, long)}: ${p.disconnects} Abbrüche`
                  + `${p.reconnects != null ? `, ${p.reconnects} Reconnects` : ''}`}</title>
                {hd > 0 && <rect x={x} y={H - hd} width={half} height={hd} className="stab-cbar stab-cbar--dc" />}
                {hr > 0 && <rect x={x + half} y={H - hr} width={half} height={hr} className="stab-cbar stab-cbar--rc" />}
              </g>
            );
          })}
        </svg>
      ) : (
        <div className="stab-chart__empty">Keine Abbrüche oder Reconnects in diesem Zeitraum</div>
      )}
      <div className="stab-legend">
        <span className="stab-key stab-key--dc">Abbrüche</span>
        <span className="stab-key stab-key--rc">Reconnects</span>
        {note && <span>{note}</span>}
      </div>
      <Axis start={start} end={end} />
    </div>
  );
}

const SHARE_LABEL = { online: 'online', offline: 'offline', gap: 'Messlücke', unknown: 'unbekannt' } as const;

/** Coarse 7 d / 30 d strip: per hour or day the stacked state shares. */
export function StripBar({ cells, start, end }: { cells: StabilityStripCell[]; start: number; end: number }) {
  const long = end - start > 8 * 86400;
  const order = ['online', 'offline', 'gap', 'unknown'] as const;
  return (
    <div className="stab-chart">
      <svg className="stab-svg stab-svg--bar" viewBox={`0 0 ${W} 24`} preserveAspectRatio="none" role="img"
        aria-label="Grober Verlauf">
        <defs>
          <pattern id="stab-hatch-strip" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="6" height="6" className="stab-gap-bg" />
            <line x1="0" y1="0" x2="0" y2="6" className="stab-gap-line" />
          </pattern>
        </defs>
        {cells.map(c => {
          const x = xOf(c.t, start, end);
          const w = Math.max(0.5, xOf(c.t + c.span_s, start, end) - x);
          let y = 24;
          const shares = order.filter(k => c[k] > 0).map(k => `${Math.round(c[k] * 100)} % ${SHARE_LABEL[k]}`);
          const events = [
            c.disconnects ? `${c.disconnects} Abbrüche` : '',
            c.infra ? `${c.infra} durch Infrastruktur` : '',
            c.roams ? `${c.roams} AP-Wechsel` : '',
            c.flaps ? `${c.flaps} Flattern` : '',
          ].filter(Boolean);
          return (
            <g key={c.t}>
              <title>{`${timeLabel(c.t, long)}${long ? '' : ` ${timeLabel(c.t, true)}`}: ${shares.join(', ')}`
                + `${events.length ? ` · ${events.join(', ')}` : ''}`}</title>
              {order.map(k => {
                const h = c[k] * 24;
                if (h <= 0) return null;
                y -= h;
                return (
                  <rect key={k} x={x} y={y} width={w} height={h} className={`stab-seg stab-seg--${k}`}
                    fill={k === 'gap' ? 'url(#stab-hatch-strip)' : undefined} />
                );
              })}
            </g>
          );
        })}
      </svg>
      <div className="stab-markers" aria-hidden="true">
        {cells.filter(c => c.disconnects + c.infra > 0).map(c => (
          <span key={c.t} className="stab-marker stab-marker--static"
            style={{ left: `${(xOf(c.t + c.span_s / 2, start, end) / W) * 100}%` }}
            title={`${timeLabel(c.t, long)}: ${c.disconnects + c.infra} Abbrüche`}>▲</span>
        ))}
      </div>
      <Axis start={start} end={end} />
    </div>
  );
}

export interface ApSpan {
  from: number;
  to: number;
  key: string;
}

export interface ApMark {
  t: number;
  flap: boolean;
  label: string;
}

/** Chart 4: which AP and band the client used, with roam and flap marks. */
export function ApStrip({
  spans,
  marks,
  legend,
  start,
  end,
  note,
}: {
  spans: ApSpan[];
  marks: ApMark[];
  legend: Array<{ key: string; label: string; color: string }>;
  start: number;
  end: number;
  note: string;
}) {
  const color = new Map(legend.map(l => [l.key, l.color]));
  const label = new Map(legend.map(l => [l.key, l.label]));
  return (
    <div className="stab-chart">
      <div className="stab-chart__head">
        <span>AP-Wechsel / Roaming</span>
        <span className="stab-chart__range">{note}</span>
      </div>
      {spans.length > 0 ? (
        <svg className="stab-svg stab-svg--bar" viewBox={`0 0 ${W} 24`} preserveAspectRatio="none" role="img"
          aria-label="Access Point und Band">
          {spans.map(s => {
            const x = xOf(Math.max(s.from, start), start, end);
            const w = Math.max(0.5, xOf(Math.min(s.to, end), start, end) - x);
            return (
              <rect key={`${s.from}-${s.key}`} x={x} y={4} width={w} height={16} style={{ fill: color.get(s.key) }}>
                <title>{`${label.get(s.key) ?? s.key} · ${timeLabel(s.from, false)}–${timeLabel(s.to, false)}`}</title>
              </rect>
            );
          })}
        </svg>
      ) : (
        <div className="stab-chart__empty">Kein Access Point in diesem Zeitraum</div>
      )}
      {marks.length > 0 && (
        <div className="stab-markers">
          {marks.map((m, i) => (
            <span key={`${m.t}-${i}`} className={`stab-marker stab-marker--static stab-roam${m.flap ? ' stab-roam--flap' : ''}`}
              style={{ left: `${(xOf(m.t, start, end) / W) * 100}%` }} title={m.label}>◆</span>
          ))}
        </div>
      )}
      <div className="stab-legend">
        {legend.map(l => (
          <span key={l.key} className="stab-key stab-key--ap" style={{ '--stab-ap': l.color } as React.CSSProperties}>{l.label}</span>
        ))}
        <span className="stab-roam">◆ AP-Wechsel</span>
        <span className="stab-roam stab-roam--flap">◆ Flattern (zurück innerhalb 10 min)</span>
      </div>
      <Axis start={start} end={end} />
    </div>
  );
}
