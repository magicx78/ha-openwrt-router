/**
 * stabilityCharts.ts — chart data of the client stability detail (1.43).
 *
 * Turns the detail response into the points of chart 3 (disconnects and
 * reconnects) and chart 4 (AP and band per time, roam and flap marks).
 * 1 h uses the raw samples and the stored transitions (exact times), 24 h
 * the hour series and the transitions, 7 d / 30 d only the buckets (marks
 * per hour or day: exact times are kept for 24 h).
 */

import type { ApMark, ApSpan, CountPoint } from '../components/StabilityCharts';
import type { ClientStabilityDetail, StabilityWindow } from '../types';
import { formatTs } from './intel';
import { FLAP_WINDOW_S, apColor, bandLabel } from './stability';

/** Bin of chart 3 in the 1 h window. */
export const BIN_1H_S = 300;
/** A raw sample stands for at most this long (poll every 60 s). */
const SAMPLE_HOLD_S = 180;

function apKey(ap: string, band: string | null | undefined): string {
  return `${ap}|${band ?? ''}`;
}

function merge(spans: ApSpan[]): ApSpan[] {
  const out: ApSpan[] = [];
  for (const s of spans) {
    const last = out[out.length - 1];
    if (last && last.key === s.key && s.from <= last.to + 1) {
      out[out.length - 1] = { ...last, to: Math.max(last.to, s.to) };
    } else {
      out.push(s);
    }
  }
  return out;
}

/** AP+band per time: raw samples (1 h) or the main AP of each bucket. */
export function apSpans(d: ClientStabilityDetail, win: StabilityWindow, step: number): ApSpan[] {
  if (win === '1h') {
    const ring = d.rssi;
    const spans: ApSpan[] = [];
    ring.forEach((p, i) => {
      if (!p.router || p.state === 'offline') return;
      const next = i + 1 < ring.length ? ring[i + 1].t : d.now;
      spans.push({ from: p.t, to: Math.min(next, p.t + SAMPLE_HOLD_S), key: apKey(p.router, p.band) });
    });
    return merge(spans);
  }
  return merge(
    d.series
      .filter(p => p.ap)
      .map(p => ({ from: p.t, to: Math.min(p.t + step, d.now), key: apKey(p.ap!, p.band) })),
  );
}

/** Legend entries of the AP strip in order of first use. */
export function apLegend(
  spans: ApSpan[],
  d: ClientStabilityDetail,
  nameOf: (id: string) => string,
): Array<{ key: string; label: string; color: string }> {
  const keys = [...new Set(spans.map(s => s.key))];
  return keys.map((key, i) => {
    const [ap, band] = key.split('|');
    const name = d.routers?.[ap] ?? nameOf(ap);
    return { key, label: band ? `${name} · ${bandLabel(band)}` : name, color: apColor(i) };
  });
}

/** Roam marks: each AP change with its time (1 h, 24 h) or per bucket. */
export function roamMarks(
  d: ClientStabilityDetail,
  win: StabilityWindow,
  step: number,
  nameOf: (id: string) => string,
): ApMark[] {
  if (win === '7d' || win === '30d') {
    return d.series
      .filter(p => (p.roams ?? 0) + (p.flaps ?? 0) > 0)
      .map(p => ({
        t: p.t + step / 2,
        flap: (p.flaps ?? 0) > 0,
        label: `${formatTs(p.t)}: ${p.roams ?? 0} AP-Wechsel, ${p.flaps ?? 0} Flattern`,
      }));
  }
  const name = (id: string | null | undefined) => (id ? d.routers?.[id] ?? nameOf(id) : '?');
  const marks: ApMark[] = [];
  let current: string | null = null;
  let last: { ts: number; from: string | null; to: string } | null = null;
  for (const tr of d.transitions) {
    const router = tr.router ?? null;
    if (tr.kind !== 'move' || !router) {
      if (router && (tr.kind === 'start' || tr.kind === 'resume')) current = router;
      continue;
    }
    // ping-pong like the engine: back to the AP left within 10 min
    const flap = last != null && tr.ts - last.ts <= FLAP_WINDOW_S
      && router === last.from && current === last.to;
    marks.push({
      t: tr.ts,
      flap,
      label: `${formatTs(tr.ts)} · ${current ? `${name(current)} → ` : 'zu '}${name(router)}${flap ? ' (Flattern)' : ''}`,
    });
    last = { ts: tr.ts, from: current, to: router };
    current = router;
  }
  return marks;
}

/** Chart 3: disconnects (with infrastructure) and reconnects per bin. */
export function countPoints(
  d: ClientStabilityDetail,
  win: StabilityWindow,
  start: number,
): CountPoint[] {
  if (win === '1h') {
    const bins = Math.ceil((d.now - start) / BIN_1H_S);
    const out: CountPoint[] = Array.from({ length: bins }, (_, i) => ({
      t: start + i * BIN_1H_S,
      disconnects: 0,
      reconnects: null,
    }));
    for (const tr of d.transitions) {
      if (tr.kind !== 'end' || tr.class === 'leave') continue;
      const i = Math.floor((tr.ts - start) / BIN_1H_S);
      if (i >= 0 && i < bins) out[i] = { ...out[i], disconnects: out[i].disconnects + 1 };
    }
    return out;
  }
  const log = Boolean(d.stats.log_coverage);
  return d.series.map(p => ({
    t: p.t,
    disconnects: p.disconnects + p.infra,
    reconnects: log ? p.reconnects : null,
  }));
}
