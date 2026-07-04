/**
 * SpeedChart — Canvas-based line chart for the 1h CPU/RAM history.
 *
 * Props:
 *   history  — array of CpuHistoryPoint (sorted by ts ascending)
 *   width    — canvas width in px (default 320)
 *   height   — canvas height in px (default 120)
 */

import React, { useEffect, useRef } from 'react';
import type { CpuHistoryPoint } from '../types';

interface Props {
  history: CpuHistoryPoint[];
  width?: number;
  height?: number;
}

const COLOR_CPU   = '#4ade80'; // green — CPU
const COLOR_MEM   = '#60a5fa'; // blue  — RAM
const COLOR_GRID  = 'rgba(255,255,255,0.06)';
const COLOR_LABEL = 'rgba(255,255,255,0.45)';

function drawChart(canvas: HTMLCanvasElement, history: CpuHistoryPoint[]): void {
  const ctx = canvas.getContext('2d')!;
  if (!ctx) return;
  const W = canvas.width;
  const H = canvas.height;
  const PAD_L = 52;
  const PAD_R = 8;
  const PAD_T = 8;
  const PAD_B = 22;
  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;

  ctx.clearRect(0, 0, W, H);

  if (history.length < 2) {
    ctx.fillStyle = COLOR_LABEL;
    ctx.font = '11px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Noch keine Daten', W / 2, H / 2);
    return;
  }

  const pts = history;
  const now = Date.now() / 1000;
  const minTs = Math.min(...pts.map(p => p.ts));
  const maxTs = Math.max(...pts.map(p => p.ts), now);
  const tsRange = maxTs - minTs || 1;

  function xOf(ts: number): number {
    return PAD_L + ((ts - minTs) / tsRange) * plotW;
  }

  const maxVal = 100;
  const minVal = 0;

  function yOf(val: number): number {
    return PAD_T + plotH - ((val - minVal) / (maxVal - minVal)) * plotH;
  }

  // Grid lines (4 horizontal)
  ctx.strokeStyle = COLOR_GRID;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = PAD_T + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(PAD_L, y);
    ctx.lineTo(PAD_L + plotW, y);
    ctx.stroke();

    // Y-axis labels
    const val = maxVal - (maxVal / 4) * i;
    ctx.fillStyle = COLOR_LABEL;
    ctx.font = '9px system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`${Math.round(val)}%`, PAD_L - 4, y + 3);
  }

  // X-axis time labels (show hours back)
  const hours = Math.round(tsRange / 3600);
  ctx.fillStyle = COLOR_LABEL;
  ctx.font = '9px system-ui, sans-serif';
  ctx.textAlign = 'center';
  const labelCount = Math.max(1, Math.min(hours, 6));
  for (let i = 0; i <= labelCount; i++) {
    const ts = minTs + (tsRange / labelCount) * i;
    const x = xOf(ts);
    const d = new Date(ts * 1000);
    const label = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
    ctx.fillText(label, x, H - 4);
  }

  function drawLine(values: (number | null)[], color: string): void {
    const points = pts
      .map((p, i) => ({ x: xOf(p.ts), y: values[i] != null ? yOf(values[i]!) : null }))
      .filter(p => p.y !== null) as { x: number; y: number }[];

    if (points.length < 2) return;

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.lineTo(points[points.length - 1].x, PAD_T + plotH);
    ctx.lineTo(points[0].x, PAD_T + plotH);
    ctx.closePath();
    ctx.fillStyle = color + '28';
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.stroke();
  }

  drawLine(pts.map(p => p.cpu), COLOR_CPU);
  const hasMemData = pts.some(p => p.mem != null);
  if (hasMemData) {
    drawLine(pts.map(p => p.mem ?? null), COLOR_MEM);
  }

  // Border
  ctx.strokeStyle = COLOR_GRID;
  ctx.lineWidth = 1;
  ctx.strokeRect(PAD_L, PAD_T, plotW, plotH);
}

export function SpeedChart({ history, width = 320, height = 120 }: Props) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (ref.current) drawChart(ref.current, history);
  }, [history, width, height]);

  const legend = [
    { color: COLOR_CPU, label: 'CPU %' },
    { color: COLOR_MEM, label: 'RAM %' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <canvas
        ref={ref}
        width={width}
        height={height}
        style={{ display: 'block', borderRadius: 6, background: 'rgba(255,255,255,0.03)' }}
      />
      <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
        {legend.map(l => (
          <span key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--text-secondary, #8899aa)' }}>
            <span style={{ width: 12, height: 2, background: l.color, display: 'inline-block', borderRadius: 1 }} />
            {l.label}
          </span>
        ))}
      </div>
    </div>
  );
}
