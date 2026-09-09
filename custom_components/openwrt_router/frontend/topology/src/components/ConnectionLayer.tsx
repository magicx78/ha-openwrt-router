/**
 * ConnectionLayer — renders topology edges as SVG path elements.
 *
 * Renders directly inside an <svg> parent (no wrapper svg here).
 * The parent SVG is owned by TopologyView and sized via the zoom wrapper.
 */

import React from 'react';
import { EdgeLayout } from '../types';

function speedLabel(mbps: number | null | undefined): string {
  if (!mbps) return '';
  if (mbps >= 2500) return '2.5G';
  if (mbps >= 1000) return '1G';
  if (mbps >= 100)  return '100M';
  return '10M';
}

// Midpoint of cubic Bézier at t=0.5
function cubicMid(path: string): { x: number; y: number } | null {
  const m = path.match(/M\s*([\d.]+)\s+([\d.]+)\s+C\s*([\d.]+)\s+([\d.]+),\s*([\d.]+)\s+([\d.]+),\s*([\d.]+)\s+([\d.]+)/);
  if (!m) return null;
  const [, x0, y0, cx1, cy1, cx2, cy2, x1, y1] = m.map(Number);
  const t = 0.5;
  const mt = 1 - t;
  return {
    x: mt*mt*mt*x0 + 3*mt*mt*t*cx1 + 3*mt*t*t*cx2 + t*t*t*x1,
    y: mt*mt*mt*y0 + 3*mt*mt*t*cy1 + 3*mt*t*t*cy2 + t*t*t*y1,
  };
}

// Start / end endpoints of any path (works for cubic and quadratic).
function pathEnds(path: string): { start: { x: number; y: number }; end: { x: number; y: number } } | null {
  const nums = path.match(/-?[\d.]+/g)?.map(Number);
  if (!nums || nums.length < 4) return null;
  return {
    start: { x: nums[0], y: nums[1] },
    end:   { x: nums[nums.length - 2], y: nums[nums.length - 1] },
  };
}

// Linear interpolation between two points.
function lerp(a: { x: number; y: number }, b: { x: number; y: number }, t: number) {
  return { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
}

/** A small port badge (rect + label) drawn at an SVG point. */
function PortBadge({ x, y, text, side }: { x: number; y: number; text: string; side: 'from' | 'to' }) {
  const w = Math.max(30, text.length * 7 + 8);
  return (
    <>
      <rect x={x - w / 2} y={y - 7} width={w} height={14} rx={3} className="edge-label-bg edge-port-badge-bg" />
      <text x={x} y={y + 3} className={`edge-label edge-port-badge edge-port-badge--${side}`}>{text}</text>
    </>
  );
}

interface Props {
  edges: EdgeLayout[];
  highlightedEdges: Set<string>;
  dimmedEdges: Set<string>;
  onEdgeHover?: (edgeId: string | null, x: number, y: number) => void;
  vlanMode?: boolean;
}

export function ConnectionLayer({ edges, highlightedEdges, dimmedEdges, onEdgeHover, vlanMode }: Props) {
  return (
    <>
      {edges.map((edge, idx) => (
        <EdgeGroup
          key={edge.id}
          edge={edge}
          highlighted={highlightedEdges.has(edge.id)}
          dimmed={dimmedEdges.has(edge.id)}
          animIndex={idx}
          onEdgeHover={onEdgeHover}
          vlanMode={vlanMode}
        />
      ))}
    </>
  );
}

// ── Single edge ───────────────────────────────────────────────────────────

interface EdgeGroupProps {
  edge: EdgeLayout;
  highlighted: boolean;
  dimmed: boolean;
  animIndex: number;
  onEdgeHover?: (edgeId: string | null, x: number, y: number) => void;
  vlanMode?: boolean;
}

function EdgeGroup({ edge, highlighted, dimmed, animIndex, onEdgeHover, vlanMode }: EdgeGroupProps) {
  const cls = [
    'edge-group',
    `edge-group--${edge.kind}`,
    dimmed && !highlighted ? 'edge-dimmed' : '',
    highlighted            ? 'edge-highlighted' : '',
    edge.status === 'warning' ? 'edge-warning' : '',
  ]
    .filter(Boolean)
    .join(' ');

  // Staggered enter: each edge delays slightly after the previous
  const style = { '--edge-delay': `${0.08 + animIndex * 0.06}s` } as React.CSSProperties;
  const vlanAttr = vlanMode && edge.vlanId != null ? edge.vlanId : undefined;

  // Transparent wide hit area — pointer-events: all overrides the parent SVG's
  // pointer-events: none so only these explicit hit paths receive mouse events.
  const hitPath = onEdgeHover ? (
    <path
      d={edge.path}
      fill="none"
      stroke="rgba(0,0,0,0)"
      strokeWidth={18}
      style={{ pointerEvents: 'all', cursor: 'crosshair' }}
      onMouseMove={(e) => onEdgeHover(edge.id, e.clientX, e.clientY)}
      onMouseLeave={() => onEdgeHover(null, 0, 0)}
    />
  ) : null;

  if (edge.kind === 'internet') {
    return (
      <g className={cls} style={style}>
        <path className="edge-internet-bg"   d={edge.path} />
        <path className="edge-internet-flow" d={edge.path} />
        {hitPath}
      </g>
    );
  }

  if (edge.kind === 'gateway-wired') {
    const mid = edge.gatewayPort ? cubicMid(edge.path) : null;
    const vlanText = edge.vlanTags && edge.vlanTags.length > 0
      ? edge.vlanTags.length > 1
        ? `T:${edge.vlanTags.join(',')}`     // Trunk
        : `V${edge.vlanTags[0]}`             // Untagged single VLAN
      : null;
    const gwLabel = edge.gatewayPort
      ? [
          edge.gatewayPort.toUpperCase(),
          vlanText,
          edge.gatewayPortSpeed ? speedLabel(edge.gatewayPortSpeed) : null,
        ].filter(Boolean).join(' · ')
      : null;
    const apLabel = edge.apPort ? edge.apPort.toUpperCase() : null;
    // Width estimate: 6.5px per char + 12px padding, capped at 120
    const gwLabelW = gwLabel ? Math.min(120, Math.round(gwLabel.length * 6.5) + 12) : 0;
    const apLabelW = apLabel ? Math.max(40, apLabel.length * 7 + 8) : 0;

    return (
      <g className={cls} style={style} data-vlan={vlanAttr}>
        <path className="edge-wired-bg"   d={edge.path} />
        <path className="edge-wired-flow" d={edge.path} />
        {mid && gwLabel && (
          <>
            {/* Gateway-side label (upper half) */}
            <rect
              x={mid.x - gwLabelW / 2} y={mid.y - 22}
              width={gwLabelW} height={14}
              rx={3} className="edge-label-bg"
            />
            <text x={mid.x} y={mid.y - 12} className="edge-label edge-label--gw">
              {gwLabel}
            </text>
            {/* AP-side label (lower half) */}
            {apLabel && (
              <>
                <rect
                  x={mid.x - apLabelW / 2} y={mid.y + 8}
                  width={apLabelW} height={14}
                  rx={3} className="edge-label-bg"
                />
                <text x={mid.x} y={mid.y + 18} className="edge-label edge-label--ap">
                  {apLabel}
                </text>
              </>
            )}
          </>
        )}
        {hitPath}
      </g>
    );
  }

  if (edge.kind === 'router-uplink') {
    const ends = pathEnds(edge.path);
    const mid = cubicMid(edge.path) ?? (ends ? lerp(ends.start, ends.end, 0.5) : null);
    const oneWay = edge.lldp?.direction === 'one_way';
    const hasConflict = (edge.lldp?.conflicts?.length ?? 0) > 0;
    // from-port badge near the source end, to-port badge near the target end.
    const fromPos = ends ? lerp(ends.start, ends.end, 0.16) : null;
    const toPos   = ends ? lerp(ends.start, ends.end, 0.84) : null;
    const flowCls = `edge-router-flow${oneWay ? ' edge-router-flow--oneway' : ''}`;

    return (
      <g className={`${cls}${oneWay ? ' edge-oneway' : ''}`} style={style} data-vlan={vlanAttr}>
        <path className="edge-router-bg"   d={edge.path} />
        <path className={flowCls} d={edge.path} />
        {mid && (
          <>
            <rect
              x={mid.x - 20} y={mid.y - 24}
              width={40} height={14} rx={7}
              className="edge-lldp-badge-bg"
            />
            <text x={mid.x} y={mid.y - 14} className="edge-lldp-badge">LLDP</text>
          </>
        )}
        {fromPos && edge.fromPort && (
          <PortBadge x={fromPos.x} y={fromPos.y} text={edge.fromPort.toUpperCase()} side="from" />
        )}
        {toPos && edge.toPort && (
          <PortBadge x={toPos.x} y={toPos.y} text={edge.toPort.toUpperCase()} side="to" />
        )}
        {mid && oneWay && (
          <text x={mid.x} y={mid.y + 20} className="edge-oneway-hint">
            <title>Nur von einer Seite gesehen (one-way)</title>
            ◃ einseitig
          </text>
        )}
        {mid && hasConflict && (
          <g className="edge-conflict-marker">
            <circle cx={mid.x + 26} cy={mid.y - 17} r={7} className="edge-conflict-dot" />
            <text x={mid.x + 26} y={mid.y - 13} className="edge-conflict-icon">!</text>
            <title>LLDP-Port weicht von Bridge-FDB ab</title>
          </g>
        )}
        {hitPath}
      </g>
    );
  }

  // ap-mesh
  return (
    <g className={cls} style={style} data-vlan={vlanAttr}>
      <path className="edge-mesh-bg"   d={edge.path} />
      <path className="edge-mesh-flow" d={edge.path} />
      {hitPath}
    </g>
  );
}
