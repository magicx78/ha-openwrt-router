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
    const gwLabel = edge.gatewayPort
      ? `${edge.gatewayPort.toUpperCase()}${edge.gatewayPortSpeed ? ' · ' + speedLabel(edge.gatewayPortSpeed) : ''}`
      : null;
    const apLabel = edge.apPort ? edge.apPort.toUpperCase() : null;

    return (
      <g className={cls} style={style} data-vlan={vlanAttr}>
        <path className="edge-wired-bg"   d={edge.path} />
        <path className="edge-wired-flow" d={edge.path} />
        {mid && gwLabel && (
          <>
            {/* Gateway-side label (upper half) */}
            <rect
              x={mid.x - 28} y={mid.y - 22}
              width={56} height={14}
              rx={3} className="edge-label-bg"
            />
            <text x={mid.x} y={mid.y - 12} className="edge-label edge-label--gw">
              {gwLabel}
            </text>
            {/* AP-side label (lower half) */}
            {apLabel && (
              <>
                <rect
                  x={mid.x - 20} y={mid.y + 8}
                  width={40} height={14}
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

  // ap-mesh
  return (
    <g className={cls} style={style} data-vlan={vlanAttr}>
      <path className="edge-mesh-bg"   d={edge.path} />
      <path className="edge-mesh-flow" d={edge.path} />
      {hitPath}
    </g>
  );
}
