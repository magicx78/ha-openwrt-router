/**
 * ConnectionLayer — renders topology edges as SVG path elements.
 *
 * Renders directly inside an <svg> parent (no wrapper svg here).
 * The parent SVG is owned by TopologyView and sized via the zoom wrapper.
 */

import React from 'react';
import { EdgeLayout } from '../types';

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
    return (
      <g className={cls} style={style} data-vlan={vlanAttr}>
        <path className="edge-wired-bg"   d={edge.path} />
        <path className="edge-wired-flow" d={edge.path} />
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
