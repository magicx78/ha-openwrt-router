/**
 * ConnectionLayer — SVG overlay that renders all topology edges.
 *
 * Rendering is separated from layout (layout.ts) and from node cards.
 * This component is pure: it receives pre-computed paths and only draws.
 */

import React from 'react';
import { EdgeLayout, NodeStatus } from '../types';

interface Props {
  edges: EdgeLayout[];
  width: number;
  height: number;
  highlightedEdges: Set<string>;
  dimmedEdges: Set<string>;
}

export function ConnectionLayer({
  edges,
  width,
  height,
  highlightedEdges,
  dimmedEdges,
}: Props) {
  return (
    <svg
      className="connections-svg"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
    >
      {edges.map(edge => (
        <EdgeGroup
          key={edge.id}
          edge={edge}
          highlighted={highlightedEdges.has(edge.id)}
          dimmed={dimmedEdges.has(edge.id)}
        />
      ))}
    </svg>
  );
}

// ── Single edge ───────────────────────────────────────────────────────────

interface EdgeGroupProps {
  edge: EdgeLayout;
  highlighted: boolean;
  dimmed: boolean;
}

function EdgeGroup({ edge, highlighted, dimmed }: EdgeGroupProps) {
  const cls = [
    dimmed && !highlighted ? 'edge-dimmed' : '',
    highlighted ? 'edge-highlighted' : '',
    edge.status === 'warning' ? 'edge-warning' : '',
  ]
    .filter(Boolean)
    .join(' ');

  if (edge.kind === 'internet') {
    return (
      <g className={cls}>
        <path className="edge-internet-bg" d={edge.path} />
        <path className="edge-internet-flow" d={edge.path} />
      </g>
    );
  }

  if (edge.kind === 'gateway-wired') {
    return (
      <g className={cls}>
        <path className="edge-wired-bg" d={edge.path} />
        <path className="edge-wired-flow" d={edge.path} />
      </g>
    );
  }

  // ap-mesh
  return (
    <g className={cls}>
      <path className="edge-mesh-bg" d={edge.path} />
      <path className="edge-mesh-flow" d={edge.path} />
    </g>
  );
}
