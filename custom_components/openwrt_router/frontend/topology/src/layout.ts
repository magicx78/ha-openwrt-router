/**
 * layout.ts — Dynamic edge computation from DOM bounding boxes.
 *
 * Separation of concerns:
 *   This module ONLY computes SVG edge paths. It contains no React, no DOM
 *   access, and no rendering logic. Given node center positions (obtained
 *   by the render layer via getBoundingClientRect) it returns EdgeLayout
 *   objects that the ConnectionLayer renders.
 *
 *   Node positions are owned by CSS Flexbox — this module receives measured
 *   bounding boxes and converts them to SVG path strings.
 */

import {
  TopologyData,
  EdgeLayout,
  EdgeKind,
} from './types';

// ── Constants ─────────────────────────────────────────────────────────────

/** Height of the client-strip row (used by TopologyView for spacing). */
export const CLIENT_STRIP_H = 52;

// ── Node bounds (measured from DOM, logical coords) ───────────────────────

export interface NodeBounds {
  cx: number; // center x in logical (pre-zoom) coordinates
  cy: number; // center y in logical (pre-zoom) coordinates
  w: number;  // width in logical coordinates
  h: number;  // height in logical coordinates
}

// ── Edge computation from DOM bounds ──────────────────────────────────────

/**
 * Compute SVG edge paths from the bounding boxes of rendered nodes.
 *
 * Caller obtains bounding boxes via getBoundingClientRect() and divides by
 * the current zoom level to convert to logical (pre-zoom) coordinates.
 */
export function computeEdgesFromBounds(
  data: TopologyData,
  bounds: Map<string, NodeBounds>,
): EdgeLayout[] {
  const edges: EdgeLayout[] = [];

  const internet = bounds.get('internet');
  const gateway  = bounds.get(data.gateway.id);

  // Internet → Gateway
  if (internet && gateway) {
    edges.push({
      id:       'edge-internet-gw',
      sourceId: 'internet',
      targetId: data.gateway.id,
      kind:     'internet',
      path:     `M ${internet.cx} ${internet.cy + internet.h / 2} L ${gateway.cx} ${gateway.cy - gateway.h / 2}`,
      status:   'online',
    });
  }

  // Gateway / parent-AP → each AP
  data.accessPoints.forEach(ap => {
    const apB = bounds.get(ap.id);
    if (!apB) return;

    if (ap.uplinkTo === data.gateway.id && gateway) {
      // Cubic S-curve: gateway bottom → AP top
      const sx = gateway.cx, sy = gateway.cy + gateway.h / 2;
      const ex = apB.cx,     ey = apB.cy - apB.h / 2;
      const midY = (sy + ey) / 2;
      edges.push({
        id:       `edge-gw-${ap.id}`,
        sourceId: data.gateway.id,
        targetId: ap.id,
        kind:     'gateway-wired' as EdgeKind,
        path:     `M ${sx} ${sy} C ${sx} ${midY}, ${ex} ${midY}, ${ex} ${ey}`,
        status:   ap.status,
        vlanId:   ap.primaryVlanId,
      });
    } else {
      // Mesh: quadratic arc between AP tops
      const parentB = bounds.get(ap.uplinkTo);
      if (parentB) {
        const sx = parentB.cx, sy = parentB.cy - parentB.h / 2;
        const ex = apB.cx,     ey = apB.cy - apB.h / 2;
        const midX    = (sx + ex) / 2;
        const arcPeakY = Math.min(sy, ey) - 48;
        edges.push({
          id:       `edge-${ap.uplinkTo}-${ap.id}`,
          sourceId: ap.uplinkTo,
          targetId: ap.id,
          kind:     'ap-mesh' as EdgeKind,
          path:     `M ${sx} ${sy} Q ${midX} ${arcPeakY} ${ex} ${ey}`,
          status:   ap.status,
          vlanId:   ap.primaryVlanId,
        });
      }
    }
  });

  return edges;
}

// ── Hover context computation ─────────────────────────────────────────────

/**
 * Given a hovered node id, returns which edges to highlight and which nodes
 * to dim. Called on every hover change.
 */
export function computeHoverContext(
  hoveredId: string | null,
  data: TopologyData,
  edges: EdgeLayout[],
): { highlightedEdges: Set<string>; dimmedNodes: Set<string> } {
  if (!hoveredId) {
    return { highlightedEdges: new Set(), dimmedNodes: new Set() };
  }

  const highlightedEdges = new Set<string>();
  const dimmedNodes      = new Set<string>();

  const allNodeIds = new Set<string>([
    'internet',
    data.gateway.id,
    ...data.accessPoints.map(a => a.id),
  ]);
  const allEdgeIds = new Set(edges.map(e => e.id));

  const pathNodeIds = new Set<string>([hoveredId]);
  const pathEdgeIds = new Set<string>();

  if (hoveredId === data.gateway.id || hoveredId === 'internet') {
    pathNodeIds.add('internet');
    pathNodeIds.add(data.gateway.id);
    pathEdgeIds.add('edge-internet-gw');
  } else {
    const ap = data.accessPoints.find(a => a.id === hoveredId);
    if (ap) {
      let current: string = ap.id;
      pathNodeIds.add(current);
      pathNodeIds.add('internet');
      pathNodeIds.add(data.gateway.id);
      pathEdgeIds.add('edge-internet-gw');

      while (true) {
        const currentAP = data.accessPoints.find(a => a.id === current);
        if (!currentAP) break;
        const edgeId = currentAP.uplinkTo === data.gateway.id
          ? `edge-gw-${current}`
          : `edge-${currentAP.uplinkTo}-${current}`;
        pathEdgeIds.add(edgeId);
        pathNodeIds.add(currentAP.uplinkTo);
        if (currentAP.uplinkTo === data.gateway.id) break;
        current = currentAP.uplinkTo;
      }
    }
  }

  for (const edgeId of allEdgeIds) {
    if (pathEdgeIds.has(edgeId)) highlightedEdges.add(edgeId);
  }
  for (const nodeId of allNodeIds) {
    if (!pathNodeIds.has(nodeId)) dimmedNodes.add(nodeId);
  }

  return { highlightedEdges, dimmedNodes };
}

// ── Signal quality helper ─────────────────────────────────────────────────

export function signalQuality(dbm: number): 'excellent' | 'good' | 'fair' | 'poor' {
  if (dbm >= -55) return 'excellent';
  if (dbm >= -65) return 'good';
  if (dbm >= -75) return 'fair';
  return 'poor';
}
