/**
 * layout.ts — Hierarchical tree layout computation.
 *
 * Separation of concerns:
 *   This module ONLY computes pixel positions. It contains no React, no DOM
 *   access, and no rendering logic. Given topology data + container width it
 *   returns NodeLayout / EdgeLayout objects that the render layer consumes.
 */

import {
  TopologyData,
  TopologyLayout,
  NodeLayout,
  EdgeLayout,
  EdgeKind,
} from './types';

// ── Fixed geometry constants ──────────────────────────────────────────────

const CANVAS_PAD_X = 60;     // horizontal breathing room on each side
const CANVAS_PAD_TOP = 28;

const INTERNET_R = 30;       // internet circle radius
const GATEWAY_W = 224;
const GATEWAY_H = 112;
const AP_W = 170;
const AP_H = 100;
const AP_SPACING_IDEAL = 260; // ideal center-to-center distance between APs
const AP_SPACING_MIN   = 180; // minimum spacing — cards stay readable

// Vertical Y of each row's center
const INTERNET_CY = CANVAS_PAD_TOP + INTERNET_R;
const GATEWAY_CY  = INTERNET_CY + INTERNET_R + 44 + GATEWAY_H / 2;
const AP_CY       = GATEWAY_CY + GATEWAY_H / 2 + 88 + AP_H / 2;
const CLIENT_STRIP_H  = 52;
const CLIENT_STRIP_CY = AP_CY + AP_H / 2 + 12 + CLIENT_STRIP_H / 2;
const CANVAS_H = CLIENT_STRIP_CY + CLIENT_STRIP_H / 2 + 36;

// ── Main layout function ──────────────────────────────────────────────────

export function computeLayout(
  data: TopologyData,
  containerWidth: number,
): TopologyLayout {
  const n = data.accessPoints.length;

  // Canvas always fits in the container — spacing shrinks if needed.
  const cw = Math.max(containerWidth, 880);
  const cx = cw / 2;

  // Dynamic AP spacing: never wider than the container.
  const available = cw - 2 * CANVAS_PAD_X - AP_W;
  const apSpacing = n > 1
    ? Math.max(AP_SPACING_MIN, Math.min(AP_SPACING_IDEAL, available / (n - 1)))
    : AP_SPACING_IDEAL;

  // ── Internet & Gateway (always centered) ─────────────────────────────
  const internetNode: NodeLayout = {
    id: 'internet',
    cx,
    cy: INTERNET_CY,
    width: INTERNET_R * 2,
    height: INTERNET_R * 2,
  };

  const gatewayNode: NodeLayout = {
    id: data.gateway.id,
    cx,
    cy: GATEWAY_CY,
    width: GATEWAY_W,
    height: GATEWAY_H,
  };

  // ── Access Points (evenly distributed, centered on canvas) ───────────
  const totalSpan = Math.max(n - 1, 0) * apSpacing;
  const apStartCX = cx - totalSpan / 2;

  const apNodes = new Map<string, NodeLayout>();
  data.accessPoints.forEach((ap, i) => {
    apNodes.set(ap.id, {
      id: ap.id,
      cx: apStartCX + i * apSpacing,
      cy: AP_CY,
      width: AP_W,
      height: AP_H,
    });
  });

  // ── Client strip (same x as parent AP, just below) ───────────────────
  const clientStripNodes = new Map<string, NodeLayout>();
  data.accessPoints.forEach(ap => {
    const apL = apNodes.get(ap.id)!;
    clientStripNodes.set(ap.id, {
      id: `strip-${ap.id}`,
      cx: apL.cx,
      cy: CLIENT_STRIP_CY,
      width: AP_W,
      height: CLIENT_STRIP_H,
    });
  });

  // ── Edges ─────────────────────────────────────────────────────────────
  const edges: EdgeLayout[] = [];

  // Internet → Gateway (straight vertical)
  edges.push({
    id: 'edge-internet-gw',
    sourceId: 'internet',
    targetId: data.gateway.id,
    kind: 'internet',
    path: vLine(cx, INTERNET_CY + INTERNET_R, GATEWAY_CY - GATEWAY_H / 2),
    status: 'online',
  });

  // Gateway → AP (wired) or parent-AP → AP (mesh)
  const gwBy = GATEWAY_CY + GATEWAY_H / 2;

  data.accessPoints.forEach(ap => {
    const apL = apNodes.get(ap.id)!;
    const apTop = apL.cy - apL.height / 2;

    if (ap.uplinkTo === data.gateway.id) {
      // Wired: cubic bezier from gateway bottom to AP top
      edges.push({
        id: `edge-gw-${ap.id}`,
        sourceId: data.gateway.id,
        targetId: ap.id,
        kind: 'gateway-wired' as EdgeKind,
        path: cubicY(cx, gwBy, apL.cx, apTop),
        status: ap.status,
      });
    } else {
      // Mesh: quadratic arc at AP level, connecting parent-top → child-top
      const parentL = apNodes.get(ap.uplinkTo);
      if (parentL) {
        const midX = (parentL.cx + apL.cx) / 2;
        // Arc peaks 64px above the AP top row
        const arcPeakY = apTop - 64;
        edges.push({
          id: `edge-${ap.uplinkTo}-${ap.id}`,
          sourceId: ap.uplinkTo,
          targetId: ap.id,
          kind: 'ap-mesh' as EdgeKind,
          path: `M ${parentL.cx} ${apTop} Q ${midX} ${arcPeakY} ${apL.cx} ${apTop}`,
          status: ap.status,
        });
      }
    }
  });

  return {
    internetNode,
    gatewayNode,
    apNodes,
    clientStripNodes,
    edges,
    canvasWidth: Math.max(cw, apStartCX + totalSpan + AP_W / 2 + CANVAS_PAD_X),
    canvasHeight: CANVAS_H,
  };
}

// ── Path helpers ──────────────────────────────────────────────────────────

/** Straight vertical line from (x, y1) to (x, y2). */
function vLine(x: number, y1: number, y2: number): string {
  return `M ${x} ${y1} L ${x} ${y2}`;
}

/** Cubic bezier with vertical tangents — smooth S-curve between two points. */
function cubicY(sx: number, sy: number, ex: number, ey: number): string {
  const midY = (sy + ey) / 2;
  return `M ${sx} ${sy} C ${sx} ${midY}, ${ex} ${midY}, ${ex} ${ey}`;
}

// ── Hover context computation ─────────────────────────────────────────────

/**
 * Given a hovered node id and the full layout, returns which edges to
 * highlight and which nodes to dim. Called on every hover change.
 */
export function computeHoverContext(
  hoveredId: string | null,
  data: TopologyData,
  layout: TopologyLayout,
): { highlightedEdges: Set<string>; dimmedNodes: Set<string> } {
  if (!hoveredId) {
    return { highlightedEdges: new Set(), dimmedNodes: new Set() };
  }

  const highlightedEdges = new Set<string>();
  const dimmedNodes = new Set<string>();

  // Collect all node ids
  const allNodeIds = new Set<string>([
    'internet',
    data.gateway.id,
    ...data.accessPoints.map(a => a.id),
  ]);
  const allEdgeIds = new Set(layout.edges.map(e => e.id));

  // Determine the "path to internet" for the hovered node
  const pathNodeIds = new Set<string>([hoveredId]);
  const pathEdgeIds = new Set<string>();

  if (hoveredId === data.gateway.id || hoveredId === 'internet') {
    // Gateway or internet: highlight full uplink chain
    pathNodeIds.add('internet');
    pathNodeIds.add(data.gateway.id);
    pathEdgeIds.add('edge-internet-gw');
  } else {
    // AP or client AP id
    const ap = data.accessPoints.find(a => a.id === hoveredId);
    if (ap) {
      // Walk uplink chain: AP → gateway (or parent AP → gateway)
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
