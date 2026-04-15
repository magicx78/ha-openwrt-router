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

// Mobile breakpoint: below this width, switch to single-column layout
const MOBILE_BREAKPOINT = 560;

// Vertical Y of each row's center (desktop)
const INTERNET_CY = CANVAS_PAD_TOP + INTERNET_R;
const GATEWAY_CY  = INTERNET_CY + INTERNET_R + 44 + GATEWAY_H / 2;
const AP_CY       = GATEWAY_CY + GATEWAY_H / 2 + 88 + AP_H / 2;
const CLIENT_STRIP_H  = 52;
const CLIENT_STRIP_CY = AP_CY + AP_H / 2 + 12 + CLIENT_STRIP_H / 2;
const CANVAS_H = CLIENT_STRIP_CY + CLIENT_STRIP_H / 2 + 36;

// Mobile row spacing
const MOBILE_PAD_X    = 16;
const MOBILE_AP_GAP   = 20;   // gap between AP bottom and next AP top
const MOBILE_STRIP_GAP = 8;   // gap between AP bottom and client strip top

// ── Main layout function ──────────────────────────────────────────────────

export function computeLayout(
  data: TopologyData,
  containerWidth: number,
): TopologyLayout {
  // On mobile, TopologyView renders a separate MobileView (no canvas).
  // Return an empty layout so the canvas is never shown.
  if (containerWidth > 0 && containerWidth < MOBILE_BREAKPOINT) {
    return {
      internetNode:      { id: 'internet', cx: 0, cy: 0, width: 0, height: 0 },
      gatewayNode:       { id: 'gw', cx: 0, cy: 0, width: 0, height: 0 },
      apNodes:           new Map(),
      clientStripNodes:  new Map(),
      edges:             [],
      canvasWidth:       0,
      canvasHeight:      0,
    };
  }
  return computeDesktopLayout(data, containerWidth);
}

// ── Desktop layout ────────────────────────────────────────────────────────

function computeDesktopLayout(
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

// ── Mobile layout (single-column, no horizontal scroll) ──────────────────

function computeMobileLayout(
  data: TopologyData,
  containerWidth: number,
): TopologyLayout {
  const cw = containerWidth;
  const cx = cw / 2;

  // Internet node
  const internetCY = CANVAS_PAD_TOP + INTERNET_R;
  const internetNode: NodeLayout = {
    id: 'internet',
    cx,
    cy: internetCY,
    width: INTERNET_R * 2,
    height: INTERNET_R * 2,
  };

  // Gateway node — narrower on mobile to fit
  const gwW = Math.min(GATEWAY_W, cw - 2 * MOBILE_PAD_X);
  const gatewayCY = internetCY + INTERNET_R + 36 + GATEWAY_H / 2;
  const gatewayNode: NodeLayout = {
    id: data.gateway.id,
    cx,
    cy: gatewayCY,
    width: gwW,
    height: GATEWAY_H,
  };

  // APs — stacked vertically, centered
  const apW = Math.min(AP_W, cw - 2 * MOBILE_PAD_X);
  const apNodes = new Map<string, NodeLayout>();
  const clientStripNodes = new Map<string, NodeLayout>();

  let cursorY = gatewayCY + GATEWAY_H / 2 + 56; // top of first AP row

  data.accessPoints.forEach(ap => {
    const apCY = cursorY + AP_H / 2;
    apNodes.set(ap.id, {
      id: ap.id,
      cx,
      cy: apCY,
      width: apW,
      height: AP_H,
    });

    const stripCY = apCY + AP_H / 2 + MOBILE_STRIP_GAP + CLIENT_STRIP_H / 2;
    clientStripNodes.set(ap.id, {
      id: `strip-${ap.id}`,
      cx,
      cy: stripCY,
      width: apW,
      height: CLIENT_STRIP_H,
    });

    cursorY = stripCY + CLIENT_STRIP_H / 2 + MOBILE_AP_GAP;
  });

  const canvasHeight = cursorY + 24;

  // ── Edges ─────────────────────────────────────────────────────────────
  const edges: EdgeLayout[] = [];

  // Internet → Gateway (straight vertical)
  edges.push({
    id: 'edge-internet-gw',
    sourceId: 'internet',
    targetId: data.gateway.id,
    kind: 'internet',
    path: vLine(cx, internetCY + INTERNET_R, gatewayCY - GATEWAY_H / 2),
    status: 'online',
  });

  const gwBy = gatewayCY + GATEWAY_H / 2;

  data.accessPoints.forEach(ap => {
    const apL = apNodes.get(ap.id)!;
    const apTop = apL.cy - AP_H / 2;

    if (ap.uplinkTo === data.gateway.id) {
      // Straight vertical line — all APs are centered under gateway
      edges.push({
        id: `edge-gw-${ap.id}`,
        sourceId: data.gateway.id,
        targetId: ap.id,
        kind: 'gateway-wired' as EdgeKind,
        path: vLine(cx, gwBy, apTop),
        status: ap.status,
      });
    } else {
      // Mesh uplink — straight vertical to parent AP bottom
      const parentL = apNodes.get(ap.uplinkTo);
      if (parentL) {
        const parentBottom = parentL.cy + AP_H / 2;
        edges.push({
          id: `edge-${ap.uplinkTo}-${ap.id}`,
          sourceId: ap.uplinkTo,
          targetId: ap.id,
          kind: 'ap-mesh' as EdgeKind,
          path: vLine(cx, parentBottom + CLIENT_STRIP_H + MOBILE_STRIP_GAP, apTop),
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
    canvasWidth: cw,
    canvasHeight,
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
