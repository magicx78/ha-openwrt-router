/**
 * TopologyView — main composition root.
 *
 * Architecture:
 *   Layout:    CSS Flexbox — nodes flow naturally, no fixed pixel positions
 *   SVG lines: computed from DOM bounding boxes via useLayoutEffect
 *   Zoom/Pan:  CSS transform on wrapper (scale + translate), wheel + drag
 *   State:     React hooks
 *   Data:      TopologyData prop
 */

import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { TopologyData, FilterType, AccessPoint, Client, Gateway, EdgeLayout } from './types';
import { computeEdgesFromBounds, computeHoverContext, NodeBounds } from './layout';
import { ConnectionLayer } from './components/ConnectionLayer';
import { InternetNode } from './components/InternetNode';
import { GatewayNode } from './components/GatewayNode';
import { APNode } from './components/APNode';
import { ClientStrip } from './components/ClientStrip';
import { DetailPanel } from './components/DetailPanel';
import { FilterBar } from './components/FilterBar';

type SelectedEntity =
  | { type: 'gateway'; data: Gateway }
  | { type: 'ap'; data: AccessPoint; clients: Client[] }
  | { type: 'client'; data: Client; apName: string }
  | null;

interface Props {
  data: TopologyData;
}

const MIN_ZOOM  = 0.25;
const MAX_ZOOM  = 3.0;
const ZOOM_STEP = 0.12;

export function TopologyView({ data }: Props) {
  // ── Zoom / Pan ──────────────────────────────────────────────────────────
  const [zoom, setZoom] = useState(1.0);
  const [pan,  setPan]  = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const lastPos = useRef<{ x: number; y: number } | null>(null);

  // Keep refs in sync so wheel handler (captured by addEventListener) reads
  // the latest zoom/pan without stale closure.
  const zoomRef = useRef(zoom);
  const panRef  = useRef(pan);
  zoomRef.current = zoom;
  panRef.current  = pan;

  // ── DOM refs ────────────────────────────────────────────────────────────
  const scrollRef  = useRef<HTMLDivElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  // Map of node-id → anchor <div> element for bounds measurement
  const nodeRefs = useRef<Map<string, HTMLDivElement | null>>(new Map());

  // ── Dynamic SVG state ────────────────────────────────────────────────────
  const [edges,   setEdges]   = useState<EdgeLayout[]>([]);
  const [svgSize, setSvgSize] = useState({ w: 800, h: 600 });

  // ── Filter / search / hover / selection ─────────────────────────────────
  const [filter,      setFilter]      = useState<FilterType>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(null);

  // ── Wheel zoom (must be non-passive to call preventDefault) ─────────────
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect      = el.getBoundingClientRect();
      const mouseX    = e.clientX - rect.left;
      const mouseY    = e.clientY - rect.top;
      const factor    = e.deltaY < 0 ? (1 + ZOOM_STEP) : (1 - ZOOM_STEP);
      const currZoom  = zoomRef.current;
      const currPan   = panRef.current;
      const newZoom   = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, currZoom * factor));
      // Zoom toward cursor: keep logical point under cursor fixed
      const newPanX   = mouseX - (mouseX - currPan.x) / currZoom * newZoom;
      const newPanY   = mouseY - (mouseY - currPan.y) / currZoom * newZoom;
      setZoom(newZoom);
      setPan({ x: newPanX, y: newPanY });
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []); // stable: uses refs internally

  // ── Recompute edge paths from DOM bounding boxes ─────────────────────────
  const recomputeEdges = useCallback(() => {
    const wrapperEl = wrapperRef.current;
    if (!wrapperEl) return;
    const wr = wrapperEl.getBoundingClientRect();
    const z  = zoomRef.current;

    const bounds = new Map<string, NodeBounds>();
    nodeRefs.current.forEach((el, id) => {
      if (!el) return;
      const r = el.getBoundingClientRect();
      // Convert screen coords (affected by zoom) back to logical coords.
      // Pan cancels out when computing relative to wrapper origin.
      bounds.set(id, {
        cx: (r.left - wr.left) / z + (r.width  / z) / 2,
        cy: (r.top  - wr.top)  / z + (r.height / z) / 2,
        w:   r.width  / z,
        h:   r.height / z,
      });
    });

    setSvgSize({ w: wrapperEl.offsetWidth, h: wrapperEl.offsetHeight });
    setEdges(computeEdgesFromBounds(data, bounds));
  }, [data, zoom]); // zoom in deps → new fn → effect re-runs

  // Run after every render where deps changed (before paint = no flash)
  useLayoutEffect(() => {
    recomputeEdges();
  }, [recomputeEdges]);

  // Also recompute on container resize (e.g. panel open/close, window resize)
  useEffect(() => {
    const ro = new ResizeObserver(recomputeEdges);
    if (wrapperRef.current) ro.observe(wrapperRef.current);
    return () => ro.disconnect();
  }, [recomputeEdges]);

  // ── Hover context ────────────────────────────────────────────────────────
  const hoverCtx  = computeHoverContext(hoveredNodeId, data, edges);
  const dimmedEdges = new Set(
    edges
      .filter(e => !hoverCtx.highlightedEdges.has(e.id) && hoveredNodeId !== null)
      .map(e => e.id),
  );

  // ── Pointer drag to pan ──────────────────────────────────────────────────
  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    // Don't start pan when clicking on interactive elements
    if ((e.target as HTMLElement).closest('.node-card, .client-strip, .filter-bar, button, input')) return;
    lastPos.current = { x: e.clientX, y: e.clientY };
    setDragging(true);
    e.currentTarget.setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (!lastPos.current) return;
    const z  = zoomRef.current;
    const dx = (e.clientX - lastPos.current.x) / z;
    const dy = (e.clientY - lastPos.current.y) / z;
    lastPos.current = { x: e.clientX, y: e.clientY };
    setPan(p => ({ x: p.x + dx, y: p.y + dy }));
  }, []);

  const onPointerUp = useCallback(() => {
    setDragging(false);
    lastPos.current = null;
  }, []);

  // ── Filter / client helpers ──────────────────────────────────────────────
  const clientsForAP = useCallback(
    (apId: string): Client[] => {
      let clients = data.clients.filter(c => c.apId === apId);
      if (filter === 'aps')      return [];
      if (filter === 'warnings') clients = clients.filter(c => c.status !== 'online');
      if (searchQuery) {
        clients = clients.filter(
          c =>
            c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            c.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
            c.ip.includes(searchQuery),
        );
      }
      return clients;
    },
    [data.clients, filter, searchQuery],
  );

  const gwClients = data.clients.filter(c => c.apId === data.gateway.id);

  const selectGateway = () => setSelectedEntity({ type: 'gateway', data: data.gateway });
  const selectAP = (ap: AccessPoint) =>
    setSelectedEntity({ type: 'ap', data: ap, clients: clientsForAP(ap.id) });
  const selectClient = (client: Client) => {
    const ap = data.accessPoints.find(a => a.id === client.apId);
    setSelectedEntity({ type: 'client', data: client, apName: ap?.name ?? client.apId });
  };

  const warningCount =
    data.accessPoints.filter(a => a.status !== 'online').length +
    data.clients.filter(c => c.status !== 'online').length;

  // ── Ref setter helper ────────────────────────────────────────────────────
  const setNodeRef = (id: string) => (el: HTMLDivElement | null) => {
    nodeRefs.current.set(id, el);
  };

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="topo-app">
      <FilterBar
        filter={filter}
        searchQuery={searchQuery}
        totalClients={data.clients.length}
        warningCount={warningCount}
        onFilterChange={setFilter}
        onSearchChange={setSearchQuery}
      />

      {/* Zoom/pan scroll container */}
      <div
        ref={scrollRef}
        className="topo-scroll"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onClick={e => { if (e.currentTarget === e.target) setSelectedEntity(null); }}
      >
        {/* Zoom wrapper — transform applied here */}
        <div
          ref={wrapperRef}
          className={`topo-zoom-wrapper${dragging ? ' dragging' : ''}`}
          style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` }}
        >
          {/* SVG connections layer — absolute overlay, behind flex nodes */}
          <svg
            className="connections-svg"
            viewBox={`0 0 ${svgSize.w} ${svgSize.h}`}
            aria-hidden="true"
          >
            <ConnectionLayer
              edges={edges}
              highlightedEdges={hoverCtx.highlightedEdges}
              dimmedEdges={dimmedEdges}
            />
          </svg>

          {/* ── Flexbox layout tree ── */}
          <div className="topo-layout">

            {/* Row 1: Internet */}
            <div className="topo-row topo-row--internet">
              <div ref={setNodeRef('internet')} style={{ width: 'fit-content' }}>
                <InternetNode />
              </div>
            </div>

            {/* Row 2: Gateway (+ optional gateway client strip below) */}
            <div className="topo-row topo-row--gateway">
              <div className="topo-col-gateway">
                <div ref={setNodeRef(data.gateway.id)} style={{ width: 'fit-content' }}>
                  <GatewayNode
                    gateway={data.gateway}
                    selected={selectedEntity?.type === 'gateway'}
                    dimmed={hoverCtx.dimmedNodes.has(data.gateway.id)}
                    onSelect={selectGateway}
                    onHover={setHoveredNodeId}
                    clientCount={gwClients.length > 0 ? gwClients.length : undefined}
                  />
                </div>
                {clientsForAP(data.gateway.id).length > 0 && (
                  <ClientStrip
                    clients={clientsForAP(data.gateway.id)}
                    dimmed={hoverCtx.dimmedNodes.has(data.gateway.id)}
                    onSelectClient={selectClient}
                  />
                )}
              </div>
            </div>

            {/* Row 3: Access Points — flex-wrap so they reflow at any width */}
            <div className="topo-row topo-row--aps">
              {data.accessPoints.map(ap => {
                const apClients = clientsForAP(ap.id);
                const isHidden =
                  filter === 'clients' ||
                  (filter === 'warnings' && ap.status === 'online' && apClients.length === 0);
                if (isHidden) return null;

                return (
                  <div key={ap.id} className="topo-col-ap">
                    <div ref={setNodeRef(ap.id)} style={{ width: 'fit-content' }}>
                      <APNode
                        ap={ap}
                        selected={selectedEntity?.type === 'ap' && selectedEntity.data.id === ap.id}
                        dimmed={hoverCtx.dimmedNodes.has(ap.id)}
                        onSelect={() => selectAP(ap)}
                        onHover={setHoveredNodeId}
                      />
                    </div>
                    <ClientStrip
                      clients={apClients}
                      dimmed={hoverCtx.dimmedNodes.has(ap.id)}
                      onSelectClient={selectClient}
                    />
                  </div>
                );
              })}
            </div>

          </div>{/* end .topo-layout */}
        </div>{/* end .topo-zoom-wrapper */}
      </div>{/* end .topo-scroll */}

      {/* Detail panel (slides in from right / up from bottom on mobile) */}
      <DetailPanel
        entity={selectedEntity}
        onClose={() => setSelectedEntity(null)}
      />
    </div>
  );
}
