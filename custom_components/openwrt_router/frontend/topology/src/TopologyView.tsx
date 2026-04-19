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
import { useAlerts } from './useAlerts';
import { useGhostDevices, formatLastSeen } from './useGhostDevices';
import { computeEdgesFromBounds, computeHoverContext, NodeBounds } from './layout';
import { ConnectionLayer } from './components/ConnectionLayer';
import { InternetNode } from './components/InternetNode';
import { GatewayNode } from './components/GatewayNode';
import { APNode } from './components/APNode';
import { ClientStrip } from './components/ClientStrip';
import { DetailPanel } from './components/DetailPanel';
import { StatusBar } from './components/StatusBar';
import { Sidebar, SidebarTab } from './components/Sidebar';
import { EdgeTooltip } from './components/EdgeTooltip';
import { NodeTooltip } from './components/NodeTooltip';
import { DevicesView } from './components/DevicesView';
import { ClientsView } from './components/ClientsView';
import { AlertsView } from './components/AlertsView';
import { TrafficView } from './components/TrafficView';
import { SettingsView } from './components/SettingsView';
import { Minimap, MinimapNode } from './components/Minimap';
import { ContextMenu, ContextMenuEntry } from './components/ContextMenu';
import { APClientList } from './components/APClientList';

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
  // ── Sidebar + active tab ─────────────────────────────────────────────────
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<SidebarTab>('topology');

  // ── Edge hover tooltip ────────────────────────────────────────────────────
  const [hoveredEdge, setHoveredEdge] = useState<{ edgeId: string; x: number; y: number } | null>(null);

  const onEdgeHover = useCallback((edgeId: string | null, x: number, y: number) => {
    setHoveredEdge(edgeId ? { edgeId, x, y } : null);
  }, []);

  // ── Traffic overlay mode ─────────────────────────────────────────────────
  const [trafficMode, setTrafficMode] = useState(false);

  // ── WLAN Heatmap toggle ──────────────────────────────────────────────────
  const [heatmapMode, setHeatmapMode] = useState(false);

  // ── Ghost Mode ───────────────────────────────────────────────────────────
  const [ghostMode, setGhostMode] = useState(false);

  // ── VLAN Overlay mode ────────────────────────────────────────────────────
  const [vlanMode, setVlanMode] = useState(false);

  // ── Health mode ───────────────────────────────────────────────────────────
  const [healthMode, setHealthMode] = useState(false);
  const ghosts = useGhostDevices(data.accessPoints, data.clients, ghostMode);

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

  // ── Minimap state — node bounds + container size ─────────────────────────
  const [minimapNodes, setMinimapNodes] = useState<MinimapNode[]>([]);
  const [containerSize, setContainerSize] = useState({ w: 800, h: 600 });

  // ── Expanded AP client list state ─────────────────────────────────────────
  const [expandedApId, setExpandedApId] = useState<string | null>(null);

  // ── Context menu state ────────────────────────────────────────────────────
  const [contextMenu, setContextMenu] = useState<{
    nodeId: string;
    kind: 'gateway' | 'ap';
    x: number;
    y: number;
  } | null>(null);

  // ── CPU history ring buffer (accumulates cpuLoad across polls) ──────────
  const CPU_HISTORY_MAX = 20;
  const cpuHistoryRef = useRef<number[]>([]);
  if (data.gateway.cpuLoad != null) {
    const h = cpuHistoryRef.current;
    if (h.length === 0 || h[h.length - 1] !== data.gateway.cpuLoad) {
      cpuHistoryRef.current = [...h, data.gateway.cpuLoad].slice(-CPU_HISTORY_MAX);
    }
  }

  // ── Filter / search / hover / selection ─────────────────────────────────
  const [filter,      setFilter]      = useState<FilterType>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // ── AP exit animation tracking ────────────────────────────────────────────
  const [exitingApIds, setExitingApIds] = useState<Set<string>>(new Set());
  const prevHiddenRef = useRef<Set<string>>(new Set());
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(null);

  // ── Fit view ─────────────────────────────────────────────────────────────
  const fitView = useCallback(() => {
    setZoom(1.0);
    setPan({ x: 0, y: 0 });
  }, []);

  // ── Minimap pan: click on minimap → center that logical point in viewport ─
  const onMinimapPan = useCallback((logicalX: number, logicalY: number) => {
    const sc = scrollRef.current;
    if (!sc) return;
    setPan({
      x: sc.clientWidth  / 2 - logicalX * zoomRef.current,
      y: sc.clientHeight / 2 - logicalY * zoomRef.current,
    });
  }, []);

  // ── Pan canvas to center a node in the viewport ───────────────────────────
  const panToNode = useCallback((nodeId: string) => {
    const el = nodeRefs.current.get(nodeId);
    const sc = scrollRef.current;
    if (!el || !sc) return;
    const er = el.getBoundingClientRect();
    const sr = sc.getBoundingClientRect();
    const nodeCX = er.left + er.width  / 2 - sr.left;
    const nodeCY = er.top  + er.height / 2 - sr.top;
    setPan(p => ({
      x: p.x + sr.width  / 2 - nodeCX,
      y: p.y + sr.height / 2 - nodeCY,
    }));
  }, []);

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

    // Derive minimap nodes from measured bounds
    const mmNodes: MinimapNode[] = [];
    const ib = bounds.get('internet');
    if (ib) mmNodes.push({ id: 'internet', cx: ib.cx, cy: ib.cy, status: 'online', kind: 'internet' });
    const gb = bounds.get(data.gateway.id);
    if (gb) mmNodes.push({ id: data.gateway.id, cx: gb.cx, cy: gb.cy, status: data.gateway.status, kind: 'gateway' });
    data.accessPoints.forEach(ap => {
      const b = bounds.get(ap.id);
      if (b) mmNodes.push({ id: ap.id, cx: b.cx, cy: b.cy, status: ap.status, kind: 'ap' });
    });
    setMinimapNodes(mmNodes);

    const sc = scrollRef.current;
    if (sc) setContainerSize({ w: sc.clientWidth, h: sc.clientHeight });
  }, [data, zoom]); // zoom in deps → new fn → effect re-runs

  // Run after every render where deps changed (before paint = no flash)
  useLayoutEffect(() => {
    recomputeEdges();
  }, [recomputeEdges]);

  // Also recompute on container resize (e.g. panel open/close, window resize)
  useEffect(() => {
    const ro = new ResizeObserver(recomputeEdges);
    if (wrapperRef.current) ro.observe(wrapperRef.current);
    if (scrollRef.current)  ro.observe(scrollRef.current);
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
    if ((e.target as HTMLElement).closest('.node-card, .client-strip, .status-bar, .topo-sidebar, .minimap, button, input')) return;
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

  // ── Detect newly-hidden APs → play exit animation before removing ─────────
  useEffect(() => {
    const currentlyHidden = new Set(
      data.accessPoints
        .filter(ap => {
          const apC = clientsForAP(ap.id);
          return filter === 'clients' ||
            (filter === 'warnings' && ap.status === 'online' && apC.length === 0);
        })
        .map(ap => ap.id),
    );
    const newlyHidden = new Set<string>();
    for (const id of currentlyHidden) {
      if (!prevHiddenRef.current.has(id)) newlyHidden.add(id);
    }
    prevHiddenRef.current = currentlyHidden;
    if (newlyHidden.size === 0) return;

    setExitingApIds(prev => new Set([...prev, ...newlyHidden]));
    const t = setTimeout(() => {
      setExitingApIds(prev => {
        const next = new Set(prev);
        newlyHidden.forEach(id => next.delete(id));
        return next;
      });
    }, 240);
    return () => clearTimeout(t);
  }, [filter, searchQuery, data.accessPoints, clientsForAP]);

  const selectGateway = () => setSelectedEntity({ type: 'gateway', data: data.gateway });
  const selectAP = (ap: AccessPoint) =>
    setSelectedEntity({ type: 'ap', data: ap, clients: clientsForAP(ap.id) });
  const selectClient = (client: Client) => {
    const ap = data.accessPoints.find(a => a.id === client.apId);
    setSelectedEntity({ type: 'client', data: client, apName: ap?.name ?? client.apId });
  };

  const totalNodes  = data.accessPoints.length + 1; // +1 for gateway
  const onlineNodes = [data.gateway, ...data.accessPoints].filter(n => n.status === 'online').length;
  const alerts      = useAlerts(data);
  const warningCount = alerts.length;

  // Highlight a client in the topology graph (called from TrafficView Top Talker)
  const highlightClient = useCallback((clientId: string) => {
    const client = data.clients.find(c => c.id === clientId);
    if (!client) return;
    const ap = data.accessPoints.find(a => a.id === client.apId);
    setSelectedEntity({ type: 'client', data: client, apName: ap?.name ?? client.apId });
    setActiveTab('topology');
  }, [data]);

  // ── Ref setter helper ────────────────────────────────────────────────────
  const setNodeRef = (id: string) => (el: HTMLDivElement | null) => {
    nodeRefs.current.set(id, el);
  };

  // ── Context menu item builders ────────────────────────────────────────────
  const buildGatewayMenuItems = useCallback((): ContextMenuEntry[] => [
    { icon: '🔍', label: 'Details', onClick: () => selectGateway() },
    { icon: '◎', label: 'Fokus', onClick: () => { selectGateway(); panToNode(data.gateway.id); } },
    { separator: true },
    { icon: '⚠', label: 'Alarme', onClick: () => setActiveTab('alerts') },
    { icon: '▦', label: 'VLANs ein/aus', onClick: () => setVlanMode(m => !m) },
  ], [data.gateway.id, panToNode]);

  const buildAPMenuItems = useCallback((ap: AccessPoint): ContextMenuEntry[] => [
    { icon: '🔍', label: 'Details', onClick: () => selectAP(ap) },
    { icon: '◎', label: 'Fokus', onClick: () => { selectAP(ap); panToNode(ap.id); } },
    { separator: true },
    { icon: '👥', label: 'Clients', onClick: () => setActiveTab('clients') },
    { icon: '⚠', label: 'Alarme', onClick: () => setActiveTab('alerts') },
  ], [panToNode]);

  const contextMenuItems = useCallback((): ContextMenuEntry[] => {
    if (!contextMenu) return [];
    if (contextMenu.kind === 'gateway') return buildGatewayMenuItems();
    const ap = data.accessPoints.find(a => a.id === contextMenu.nodeId);
    return ap ? buildAPMenuItems(ap) : [];
  }, [contextMenu, buildGatewayMenuItems, buildAPMenuItems, data.accessPoints]);

  // ── Render ───────────────────────────────────────────────────────────────
  // ── Focus mode class — applied when any node is hovered ─────────────────
  const hasActiveFocus = hoveredNodeId !== null;

  const appClass = [
    'topo-app',
    trafficMode ? 'traffic-mode'  : '',
    vlanMode    ? 'vlan-mode'     : '',
    healthMode  ? 'health-mode'   : '',
  ].filter(Boolean).join(' ');

  return (
    <div className={appClass}>
      {/* ── Left sidebar ─────────────────────────────────────── */}
      <Sidebar
        open={sidebarOpen}
        activeTab={activeTab}
        warningCount={warningCount}
        onToggle={() => setSidebarOpen(o => !o)}
        onTabChange={setActiveTab}
      />

      {/* ── Main column ─────────────────────────────────────── */}
      <div className="topo-main">
        <StatusBar
          filter={filter}
          searchQuery={searchQuery}
          totalNodes={totalNodes}
          onlineNodes={onlineNodes}
          totalClients={data.clients.length}
          warningCount={warningCount}
          pingMs={data.gateway.pingMs}
          trafficMode={trafficMode}
          heatmapMode={heatmapMode}
          ghostMode={ghostMode}
          vlanMode={vlanMode}
          healthMode={healthMode}
          topologyControls={activeTab === 'topology'}
          onFilterChange={setFilter}
          onSearchChange={setSearchQuery}
          onFitView={fitView}
          onToggleTraffic={() => setTrafficMode(m => !m)}
          onToggleHeatmap={() => setHeatmapMode(m => !m)}
          onToggleGhost={() => setGhostMode(m => !m)}
          onToggleVlan={() => setVlanMode(m => !m)}
          onToggleHealth={() => setHealthMode(m => !m)}
        />

        {/* ── Non-topology views ───────────────────────────────── */}
        {activeTab === 'devices' && (
          <DevicesView
            data={data}
            onSelectGateway={selectGateway}
            onSelectAP={ap => setSelectedEntity({ type: 'ap', data: ap, clients: data.clients.filter(c => c.apId === ap.id) })}
          />
        )}
        {activeTab === 'clients' && (
          <ClientsView data={data} onSelectClient={selectClient} />
        )}
        {activeTab === 'traffic' && (
          <TrafficView data={data} onHighlightClient={highlightClient} />
        )}
        {activeTab === 'alerts' && (
          <AlertsView
            data={data}
            onSelectGateway={selectGateway}
            onSelectAP={ap => setSelectedEntity({ type: 'ap', data: ap, clients: data.clients.filter(c => c.apId === ap.id) })}
            onSelectClient={selectClient}
          />
        )}
        {activeTab === 'settings' && <SettingsView />}

        {/* ── Topology zoom/pan canvas ─────────────────────────── */}
        <div
          ref={scrollRef}
          className={`topo-scroll${hasActiveFocus ? ' has-focus' : ''}${activeTab !== 'topology' ? ' topo-scroll--hidden' : ''}`}
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
                onEdgeHover={!dragging ? onEdgeHover : undefined}
                vlanMode={vlanMode}
              />
            </svg>

            {/* ── Flexbox layout tree ── */}
            <div className="topo-layout">

              {/* Row 1: Internet */}
              <div className="topo-row topo-row--internet">
                <div ref={setNodeRef('internet')} style={{ width: 'fit-content' }}>
                  <InternetNode pingMs={data.gateway.pingMs} />
                </div>
              </div>

              {/* Row 2: Gateway (+ optional gateway client strip below) */}
              <div className="topo-row topo-row--gateway">
                <div className="topo-col-gateway">
                  <div ref={setNodeRef(data.gateway.id)} style={{ width: 'fit-content' }}>
                    <GatewayNode
                      gateway={{ ...data.gateway, cpuHistory: cpuHistoryRef.current }}
                      selected={selectedEntity?.type === 'gateway'}
                      dimmed={hoverCtx.dimmedNodes.has(data.gateway.id)}
                      onSelect={selectGateway}
                      onHover={setHoveredNodeId}
                      onContextMenu={(x, y) => setContextMenu({ nodeId: data.gateway.id, kind: 'gateway', x, y })}
                      clientCount={gwClients.length > 0 ? gwClients.length : undefined}
                      vlanMode={vlanMode}
                      healthMode={healthMode}
                    />
                  </div>
                  {clientsForAP(data.gateway.id).length > 0 && (
                    <ClientStrip
                      clients={clientsForAP(data.gateway.id)}
                      dimmed={hoverCtx.dimmedNodes.has(data.gateway.id)}
                      onSelectClient={selectClient}
                      vlanMode={vlanMode}
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
                  const isExiting = exitingApIds.has(ap.id);
                  if (isHidden && !isExiting) return null;

                  return (
                    <div key={ap.id} className={`topo-col-ap${isExiting ? ' ap-exiting' : ''}`}>
                      <div ref={setNodeRef(ap.id)} style={{ width: 'fit-content' }}>
                        <APNode
                          ap={ap}
                          clients={apClients}
                          selected={selectedEntity?.type === 'ap' && selectedEntity.data.id === ap.id}
                          dimmed={hoverCtx.dimmedNodes.has(ap.id)}
                          expanded={expandedApId === ap.id}
                          onSelect={() => selectAP(ap)}
                          onHover={setHoveredNodeId}
                          onContextMenu={(x, y) => setContextMenu({ nodeId: ap.id, kind: 'ap', x, y })}
                          onToggleExpand={() => setExpandedApId(id => id === ap.id ? null : ap.id)}
                          heatmap={heatmapMode}
                          vlanMode={vlanMode}
                          healthMode={healthMode}
                        />
                      </div>
                      {expandedApId === ap.id ? (
                        <APClientList clients={apClients} onSelectClient={selectClient} />
                      ) : (
                        <ClientStrip
                          clients={apClients}
                          dimmed={hoverCtx.dimmedNodes.has(ap.id)}
                          onSelectClient={selectClient}
                          vlanMode={vlanMode}
                        />
                      )}
                    </div>
                  );
                })}

                {/* Ghost APs */}
                {ghosts.aps.map(gAP => (
                  <div key={`ghost-${gAP.id}`} className="topo-col-ap ghost-node">
                    <div className="ap-card node-card ghost-ap">
                      <div className="ap-card__header">
                        <div className="ghost-ap__icon">👻</div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div className="ap-card__name">{gAP.name}</div>
                          <div className="ap-card__ip">{gAP.ip}</div>
                        </div>
                      </div>
                      <div className="ghost-ap__lastseen">
                        Zuletzt gesehen: {formatLastSeen(gAP.lastSeenMs)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

            </div>{/* end .topo-layout */}
          </div>{/* end .topo-zoom-wrapper */}

          {/* Minimap — bottom-right overview, only in topology tab */}
          {activeTab === 'topology' && minimapNodes.length > 0 && (
            <Minimap
              nodes={minimapNodes}
              canvasW={svgSize.w}
              canvasH={svgSize.h}
              pan={pan}
              zoom={zoom}
              containerW={containerSize.w}
              containerH={containerSize.h}
              onPanTo={onMinimapPan}
            />
          )}
        </div>{/* end .topo-scroll */}

        {/* Detail panel (slides in from right / up from bottom on mobile) */}
        <DetailPanel
          entity={selectedEntity}
          onClose={() => setSelectedEntity(null)}
        />
      </div>{/* end .topo-main */}

      {/* Edge hover tooltip — fixed overlay, outside zoom transform */}
      {hoveredEdge && !dragging && (
        <EdgeTooltip
          edgeId={hoveredEdge.edgeId}
          x={hoveredEdge.x}
          y={hoveredEdge.y}
          edges={edges}
          data={data}
        />
      )}

      {/* VLAN Overlay — floating legend panel when vlanMode is active */}
      {vlanMode && activeTab === 'topology' && (() => {
        const vlans = data.gateway.vlans ?? [];
        return (
          <div className="vlan-overlay">
            <div className="vlan-overlay__title">VLANs ({vlans.length})</div>
            {vlans.length === 0 ? (
              <div className="vlan-overlay__empty">Keine VLANs erkannt</div>
            ) : (
              <div className="vlan-overlay__list">
                {vlans.map(v => (
                  <div key={v.id} className="vlan-overlay__row" data-vlan={v.id}>
                    <span className={`vlan-overlay__dot${v.status === 'up' ? ' up' : v.status === 'down' ? ' down' : ''}`} />
                    <span className="vlan-overlay__id">VLAN {v.id}</span>
                    <span className="vlan-overlay__iface">{v.interface}</span>
                    <span className={`vlan-overlay__status${v.status === 'up' ? ' up' : v.status === 'down' ? ' down' : ''}`}>{v.status}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      {/* Node hover tooltip — appears beside the hovered gateway / AP card */}
      {hoveredNodeId && !dragging && (() => {
        const el = nodeRefs.current.get(hoveredNodeId);
        if (!el) return null;
        const rect = el.getBoundingClientRect();
        return (
          <NodeTooltip nodeId={hoveredNodeId} data={data} anchorRect={rect} />
        );
      })()}

      {/* Right-click context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          items={contextMenuItems()}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
}
