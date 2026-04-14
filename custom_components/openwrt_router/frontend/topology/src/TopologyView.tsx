/**
 * TopologyView — main composition root.
 *
 * Architecture separation:
 *   Layout:    computed by layout.ts (no React, pure math)
 *   Rendering: this file + individual node components
 *   Animation: topology.css (pure CSS, GPU-accelerated)
 *   State:     React useState hooks below
 *   Data:      passed as prop (TopologyData)
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { TopologyData, FilterType, AccessPoint, Client, Gateway } from './types';
import { computeLayout, computeHoverContext } from './layout';
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

export function TopologyView({ data }: Props) {
  // ── Container width measurement ─────────────────────────────────────
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(960);

  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width ?? 960;
      setContainerWidth(w);
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // ── Filter & search state ───────────────────────────────────────────
  const [filter, setFilter] = useState<FilterType>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // ── Hover state ─────────────────────────────────────────────────────
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // ── Selection / detail panel ────────────────────────────────────────
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(null);

  // ── Layout computation ──────────────────────────────────────────────
  const layout = computeLayout(data, containerWidth);
  const hoverCtx = computeHoverContext(hoveredNodeId, data, layout);

  // ── Filtered views ──────────────────────────────────────────────────
  const visibleAPs = data.accessPoints.filter(ap => {
    if (filter === 'clients') return false;
    if (filter === 'warnings') return ap.status !== 'online';
    if (searchQuery) return ap.name.toLowerCase().includes(searchQuery.toLowerCase())
      || ap.ip.includes(searchQuery);
    return true;
  });

  const clientsForAP = useCallback(
    (apId: string): Client[] => {
      let clients = data.clients.filter(c => c.apId === apId);
      if (filter === 'aps') return [];
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

  // ── Selection handlers ──────────────────────────────────────────────
  const selectGateway = () =>
    setSelectedEntity({ type: 'gateway', data: data.gateway });

  const selectAP = (ap: AccessPoint) =>
    setSelectedEntity({ type: 'ap', data: ap, clients: clientsForAP(ap.id) });

  const selectClient = (client: Client) => {
    const ap = data.accessPoints.find(a => a.id === client.apId);
    setSelectedEntity({ type: 'client', data: client, apName: ap?.name ?? client.apId });
  };

  // ── Stats for filter bar ────────────────────────────────────────────
  const warningCount =
    data.accessPoints.filter(a => a.status !== 'online').length +
    data.clients.filter(c => c.status !== 'online').length;

  // ── Render ──────────────────────────────────────────────────────────
  const dimmedEdges = new Set(
    layout.edges
      .filter(e => !hoverCtx.highlightedEdges.has(e.id) && hoveredNodeId !== null)
      .map(e => e.id),
  );

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

      <div className="topo-scroll" ref={containerRef}>
        <div
          className="topo-canvas"
          style={{ width: layout.canvasWidth, height: layout.canvasHeight }}
          onClick={e => {
            if (e.currentTarget === e.target) setSelectedEntity(null);
          }}
        >
          {/* ── Layer 1: SVG connections (below nodes) ── */}
          <ConnectionLayer
            edges={layout.edges}
            width={layout.canvasWidth}
            height={layout.canvasHeight}
            highlightedEdges={hoverCtx.highlightedEdges}
            dimmedEdges={dimmedEdges}
          />

          {/* ── Layer 2: HTML nodes ── */}

          {/* Internet */}
          <InternetNode layout={layout.internetNode} />

          {/* Gateway */}
          <GatewayNode
            gateway={data.gateway}
            layout={layout.gatewayNode}
            selected={selectedEntity?.type === 'gateway'}
            dimmed={hoverCtx.dimmedNodes.has(data.gateway.id)}
            onSelect={selectGateway}
            onHover={setHoveredNodeId}
          />

          {/* Access Points + Client Strips */}
          {data.accessPoints.map(ap => {
            const apLayout = layout.apNodes.get(ap.id);
            const stripLayout = layout.clientStripNodes.get(ap.id);
            if (!apLayout || !stripLayout) return null;

            const apClients = clientsForAP(ap.id);
            const isHidden =
              filter === 'clients' ||
              (filter === 'warnings' && ap.status === 'online' && apClients.length === 0);
            if (isHidden) return null;

            return (
              <React.Fragment key={ap.id}>
                <APNode
                  ap={ap}
                  layout={apLayout}
                  selected={selectedEntity?.type === 'ap' && selectedEntity.data.id === ap.id}
                  dimmed={hoverCtx.dimmedNodes.has(ap.id)}
                  onSelect={() => selectAP(ap)}
                  onHover={setHoveredNodeId}
                />
                <ClientStrip
                  clients={apClients}
                  layout={stripLayout}
                  dimmed={hoverCtx.dimmedNodes.has(ap.id)}
                  onSelectClient={selectClient}
                />
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* ── Detail panel (fixed right side) ── */}
      <DetailPanel
        entity={selectedEntity}
        onClose={() => setSelectedEntity(null)}
      />
    </div>
  );
}
