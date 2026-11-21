/**
 * TrafficFlows — "Flows" (administrators only): the flows an external
 * collector pushed (Phase K), and which flow sources exist and why none
 * delivers. Endpoints are pseudonyms only; an empty list is said to be
 * "unknown", never "no traffic".
 */

import React from 'react';
import type { FlowsView, TrafficApi } from './trafficTypes';
import {
  DASH, FLOWS_NOTE, clientLabel, flowEndpoint, fmtBytes, fmtCount, formatTs, reasonText, routerName,
  sourceStateView,
} from './trafficLogic.ts';
import { Fact, Loaded, Notice, SectionBox, ShownBadge, SourceList, usePolled } from './trafficUi';

export function FlowRows({ data }: { data: FlowsView }) {
  if (!data.rows.length) return null;
  return (
    <SectionBox title={`Flows vom Collector (${data.rows.length})`}>
      <ul className="wifi-cards">
        {data.rows.map((f, i) => (
          <li key={i} className="wifi-card">
            <div className="wifi-card__head">
              <span className="wifi-card__title">{(f.proto ?? DASH).toUpperCase()} {flowEndpoint(f.src, f.srcPort)} → {flowEndpoint(f.dst, f.dstPort)}</span>
            </div>
            <Fact name="Wo">{routerName(f.routerId)}{f.clientRef ? ` · ${clientLabel(f.clientRef)}` : ' · Client unbekannt'}{f.vlanId !== null ? ` · VLAN ${f.vlanId}` : ''}</Fact>
            <Fact name="Daten / Pakete">{fmtBytes(f.bytes)} / {fmtCount(f.packets)}</Fact>
            <Fact name="Zeitraum">{formatTs(f.start)} – {formatTs(f.end)}</Fact>
          </li>
        ))}
      </ul>
      {data.complete === false && <div className="wifi-muted">Nicht vollständig: es werden höchstens die neuesten Flows gezeigt.</div>}
    </SectionBox>
  );
}

export function FlowsBody({ data }: { data: FlowsView }) {
  return (
    <>
      <Notice tone="info">
        <ShownBadge shown={sourceStateView(data.source.state)} /> {data.source.reason ? reasonText(data.source.reason) : ''}. {FLOWS_NOTE}
      </Notice>
      <FlowRows data={data} />
      <SectionBox title="Flow-Quellen"><SourceList sources={data.sources} /></SectionBox>
    </>
  );
}

export function TrafficFlows({ api, rev }: { api: TrafficApi; rev: number }) {
  const res = usePolled(() => api.flows(), rev);
  return <Loaded res={res}>{d => <FlowsBody data={d} />}</Loaded>;
}
