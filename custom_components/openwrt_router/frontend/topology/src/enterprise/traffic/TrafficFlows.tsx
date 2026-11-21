/**
 * TrafficFlows — "Flows" (administrators only): which flow sources exist
 * and why none delivers. Phase J has no collector, so there are no flow
 * rows; an empty list is said to be "unknown", never "no traffic".
 */

import React from 'react';
import type { FlowsView, TrafficApi } from './trafficTypes';
import { FLOWS_NOTE, reasonText, sourceStateView } from './trafficLogic.ts';
import { Loaded, Notice, SectionBox, ShownBadge, SourceList, usePolled } from './trafficUi';

export function FlowsBody({ data }: { data: FlowsView }) {
  return (
    <>
      <Notice tone="info">
        <ShownBadge shown={sourceStateView(data.source.state)} /> {data.source.reason ? reasonText(data.source.reason) : ''}. {FLOWS_NOTE}
      </Notice>
      <SectionBox title="Flow-Quellen"><SourceList sources={data.sources} /></SectionBox>
    </>
  );
}

export function TrafficFlows({ api, rev }: { api: TrafficApi; rev: number }) {
  const res = usePolled(() => api.flows(), rev);
  return <Loaded res={res}>{d => <FlowsBody data={d} />}</Loaded>;
}
