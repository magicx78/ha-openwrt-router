/**
 * TrafficClients — "Clients & VLANs": per client (pseudonym, never a MAC or
 * host name) the current rate and volume at its access point, and per
 * router the measured and configured VLANs. VLANs are never added up
 * across routers.
 */

import React from 'react';
import type { ClientList, ClientRow, TrafficApi, VlanList, VlanRow } from './trafficTypes';
import {
  DASH, clientLabel, durationText, fmtBytes, fmtCount, fmtRate, formatTs, reasonText, routerName, sourceStateView,
} from './trafficLogic.ts';
import { CoverageBadge, Fact, Loaded, SectionBox, ShownBadge, Unknown, V, usePolled } from './trafficUi';

function reasonOf(row: { unavailable: { field: string; reason: string }[] }, field: string): string | null {
  return row.unavailable.find(u => u.field === field)?.reason ?? null;
}

function ClientCard({ c }: { c: ClientRow }) {
  return (
    <li className="wifi-card">
      <div className="wifi-card__head">
        <span className="wifi-card__title">{clientLabel(c.clientRef)}</span>
        <CoverageBadge level={c.coverage} reasons={c.coverageReasons} />
      </div>
      <Fact name="Download jetzt"><V text={fmtRate(c.downBps)} known={c.downBps !== null} reason={reasonOf(c, 'down_bps')} /></Fact>
      <Fact name="Upload jetzt"><V text={fmtRate(c.upBps)} known={c.upBps !== null} reason={reasonOf(c, 'up_bps')} /></Fact>
      <Fact name="Download gesamt"><V text={fmtBytes(c.downBytes)} known={c.downBytes !== null} reason={reasonOf(c, 'down_bytes')} /></Fact>
      <Fact name="Upload gesamt"><V text={fmtBytes(c.upBytes)} known={c.upBytes !== null} reason={reasonOf(c, 'up_bytes')} /></Fact>
      <Fact name="Erfasste Zeit">{durationText(c.coveredS)}</Fact>
      <Fact name="Router">{routerName(c.routerId)}</Fact>
      <Fact name="VLAN">{c.vlanId === null ? <Unknown text={`${DASH} ${reasonText(reasonOf(c, 'vlan_id') ?? 'no_data')}`} /> : c.vlanId}</Fact>
      <Fact name="Anteil am WAN"><ShownBadge shown={sourceStateView(c.wanAttribution.state)} />{c.wanAttribution.reason && <span className="wifi-muted"> {reasonText(c.wanAttribution.reason)}</span>}</Fact>
      <Fact name="Lücken">Roaming {fmtCount(c.roamingGaps)} · Unterbrechungen {fmtCount(c.interruptions)}</Fact>
      <Fact name="Zuletzt gesehen">{c.lastSeen === null ? <Unknown text={DASH} /> : formatTs(c.lastSeen)}</Fact>
    </li>
  );
}

export function ClientCards({ list }: { list: ClientList }) {
  if (!list.clients.length) return <Unknown text="— noch kein Client erfasst (WLAN-Stationszähler der Access Points)" />;
  return (
    <>
      <ul className="wifi-cards">{list.clients.map(c => <ClientCard key={c.clientRef} c={c} />)}</ul>
      {list.truncated && <div className="wifi-muted">Gezeigt werden {list.clients.length} von {fmtCount(list.total)} Clients.</div>}
    </>
  );
}

function VlanCard({ v }: { v: VlanRow }) {
  return (
    <li className="wifi-card">
      <div className="wifi-card__head">
        <span className="wifi-card__title">VLAN {v.vlanId ?? DASH} · {routerName(v.routerId)}</span>
        <CoverageBadge level={v.coverage} reasons={v.coverageReasons} />
      </div>
      <Fact name="Empfangen (rx) jetzt"><V text={fmtRate(v.rxBps)} known={v.rxBps !== null} reason={reasonOf(v, 'rx_bps')} /></Fact>
      <Fact name="Gesendet (tx) jetzt"><V text={fmtRate(v.txBps)} known={v.txBps !== null} reason={reasonOf(v, 'tx_bps')} /></Fact>
      <Fact name="Messstellen">{v.measured} gemessen · {v.configuredPorts} Ports konfiguriert</Fact>
      <Fact name="Aktive Clients"><V text={fmtCount(v.activeClients)} known={v.activeClients !== null} reason={reasonOf(v, 'active_clients')} /></Fact>
      <Fact name="Zwischen VLANs"><ShownBadge shown={sourceStateView(v.interVlan.state)} />{v.interVlan.reason && <span className="wifi-muted"> {reasonText(v.interVlan.reason)}</span>}</Fact>
      <Fact name="Bezug zum WAN"><ShownBadge shown={sourceStateView(v.wanRelated.state)} />{v.wanRelated.reason && <span className="wifi-muted"> {reasonText(v.wanRelated.reason)}</span>}</Fact>
      {v.directionReason && <div className="wifi-muted">{reasonText(v.directionReason)}</div>}
    </li>
  );
}

export function VlanCards({ list }: { list: VlanList }) {
  if (!list.vlans.length) return <Unknown text="— kein VLAN gemessen oder konfiguriert" />;
  return <ul className="wifi-cards">{list.vlans.map(v => <VlanCard key={`${v.routerId}|${v.vlanId}`} v={v} />)}</ul>;
}

export function TrafficClients({ api, rev }: { api: TrafficApi; rev: number }) {
  const clients = usePolled(() => api.clients(), rev);
  const vlans = usePolled(() => api.vlans(), rev);
  return (
    <>
      <SectionBox title="Clients" hint="Pseudonyme statt MAC-Adressen und Gerätenamen. Download = was der Access Point an den Client gesendet hat.">
        <Loaded res={clients}>{l => <ClientCards list={l} />}</Loaded>
      </SectionBox>
      <SectionBox title="VLANs" hint="Je Router; VLANs mehrerer Router werden nicht addiert.">
        <Loaded res={vlans}>{l => <VlanCards list={l} />}</Loaded>
      </SectionBox>
    </>
  );
}
