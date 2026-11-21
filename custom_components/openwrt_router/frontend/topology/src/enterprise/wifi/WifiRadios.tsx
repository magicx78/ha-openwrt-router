/**
 * WifiRadios — one card per radio: channel, width, utilization, noise,
 * retries, TX power, signal, clients, health, load, and the capability
 * state of every metric. Unknown values are "—" with their reason; the
 * survey / scan warning sits above the list.
 */

import React from 'react';
import type { Radio, RadiosView } from './wifiTypes';
import {
  DASH, METRIC_LABEL, SCAN_METRICS, bandLabel, countText, fmtNum, fmtShare, fmtValue, healthView, loadView,
  metricView, radioLabel, reasonText, stateText,
} from './wifiLogic.ts';
import { Fact, ScanNotes, ToneBadge, Unknown, Val } from './wifiUi';
import { NotReadyNotice, OffNotice } from './WifiOverview';

function CapabilityList({ radio }: { radio: Radio }) {
  return (
    <ul className="wifi-caps" aria-label={`Fähigkeiten ${radioLabel(radio)}`}>
      {Object.keys(METRIC_LABEL).map(name => {
        const state = radio.capabilities.states[name] ?? null;
        const tone = state === 'measured' ? 'info' : state === 'unreachable' ? 'warn' : 'muted';
        return (
          <li key={name} className={`wifi-cap wifi-cap--${tone}`}>
            <span className="wifi-cap__name">{METRIC_LABEL[name]}{SCAN_METRICS.includes(name) ? ' (Survey/Scan)' : ''}</span>
            <span className="wifi-cap__state">{stateText(state)}</span>
          </li>
        );
      })}
    </ul>
  );
}

function RadioCard({ radio, status }: { radio: Radio; status: RadiosView['status'] }) {
  const m = radio.metrics;
  const util = metricView(m.utilization, 'pct');
  const health = healthView(radio.health, status);
  const load = loadView(radio.loadStatus);
  const sum = radio.utilSummary;
  return (
    <li className="wifi-card">
      <div className="wifi-card__head">
        <span className="wifi-card__title">{radioLabel(radio)}</span>
        <ToneBadge tone="info">{bandLabel(radio.band)}</ToneBadge>
        {radio.backhaul === true && <ToneBadge tone="muted">WLAN-Uplink</ToneBadge>}
      </div>
      <Fact name="Kanal">{radio.channel === null ? <Unknown text={`${DASH} unbekannt`} /> : fmtNum(radio.channel)}</Fact>
      <Fact name="Breite">{radio.widthMhz === null ? <Unknown text={`${DASH} unbekannt`} /> : `${fmtNum(radio.widthMhz)} MHz`}</Fact>
      <Fact name="Auslastung">
        <Val v={util} />
        {util.known && sum && sum.mean !== null && (
          <span className="wifi-muted"> · Mittel {fmtValue(sum.mean, 'pct')}{sum.peak !== null ? `, Spitze ${fmtValue(sum.peak, 'pct')}` : ''}</span>
        )}
        {!util.known && radio.utilReason && <span className="wifi-muted"> · {reasonText(radio.utilReason)}</span>}
      </Fact>
      <Fact name="Noise"><Val v={metricView(m.noise, 'dbm')} /></Fact>
      <Fact name="Retry"><Val v={metricView(m.retry_rate, 'per_packet')} /></Fact>
      <Fact name="Sendeleistung"><Val v={metricView(m.txpower, 'dbm')} /></Fact>
      <Fact name="Signal (Mittel)"><Val v={metricView(m.rssi_mean, 'dbm')} /></Fact>
      <Fact name="Signalqualität"><Val v={metricView(m.signal_quality, 'score')} /></Fact>
      <Fact name="Airtime des größten Clients"><Val v={metricView(m.airtime_top_client, 'pct')} /></Fact>
      <Fact name="Clients">
        {radio.clients.count === null ? <Unknown text={countText(null)} /> : fmtNum(radio.clients.count)}
        {radio.clients.retryCoverage !== null && <span className="wifi-muted"> · Retry-Zähler für {fmtShare(radio.clients.retryCoverage)}</span>}
      </Fact>
      <Fact name="Health Score">
        {health.value === null ? <Unknown text={health.text} /> : <span className={`wifi-tone-${health.tone}`}>{health.text}</span>}
      </Fact>
      <Fact name="Last">{radio.loadStatus === null || radio.loadStatus === 'unknown'
        ? <Unknown text={load.label} />
        : <span className={`wifi-tone-${load.tone}`}>{load.label}</span>}</Fact>
      <details className="wifi-details">
        <summary>Fähigkeiten je Messwert{radio.capabilities.coverage !== null ? ` (${fmtShare(radio.capabilities.coverage)} gemessen)` : ''}</summary>
        <CapabilityList radio={radio} />
      </details>
    </li>
  );
}

export function WifiRadios({ view }: { view: RadiosView }) {
  if (view.status === 'off') return <OffNotice />;
  return (
    <div className="cfg-stack">
      {view.status === 'not_ready' && <NotReadyNotice reasons={view.reasons.map(reasonText)} />}
      <ScanNotes />
      {view.radios.length === 0
        ? <Unknown text={`${DASH} noch kein Radio ausgewertet`} />
        : <ul className="wifi-cards">{view.radios.map(r => <RadioCard key={`${r.routerId}/${r.radioId}`} radio={r} status={view.status} />)}</ul>}
    </div>
  );
}
