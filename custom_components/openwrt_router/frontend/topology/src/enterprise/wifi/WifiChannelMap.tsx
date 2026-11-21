/**
 * WifiChannelMap — occupied channels per band: the own radios on each
 * channel (width, clients, utilization) and the number of foreign networks.
 * No SSID or BSSID is ever shown; the backend sends no foreign count in
 * this release (no scan), so that column says why it is unknown. Below,
 * the channel conflicts with their status and evidence.
 */

import React from 'react';
import type { ChannelMap, RadiosView } from './wifiTypes';
import {
  CONFLICT_KIND_TEXT, CONFLICT_STATUS_TEXT, DASH, bandLabel, channelRows, fmtNum, radioLabel, reasonText, scrub,
} from './wifiLogic.ts';
import { Fact, ScanNotes, SectionBox, ToneBadge, Unknown, Val } from './wifiUi';
import { NotReadyNotice, OffNotice } from './WifiOverview';

export function WifiChannelMap({ map, radios }: { map: ChannelMap; radios: RadiosView | null }) {
  if (map.status === 'off') return <OffNotice />;
  const bands = channelRows(map, radios);
  return (
    <div className="cfg-stack">
      {map.status === 'not_ready' && <NotReadyNotice reasons={map.reasons.map(reasonText)} />}
      <ScanNotes />
      {bands.length === 0 && <Unknown text={`${DASH} noch kein Kanal ausgewertet`} />}
      {bands.map(b => (
        <SectionBox key={b.band} title={b.label} hint="Belegte Kanäle mit den eigenen Radios. Fremde Netze nur als Anzahl, nie mit Namen oder Adresse.">
          <ul className="wifi-cards">
            {b.channels.map(ch => (
              <li key={String(ch.channel)} className="wifi-card">
                <div className="wifi-card__head">
                  <span className="wifi-card__title">{ch.channel === null ? 'Kanal unbekannt' : `Kanal ${fmtNum(ch.channel)}`}</span>
                  <ToneBadge tone={ch.own.length > 1 ? 'warn' : 'info'}>
                    {ch.own.length === 1 ? '1 eigenes Radio' : `${fmtNum(ch.own.length)} eigene Radios`}
                  </ToneBadge>
                </div>
                <ul className="wifi-rows">
                  {ch.own.map(o => (
                    <li key={o.key} className="wifi-row">
                      <span className="wifi-row__title">{o.label}{o.backhaul ? ' (WLAN-Uplink)' : ''}</span>
                      <span>{o.width}</span>
                      <span>Clients {o.clients}</span>
                      <span>Auslastung <Val v={o.util} /></span>
                    </li>
                  ))}
                </ul>
                <Fact name="Fremde Netze"><Unknown text={ch.foreign.text} /></Fact>
              </li>
            ))}
          </ul>
        </SectionBox>
      ))}
      <SectionBox title="Kanalkonflikte" hint="„Möglich“ kommt nur aus dem Kanalplan; „gemessen“ ist durch Messwerte bestätigt.">
        {map.conflicts.length === 0
          ? <Unknown text={map.status === 'ready' && bands.length > 0 ? 'Keine Konflikte im Kanalplan gefunden (nur eigene Radios geprüft).' : `${DASH} keine Auswertung`} />
          : (
            <ul className="wifi-cards">
              {map.conflicts.map((c, i) => (
                <li key={i} className="wifi-card">
                  <div className="wifi-card__head">
                    <span className="wifi-card__title">{c.kind ? CONFLICT_KIND_TEXT[c.kind] ?? scrub(c.kind) : 'Konflikt'}</span>
                    <ToneBadge tone="muted">{bandLabel(c.band)}</ToneBadge>
                    <ToneBadge tone={c.status === 'measured' ? 'warn' : 'info'}>
                      {c.status ? CONFLICT_STATUS_TEXT[c.status] ?? scrub(c.status) : `${DASH} unbekannt`}
                    </ToneBadge>
                  </div>
                  <Fact name="Radios">{c.members.map(radioLabel).join(', ') || `${DASH} keine`}</Fact>
                  {c.evidence.length > 0 && (
                    <Fact name="Nachweis"><span className="wifi-mono">{c.evidence.map(scrub).join(' · ')}</span></Fact>
                  )}
                </li>
              ))}
            </ul>
          )}
      </SectionBox>
    </div>
  );
}
