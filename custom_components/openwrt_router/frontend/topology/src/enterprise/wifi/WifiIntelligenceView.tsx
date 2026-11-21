/**
 * WifiIntelligenceView — Enterprise sub-tab "WiFi Intelligence".
 *
 * Sections: Übersicht, Radios, Kanalkarte, RF-Zeitverlauf, Roaming,
 * Empfehlungen. Each section loads its own route while it is shown, at most
 * every 60 s and only while the page is visible; "Aktualisieren" reloads at
 * once. Each section sits in its own error boundary, so one failing view
 * never takes the panel down. Off shows how to switch RF on; the module only
 * observes and recommends and has no switch or apply button.
 */

import React, { useState } from 'react';
import configCSS from '../config/config.css?inline';
import wifiCSS from './wifi.css?inline';
import type { WifiApi } from './wifiTypes';
import { NOT_A_SPECTRUM_ANALYZER, SECTIONS, TAB_TITLE, errorInfo, statusView, type SectionId } from './wifiLogic.ts';
import { Loaded, Notice, SectionBoundary, ToneBadge, usePolled } from './wifiUi';
import { OffNotice, WifiOverview } from './WifiOverview';
import { WifiRadios } from './WifiRadios';
import { WifiChannelMap } from './WifiChannelMap';
import { WifiTimeline } from './WifiTimeline';
import { WifiRoaming } from './WifiRoaming';
import { WifiRecommendations } from './WifiRecommendations';

function RadiosSection({ api, rev }: { api: WifiApi; rev: number }) {
  const res = usePolled(() => api.radios(), rev);
  return <Loaded res={res}>{v => <WifiRadios view={v} />}</Loaded>;
}

function ChannelsSection({ api, rev }: { api: WifiApi; rev: number }) {
  const map = usePolled(() => api.channelMap(), rev);
  const radios = usePolled(() => api.radios(), rev);
  return <Loaded res={map}>{m => <WifiChannelMap map={m} radios={radios.data} />}</Loaded>;
}

function RecommendationsSection({ api, rev }: { api: WifiApi; rev: number }) {
  const res = usePolled(() => api.recommendations(), rev);
  return <Loaded res={res}>{d => <WifiRecommendations data={d} />}</Loaded>;
}

export function WifiIntelligenceView({ api, isAdmin }: { api: WifiApi; isAdmin: () => boolean }) {
  const admin = isAdmin();
  const [rev, setRev] = useState(0);
  const [section, setSection] = useState<SectionId>('overview');
  const overview = usePolled(() => api.overview(), rev);
  const o = overview.data;
  const st = o ? statusView(o.status, o.reasons) : null;
  const off = o?.status === 'off';
  const forbidden = o === null && overview.error !== null && errorInfo(overview.error).kind === 'forbidden';
  const title = SECTIONS.find(s => s.id === section)?.title ?? '';

  const body = (() => {
    if (o === null) return <Loaded res={overview}>{() => null}</Loaded>;
    if (off) return <OffNotice />;
    switch (section) {
      case 'overview': return <WifiOverview overview={o} />;
      case 'radios': return <RadiosSection api={api} rev={rev} />;
      case 'channels': return <ChannelsSection api={api} rev={rev} />;
      case 'timeline': return <WifiTimeline api={api} rev={rev} />;
      case 'roaming': return <WifiRoaming api={api} admin={admin} rev={rev} />;
      case 'recommendations': return <RecommendationsSection api={api} rev={rev} />;
      default: return null;
    }
  })();

  return (
    <div className="cfg wifi">
      <style>{configCSS}</style>
      <style>{wifiCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        {st && <ToneBadge tone={st.tone}>{st.label}</ToneBadge>}
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={overview.loading}
          onClick={() => setRev(r => r + 1)}>
          Aktualisieren
        </button>
      </div>
      <div className="cfg-hint">
        WLAN-Funkanalyse der Router: Auslastung, Rauschen, Wiederholungen, Kanäle, Roaming und Empfehlungen. Hinweis:{' '}
        {NOT_A_SPECTRUM_ANALYZER}. Was nicht gemessen wurde, steht als „—“ mit Grund da, nie als 0 und nie grün.
      </div>
      {forbidden && <Notice tone="warn"><strong>Admin nötig.</strong> WiFi Intelligence ist Administratoren vorbehalten, solange die Topologie nicht in den Integrationsoptionen für alle Benutzer freigegeben ist.</Notice>}
      {o !== null && !off && (
        <nav className="wifi-nav" aria-label="Bereiche von WiFi Intelligence">
          {SECTIONS.map(s => (
            <button key={s.id} type="button" className={`wifi-nav__btn${section === s.id ? ' active' : ''}`}
              aria-current={section === s.id ? 'page' : undefined} onClick={() => setSection(s.id)}>
              {s.title}
            </button>
          ))}
        </nav>
      )}
      {!forbidden && <SectionBoundary key={section} title={title}>{body}</SectionBoundary>}
    </div>
  );
}
