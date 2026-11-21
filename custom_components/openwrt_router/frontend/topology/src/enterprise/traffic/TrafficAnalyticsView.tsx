/**
 * TrafficAnalyticsView — Enterprise sub-tab "Traffic Analytics".
 *
 * Sections: Übersicht, Verlauf, Top Talkers, Clients & VLANs, Anomalien,
 * Kapazität and (administrators) Flows. The component is mounted only
 * while its tab is shown; each section loads its own route while it is
 * shown, at most every 60 s and only while the page is visible;
 * "Aktualisieren" reloads at once. Each section sits in its own error
 * boundary. Off shows a notice and loads nothing else.
 */

import React, { useState } from 'react';
import configCSS from '../config/config.css?inline';
import wifiCSS from '../wifi/wifi.css?inline';
import trafficCSS from './traffic.css?inline';
import type { TrafficApi } from './trafficTypes';
import { SECTIONS, TAB_TITLE, UNKNOWN_RULE, errorInfo, sectionsFor, statusView, type SectionId } from './trafficLogic.ts';
import { Loaded, Notice, SectionBoundary, ShownBadge, usePolled } from './trafficUi';
import { OffNotice, TrafficOverview } from './TrafficOverview';
import { TrafficHistory } from './TrafficHistory';
import { TrafficTalkers } from './TrafficTalkers';
import { TrafficClients } from './TrafficClients';
import { TrafficAnomalies } from './TrafficAnomalies';
import { TrafficCapacity } from './TrafficCapacity';
import { TrafficFlows } from './TrafficFlows';

export function TrafficAnalyticsView({ api, isAdmin }: { api: TrafficApi; isAdmin: () => boolean }) {
  const admin = isAdmin();
  const [rev, setRev] = useState(0);
  const [section, setSection] = useState<SectionId>('overview');
  const overview = usePolled(() => api.overview(), rev);
  const o = overview.data;
  const st = o ? statusView(o.status, o.reasons) : null;
  const off = o?.status === 'off';
  const forbidden = o === null && overview.error !== null && errorInfo(overview.error).kind === 'forbidden';
  const sections = sectionsFor(admin);
  const current = sections.some(s => s.id === section) ? section : 'overview';
  const title = SECTIONS.find(s => s.id === current)?.title ?? '';

  const body = (() => {
    if (o === null) return <Loaded res={overview}>{() => null}</Loaded>;
    if (off) return <OffNotice />;
    switch (current) {
      case 'overview': return <TrafficOverview overview={o} />;
      case 'history': return <TrafficHistory api={api} rev={rev} />;
      case 'talkers': return <TrafficTalkers api={api} rev={rev} />;
      case 'clients': return <TrafficClients api={api} rev={rev} />;
      case 'anomalies': return <TrafficAnomalies api={api} rev={rev} />;
      case 'capacity': return <TrafficCapacity api={api} rev={rev} />;
      case 'flows': return <TrafficFlows api={api} rev={rev} />;
      default: return null;
    }
  })();

  return (
    <div className="cfg wifi trf">
      <style>{configCSS}</style>
      <style>{wifiCSS}</style>
      <style>{trafficCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        {st && <ShownBadge shown={st} />}
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={overview.loading}
          onClick={() => setRev(r => r + 1)}>
          Aktualisieren
        </button>
      </div>
      <div className="cfg-hint">
        Verkehr der Router: WAN, Schnittstellen, Clients, VLANs, Spitzen, Anomalien und Kapazität. Nur Beobachtung, keine
        Änderung am Router. {UNKNOWN_RULE}
      </div>
      {forbidden && <Notice tone="warn"><strong>Admin nötig.</strong> Traffic Analytics ist Administratoren vorbehalten, solange die Topologie nicht in den Integrationsoptionen für alle Benutzer freigegeben ist.</Notice>}
      {o !== null && !off && (
        <nav className="wifi-nav" aria-label="Bereiche von Traffic Analytics">
          {sections.map(s => (
            <button key={s.id} type="button" className={`wifi-nav__btn${current === s.id ? ' active' : ''}`}
              aria-current={current === s.id ? 'page' : undefined} onClick={() => setSection(s.id)}>
              {s.title}
            </button>
          ))}
        </nav>
      )}
      {!forbidden && <SectionBoundary key={current} title={title}>{body}</SectionBoundary>}
    </div>
  );
}
