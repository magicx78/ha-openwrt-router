/**
 * SecurityCenterView — Enterprise sub-tab "Security Center".
 *
 * Observes only: no blocking, no scans. Sections: Übersicht, Zeitleiste,
 * Geräte, Erkennungen, Einstellungen; one finding opens as a detail view.
 *
 * Data is loaded when the tab opens, after every action and on
 * "Aktualisieren"; there is no polling. Nothing is stored in the browser.
 * Off (409 / enabled = false) shows an explanation; only an administrator
 * gets the switch. Unknown values are shown as unknown, never as healthy.
 */

import React, { useMemo, useState } from 'react';
import configCSS from '../config/config.css?inline';
import securityCSS from './security.css?inline';
import type { SecurityApi } from './securityTypes';
import { DEFAULT_FILTERS, errorInfo, notReadyText, routerIds, type TimelineFilters } from './securityLogic.ts';
import { ErrorBox, Notice, Skeleton, useAction, useResource } from './securityUi';
import { SecurityOverview } from './SecurityOverview';
import { SecurityTimeline } from './SecurityTimeline';
import { SecurityDevices } from './SecurityDevices';
import { SecurityIncident } from './SecurityIncident';
import { SecurityDetections } from './SecurityDetections';
import { SecuritySettings } from './SecuritySettings';

type Section = 'overview' | 'timeline' | 'devices' | 'detections' | 'settings';

const SECTIONS: Array<{ id: Section; title: string }> = [
  { id: 'overview', title: 'Übersicht' },
  { id: 'timeline', title: 'Zeitleiste' },
  { id: 'devices', title: 'Geräte' },
  { id: 'detections', title: 'Erkennungen' },
  { id: 'settings', title: 'Einstellungen' },
];

// ── Off state ────────────────────────────────────────────────────────────

function OffState({ admin, api, onEnabled }: { admin: boolean; api: SecurityApi; onEnabled: () => void }) {
  const action = useAction();
  const enable = async () => {
    const ok = await action.run(async () => { await api.updateSettings({ enabled: true }); });
    if (ok) onEnabled();
  };
  return (
    <section className="cfg-section sec-off" aria-labelledby="sec-off-title">
      <div className="cfg-section__title" id="sec-off-title">Das Security Center ist ausgeschaltet</div>
      <p>
        Das Security Center wertet Daten aus, die diese Integration überwiegend ohnehin von den Routern liest
        (WLAN-Ereignisse, Konfigurationsänderungen, Geräteliste). Daraus entstehen Hinweise, zum Beispiel auf auffällig viele
        Anmeldefehler oder neue Geräte. Optional kann es Syslog-Zeilen der Router auswerten.
      </p>
      <p>
        Es beobachtet nur: keine Sperren, keine Scans, keine Änderungen an den Routern. Hinweise sind Indikatoren und
        Hypothesen, keine Beweise. Solange es aus ist, wird nichts ausgewertet und keine Bewertung berechnet.
      </p>
      {admin ? (
        <>
          <div className="sec-actions">
            <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={action.busy} onClick={() => void enable()}>
              {action.busy ? 'Schaltet ein…' : 'Security Center einschalten'}
            </button>
          </div>
          {action.error !== null && <ErrorBox error={action.error} />}
          <div className="cfg-hint">Den Log-Pfad stellen Sie danach unter „Einstellungen“ ein. Standardmäßig ist alles zurückhaltend eingestellt.</div>
        </>
      ) : (
        <Notice tone="info">Nur ein Administrator kann das Security Center einschalten.</Notice>
      )}
    </section>
  );
}

// ── Root ─────────────────────────────────────────────────────────────────

export function SecurityCenterView({ api, isAdmin }: { api: SecurityApi; isAdmin: () => boolean }) {
  const admin = isAdmin();
  const [rev, setRev] = useState(0);
  const [section, setSection] = useState<Section>('overview');
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [filters, setFilters] = useState<TimelineFilters>(DEFAULT_FILTERS);
  const base = useResource(() => api.overview(), true, rev);
  const overview = base.data;
  const now = useMemo(() => Date.now(), [base.data]);
  const refresh = () => setRev(r => r + 1);

  const kind = base.error !== null ? errorInfo(base.error).kind : null;
  const off = (overview !== null && !overview.enabled) || (overview === null && kind === 'disabled');
  const routers = overview ? routerIds(overview, null) : [];

  const body = (() => {
    if (overview === null) {
      if (base.error === null) return <Skeleton rows={5} />;
      if (kind === 'disabled') return <OffState admin={admin} api={api} onEnabled={refresh} />;
      if (kind === 'forbidden') {
        return (
          <Notice tone="warn">
            <strong>Kein Zugriff.</strong> Das Security Center ist Administratoren vorbehalten, solange die Topologie
            nicht in den Optionen der Integration für alle Benutzer freigegeben ist.
          </Notice>
        );
      }
      return <ErrorBox error={base.error} onRetry={refresh} />;
    }
    if (off) return <OffState admin={admin} api={api} onEnabled={refresh} />;
    if (incidentId !== null) {
      return (
        <SecurityIncident key={`${incidentId}-${rev}`} api={api} id={incidentId} isAdmin={admin} now={now}
          onBack={() => setIncidentId(null)} onChanged={refresh} />
      );
    }
    return (
      <>
        {!overview.active && (
          <Notice tone="warn">
            Das Security Center ist eingeschaltet, aber noch nicht aktiv. Angaben können fehlen oder unvollständig sein.
          </Notice>
        )}
        {overview.active && !overview.ready && (
          <Notice tone="warn">
            <strong>Nicht bereit.</strong> {notReadyText(overview.notReadyReason)}
          </Notice>
        )}
        {section === 'overview' && <SecurityOverview overview={overview} now={now} onOpenIncident={setIncidentId} />}
        {section === 'timeline' && (
          <SecurityTimeline api={api} base={overview} filters={filters} onFilters={setFilters} routers={routers}
            now={now} rev={rev} onOpenIncident={setIncidentId} />
        )}
        {section === 'devices' && (
          <SecurityDevices api={api} overview={overview} isAdmin={admin} now={now} onChanged={refresh}
            onShowEvents={client => { setFilters({ ...DEFAULT_FILTERS, client }); setSection('timeline'); }} />
        )}
        {section === 'detections' && <SecurityDetections api={api} now={now} rev={rev} />}
        {section === 'settings' && <SecuritySettings api={api} rev={rev} onChanged={refresh} />}
      </>
    );
  })();

  return (
    <div className="cfg sec">
      <style>{configCSS}</style>
      <style>{securityCSS}</style>
      <div className="cfg-header">
        <span className="view-title">Security Center</span>
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={base.loading}
          onClick={refresh}>
          Aktualisieren
        </button>
      </div>
      <div className="cfg-hint">
        Das Security Center beobachtet nur: es sperrt nichts und startet keine Scans. Alle Angaben sind Hinweise und
        Indikatoren, keine Beweise.
      </div>

      {overview !== null && base.error !== null && <ErrorBox error={base.error} onRetry={refresh} />}

      {overview !== null && !off && incidentId === null && (
        <nav className="sec-nav" aria-label="Bereiche des Security Centers">
          {SECTIONS.map(s => (
            <button
              key={s.id}
              type="button"
              className={`sec-nav__btn${section === s.id ? ' active' : ''}`}
              aria-current={section === s.id ? 'page' : undefined}
              onClick={() => setSection(s.id)}
            >
              {s.title}
            </button>
          ))}
        </nav>
      )}

      {body}
    </div>
  );
}
