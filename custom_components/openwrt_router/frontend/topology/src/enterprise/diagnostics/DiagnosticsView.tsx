/**
 * DiagnosticsView — Enterprise sub-tab "Netzwerkdiagnose" (Network Diagnostics).
 *
 * Sections: Übersicht (score, coverage, findings, chain per point), Verlauf
 * (windows per series), and for administrators only Manuelle Diagnose and
 * Einstellungen. Non-admins get neither the sections nor their controls.
 *
 * Data is loaded when the tab opens, after every action and on
 * "Aktualisieren"; there is no polling. Nothing is stored in the browser.
 * Off (module state "off" / 409) shows an explanation, never an empty healthy
 * page; only an administrator gets the switch. Unknown values are shown as
 * unknown, never as healthy.
 */

import React, { useMemo, useState } from 'react';
import configCSS from '../config/config.css?inline';
import diagnosticsCSS from './diagnostics.css?inline';
import type { DiagApi } from './diagnosticsTypes';
import { TAB_TITLE, controlsFor, errorInfo, moduleView, type SectionId } from './diagnosticsLogic.ts';
import { ErrorBox, Notice, Skeleton, ToneBadge, useAction, useResource } from './diagUi';
import { DiagOverview } from './DiagOverview';
import { DiagHistory } from './DiagHistory';
import { DiagRun } from './DiagRun';
import { DiagSettings } from './DiagSettings';

// ── Off state ────────────────────────────────────────────────────────────

function OffState({ admin, api, onEnabled }: { admin: boolean; api: DiagApi; onEnabled: () => void }) {
  const action = useAction();
  const enable = async () => {
    const ok = await action.run(async () => { await api.updateSettings({ enabled: true }); });
    if (ok) onEnabled();
  };
  return (
    <section className="cfg-section" aria-labelledby="dg-off-title">
      <div className="cfg-section__title" id="dg-off-title">Die Netzwerkdiagnose ist ausgeschaltet</div>
      <p className="dg-p">
        Sie prüft die Kette Router, Gateway, WAN, Internet und DNS. Dazu liest sie Daten, die die Router ohnehin liefern,
        und misst von Home Assistant aus bestätigte Ziele. Solange sie aus ist, wird nichts gemessen und kein Wert berechnet:
        es gibt hier weder einen Qualitätswert noch eine Aussage über den Zustand des Netzes.
      </p>
      {admin ? (
        <>
          <div className="dg-actions">
            <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={action.busy} onClick={() => void enable()}>
              {action.busy ? 'Schaltet ein…' : 'Netzwerkdiagnose einschalten'}
            </button>
          </div>
          {action.error !== null && <ErrorBox error={action.error} />}
          <div className="cfg-hint">Messziele und Intervall stellen Sie danach unter „Einstellungen“ ein. Anfangs ist nichts davon aktiv.</div>
        </>
      ) : (
        <Notice tone="info">Nur ein Administrator kann die Netzwerkdiagnose einschalten.</Notice>
      )}
    </section>
  );
}

// ── Root ─────────────────────────────────────────────────────────────────

export function DiagnosticsView({ api, isAdmin }: { api: DiagApi; isAdmin: () => boolean }) {
  const controls = controlsFor(isAdmin());
  const admin = controls.run;
  const [rev, setRev] = useState(0);
  const [requested, setRequested] = useState<SectionId>('overview');
  const base = useResource(() => api.overview(), true, rev);
  const overview = base.data;
  const nowMs = useMemo(() => Date.now(), [base.data]);
  const refresh = () => setRev(r => r + 1);

  // a section the user may not see (e.g. admin rights ended) falls back to the overview
  const section: SectionId = controls.sections.some(s => s.id === requested) ? requested : 'overview';
  const kind = base.error !== null ? errorInfo(base.error).kind : null;
  const off = (overview !== null && overview.state === 'off') || (overview === null && kind === 'disabled');
  const module = overview ? moduleView(overview.state, overview.reasons) : null;

  const body = (() => {
    if (overview === null) {
      if (base.error === null) return <Skeleton rows={5} />;
      if (kind === 'disabled') return <OffState admin={admin} api={api} onEnabled={refresh} />;
      if (kind === 'forbidden') {
        return (
          <Notice tone="warn">
            <strong>Kein Zugriff.</strong> Die Netzwerkdiagnose ist Administratoren vorbehalten, solange die Topologie
            nicht in den Optionen der Integration für alle Benutzer freigegeben ist.
          </Notice>
        );
      }
      return <ErrorBox error={base.error} onRetry={refresh} />;
    }
    if (off) return <OffState admin={admin} api={api} onEnabled={refresh} />;
    return (
      <>
        {overview.state === 'not_ready' && module && (
          <Notice tone="warn">
            <strong>Nicht bereit.</strong>{' '}
            {module.reasons.length > 0 ? module.reasons.join(' · ') : 'Der Grund ist nicht bekannt.'} Angaben können fehlen.
          </Notice>
        )}
        {overview.state === null && (
          <Notice tone="warn">Der Zustand der Netzwerkdiagnose ist unbekannt. Angaben können fehlen oder unvollständig sein.</Notice>
        )}
        {section === 'overview' && <DiagOverview overview={overview} nowMs={nowMs} />}
        {section === 'history' && <DiagHistory api={api} rev={rev} />}
        {section === 'run' && controls.run && <DiagRun api={api} rev={rev} onDone={refresh} />}
        {section === 'settings' && controls.settings && <DiagSettings api={api} rev={rev} onChanged={refresh} />}
      </>
    );
  })();

  return (
    <div className="cfg dg">
      <style>{configCSS}</style>
      <style>{diagnosticsCSS}</style>
      <div className="cfg-header">
        <span className="view-title">{TAB_TITLE}</span>
        {module && <ToneBadge tone={module.tone}>{module.label}</ToneBadge>}
        <button type="button" className="diag-btn cfg-btn cfg-header__refresh" disabled={base.loading}
          onClick={refresh}>
          Aktualisieren
        </button>
      </div>
      <div className="cfg-hint">
        Die Netzwerkdiagnose zeigt, an welcher Stelle der Kette Router, Gateway, WAN, Internet und DNS ein Problem liegen kann.
        Was nicht gemessen wurde, ist grau und „unbekannt“ – nie grün.
      </div>

      {overview !== null && base.error !== null && <ErrorBox error={base.error} onRetry={refresh} />}

      {overview !== null && !off && (
        <nav className="dg-nav" aria-label="Bereiche der Netzwerkdiagnose">
          {controls.sections.map(s => (
            <button key={s.id} type="button" className={`dg-nav__btn${section === s.id ? ' active' : ''}`}
              aria-current={section === s.id ? 'page' : undefined} onClick={() => setRequested(s.id)}>
              {s.title}
            </button>
          ))}
        </nav>
      )}

      {body}
    </div>
  );
}
