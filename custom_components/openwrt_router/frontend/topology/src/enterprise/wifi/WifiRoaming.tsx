/**
 * WifiRoaming — roaming problems as counts for every reader (from the
 * radios route, no sensitive read). The client roaming history is a
 * sensitive read: only an administrator can open it, and only after an
 * explicit approval in a dialog (the Configuration Manager's modal and tick
 * pattern, reused). The approval request is the one GET of the roaming
 * route: the backend asks the Enterprise Core guard once per HA login and
 * audits it. A 403 ends in "Admin nötig". Clients appear as pseudonyms only.
 */

import React, { useEffect, useReducer, useState } from 'react';
import type { RadiosView, Roaming, WifiApi } from './wifiTypes';
import {
  APPROVAL_INIT, DASH, approvalReduce, countText, errorInfo, fmtNum, formatTs, mayLoadDetails, radioLabel,
  reasonText, roamingSummary, scrub, type ApprovalState, type SumView,
} from './wifiLogic.ts';
import { ConfigModal } from '../config/ConfigApprovalDialog';
import { ErrorBox, Fact, Loaded, Notice, SectionBox, Spinner, Unknown, usePolled } from './wifiUi';
import { NotReadyNotice, OffNotice } from './WifiOverview';

function Sum({ name, v }: { name: string; v: SumView }) {
  return (
    <Fact name={name}>
      {v.text.startsWith(DASH) ? <Unknown text={v.text} /> : v.text}
      {v.partial && <span className="wifi-muted"> (mindestens; nicht jedes Radio liefert den Wert)</span>}
    </Fact>
  );
}

export interface RoamingViewProps {
  radios: RadiosView;
  admin: boolean;
  approval: ApprovalState;
  roaming: Roaming | null;
  onOpen: () => void;
  onAck: (value: boolean) => void;
  onCancel: () => void;
  onSubmit: () => void;
}

function Details({ roaming }: { roaming: Roaming }) {
  if (roaming.events === null) {
    return <Unknown text={`${DASH} keine Historie (${roaming.eventsRestricted === 'admin_only' ? 'nur für Administratoren' : 'Modul nicht bereit'})`} />;
  }
  if (roaming.events.length === 0) return <Unknown text="Keine Roaming-Wechsel gespeichert." />;
  return (
    <ul className="wifi-rows">
      {roaming.events.map((e, i) => (
        <li key={i} className="wifi-row">
          <span className="wifi-row__title wifi-mono">{e.clientRef ? scrub(e.clientRef) : `${DASH} ohne Kennung`}</span>
          <span>{e.from ? radioLabel(e.from) : `${DASH} unbekannt`} → {e.to ? radioLabel(e.to) : `${DASH} unbekannt`}</span>
          <span>{formatTs(e.at)}</span>
          <span>Lücke {e.gapS === null ? `${DASH} unbekannt` : `${fmtNum(e.gapS, 1)} s`}</span>
        </li>
      ))}
    </ul>
  );
}

export function WifiRoamingView({ radios, admin, approval, roaming, onOpen, onAck, onCancel, onSubmit }: RoamingViewProps) {
  if (radios.status === 'off') return <OffNotice />;
  const sum = roamingSummary(radios);
  const step = approval.step;
  return (
    <div className="cfg-stack">
      {radios.status === 'not_ready' && <NotReadyNotice reasons={radios.reasons.map(reasonText)} />}
      <SectionBox title="Probleme (Anzahl)" hint="Zählungen über alle Radios; einzelne Clients erscheinen hier nicht.">
        <Sum name="Roaming-Wechsel (letzte Stunde)" v={sum.roams} />
        <Sum name="Clients mit Problemen" v={sum.problemClients} />
        <Sum name="Auffällige Clients" v={sum.flagged} />
        <Sum name="Dauerhaft schwaches Signal" v={sum.weak} />
      </SectionBox>
      <SectionBox title="Je Radio">
        {radios.radios.length === 0
          ? <Unknown text={`${DASH} noch kein Radio ausgewertet`} />
          : (
            <ul className="wifi-rows">
              {radios.radios.map(r => (
                <li key={`${r.routerId}/${r.radioId}`} className="wifi-row">
                  <span className="wifi-row__title">{radioLabel(r)}</span>
                  <span>Wechsel {countText(r.roams1h)}</span>
                  <span>Problem-Clients {countText(r.clients.problem)}</span>
                </li>
              ))}
            </ul>
          )}
      </SectionBox>
      <SectionBox title="Roaming-Historie der Clients" hint="Welcher Client wann von welchem Radio zu welchem gewechselt ist; Clients nur als Pseudonym.">
        {!admin && <Notice tone="info">Die Historie ist nur für Administratoren sichtbar, nach einer Freigabe je Sitzung.</Notice>}
        {admin && (step === 'idle' || step === 'confirm') && (
          <div className="wifi-actions">
            <button type="button" className="diag-btn cfg-btn" onClick={onOpen}>Roaming-Details freigeben …</button>
          </div>
        )}
        {admin && step === 'loading' && <Spinner text="Freigabe wird geprüft …" />}
        {admin && step === 'approved' && roaming && <Details roaming={roaming} />}
        {admin && (step === 'refused' || step === 'failed') && (
          <>
            <ErrorBox error={approval.error} />
            <div className="wifi-actions">
              <button type="button" className="diag-btn cfg-btn" onClick={onOpen}>
                {step === 'refused' ? 'Erneut freigeben …' : 'Erneut versuchen …'}
              </button>
            </div>
          </>
        )}
      </SectionBox>
      {admin && step === 'confirm' && (
        <ConfigModal title="Roaming-Historie freigeben" onClose={onCancel}>
          <div className="cfg-stack">
            <p className="wifi-p">
              Die Historie zeigt für diese Sitzung, welcher Client (als Pseudonym) wann zwischen den Radios gewechselt ist. Das ist
              ein sensibler Lesezugriff: der Enterprise Core prüft und protokolliert die Freigabe einmal je Anmeldung.
              Am WLAN wird nichts geändert.
            </p>
            <label className="diag-check cfg-confirm">
              <input type="checkbox" checked={approval.ack} onChange={e => onAck(e.target.checked)} />
              Ich gebe die Roaming-Historie für diese Sitzung frei.
            </label>
            <div className="wifi-actions">
              <button type="button" className="diag-btn diag-btn--primary cfg-btn" disabled={!approval.ack} onClick={onSubmit}>Freigeben und anzeigen</button>
              <button type="button" className="diag-btn cfg-btn" onClick={onCancel}>Abbrechen</button>
            </div>
          </div>
        </ConfigModal>
      )}
    </div>
  );
}

/** Panel session memory (page lifetime only, never in browser storage). */
let sessionApproved = false;

export function WifiRoaming({ api, admin, rev }: { api: WifiApi; admin: boolean; rev: number }) {
  const radios = usePolled(() => api.radios(), rev);
  const [approval, dispatch] = useReducer(approvalReduce, undefined,
    () => (admin && sessionApproved ? { step: 'loading', ack: true, error: null } as ApprovalState : APPROVAL_INIT));
  const [roaming, setRoaming] = useState<Roaming | null>(null);
  const load = mayLoadDetails(admin, approval);

  // The details are loaded once per approval and on "Aktualisieren", not polled.
  useEffect(() => {
    if (!load) return;
    let cancelled = false;
    api.roaming().then(
      r => {
        if (cancelled) return;
        sessionApproved = true;
        setRoaming(r);
        dispatch({ type: 'loaded' });
      },
      e => {
        if (cancelled) return;
        if (errorInfo(e).kind === 'forbidden') sessionApproved = false;
        setRoaming(null);
        dispatch({ type: 'failed', error: e });
      },
    );
    return () => { cancelled = true; };
  }, [load, rev, api]);

  return (
    <Loaded res={radios}>
      {view => (
        <WifiRoamingView radios={view} admin={admin} approval={approval} roaming={roaming}
          onOpen={() => dispatch({ type: 'open' })}
          onAck={value => dispatch({ type: 'ack', value })}
          onCancel={() => dispatch({ type: 'cancel' })}
          onSubmit={() => dispatch({ type: 'submit' })} />
      )}
    </Loaded>
  );
}
