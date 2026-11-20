/**
 * SecurityDevices — trust level per device. Administrators can confirm a
 * device and give it a name; everyone else sees the server's pseudonyms
 * (`cli_…`, `ipa_…`, `hst_…`) unchanged and gets no write buttons.
 *
 * Trust states are the backend's: "Mehrere Indikatoren" is a hypothesis, not
 * a verdict. The Security Center only observes: there is no block action.
 */

import React, { useState } from 'react';
import type { Device, Overview, SecurityApi } from './securityTypes';
import {
  INDICATOR_LABEL,
  NAME_MAX,
  TRUST_HELP,
  TRUST_LABEL,
  TRUST_TONE,
  devicesObserved,
  formatRelativeTs,
  formatTs,
  isRealMac,
  label,
  sanitizeName,
  sortDevices,
} from './securityLogic.ts';
import { ErrorBox, Notice, SectionBox, ToneBadge, Unknown, useAction } from './securityUi';

type Edit = { id: string; mode: 'confirm' | 'name'; value: string } | null;

function deviceTitle(d: Device): string {
  if (d.name) return d.name;
  if (d.hostname) return d.hostname;
  return d.nameSet ? 'Name vergeben (nur für Administratoren sichtbar)' : 'Ohne Namen';
}

function CountsBar({ overview }: { overview: Overview }) {
  const c = overview.deviceCounts;
  const items: Array<[string, number | null]> = [
    ['known', c.known], ['new', c.new], ['unrecognized', c.unrecognized], ['suspicious', c.suspicious], ['quarantined', c.quarantined],
  ];
  return (
    <div className="sec-chips" aria-label="Anzahl je Vertrauensstufe">
      {items.map(([state, n]) => (
        <ToneBadge key={state} tone={n === null ? 'muted' : TRUST_TONE[state]}>
          {label(TRUST_LABEL, state)}: {n === null ? 'unbekannt' : n}
        </ToneBadge>
      ))}
    </div>
  );
}

export function SecurityDevices({ api, overview, isAdmin, now, onChanged, onShowEvents }: {
  api: SecurityApi;
  overview: Overview;
  isAdmin: boolean;
  now: number;
  onChanged: () => void;
  onShowEvents: (client: string) => void;
}) {
  const [edit, setEdit] = useState<Edit>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const action = useAction();
  const devices = sortDevices(overview.devices);
  const observed = devicesObserved(overview.coverage);
  // Writing needs a real MAC, which the server only sends in the admin view.
  const canEdit = isAdmin && overview.adminView;

  const submit = async () => {
    if (!edit) return;
    const raw = edit.value.trim();
    const name = raw === '' ? null : sanitizeName(raw);
    if (raw !== '' && name === null) {
      setNameError(`Der Name darf höchstens ${NAME_MAX} Zeichen lang sein und keine Steuerzeichen enthalten.`);
      return;
    }
    setNameError(null);
    const ok = await action.run(async () => {
      if (edit.mode === 'confirm') await api.confirmDevice(edit.id, name ?? undefined);
      else await api.setDeviceName(edit.id, name);
    });
    if (ok) {
      setEdit(null);
      onChanged();
    }
  };

  return (
    <div className="cfg-stack">
      <SectionBox
        title="Vertrauensstufen"
        hint="Die Stufe sagt, wie gut ein Gerät bekannt ist. Sie ist eine Einordnung, kein Urteil. Das Security Center beobachtet nur und sperrt kein Gerät."
      >
        <CountsBar overview={overview} />
      </SectionBox>

      {!observed && (
        <Notice tone="warn">
          Zurzeit liefert keine Datenquelle die Geräteliste (WLAN-Clients oder Geräteverlauf). Die Angaben unten können veraltet sein.
        </Notice>
      )}
      {!isAdmin && (
        <Notice tone="info">
          Aus Datenschutzgründen sehen Sie Pseudonyme (<span className="diag-mono">cli_…</span>) statt MAC-, IP-Adressen und Namen.
          Bestätigen und Benennen kann nur ein Administrator.
        </Notice>
      )}
      {isAdmin && !overview.adminView && (
        <Notice tone="warn">
          Die Klartext-Ansicht ist gerade nicht verfügbar (Prüfung des Administrators nicht möglich). Bestätigen und Benennen sind deshalb gesperrt.
        </Notice>
      )}

      {devices.length === 0 ? (
        <div className="cfg-empty">
          {observed ? 'Noch keine Geräte erfasst.' : 'Keine Geräte bekannt: die Geräteliste wird zurzeit nicht beobachtet.'}
        </div>
      ) : (
        <ul className="sec-rows" aria-label="Geräte">
          {devices.map((d, idx) => {
            const key = d.mac ?? `idx-${idx}`;
            const editable = canEdit && isRealMac(d.mac);
            const mac = d.mac;
            const editing = edit !== null && mac !== null && edit.id === mac ? edit : null;
            const state = d.state;
            const filterable = mac !== null && (isRealMac(mac) || mac.startsWith('cli_'));
            return (
              <li key={key} className="sec-row sec-row--device">
                <div className="sec-row__main">
                  <ToneBadge tone={state ? (TRUST_TONE[state] ?? 'muted') : 'muted'}>
                    {state ? label(TRUST_LABEL, state) : 'Unbekannt'}
                  </ToneBadge>
                  <span className="sec-row__title">{deviceTitle(d)}</span>
                </div>
                <div className="sec-row__meta">
                  <span className="diag-mono sec-ident">{d.mac ?? 'MAC unbekannt'}</span>
                  <span className="diag-mono sec-ident">{d.ip ?? 'IP unbekannt'}</span>
                  {d.hostname && d.name && <span className="diag-mono sec-ident">{d.hostname}</span>}
                  <span title={formatTs(d.lastSeen)}>zuletzt {d.lastSeen === null ? <Unknown /> : formatRelativeTs(d.lastSeen, now)}</span>
                  {d.privateMac && <ToneBadge tone="info">Private MAC-Adresse</ToneBadge>}
                  {!d.observed && <ToneBadge tone="muted">Derzeit nicht beobachtet</ToneBadge>}
                </div>
                {state && TRUST_HELP[state] && <div className="cfg-hint">{TRUST_HELP[state]}</div>}
                {d.indicators.length > 0 && (
                  <div className="sec-chips" aria-label="Indikatoren der letzten 24 Stunden">
                    <span className="cfg-hint">Indikatoren (24 h):</span>
                    {d.indicators.map(k => <ToneBadge key={k} tone="warn">{label(INDICATOR_LABEL, k)}</ToneBadge>)}
                  </div>
                )}

                {editing ? (
                  <form
                    className="sec-edit"
                    onSubmit={e => { e.preventDefault(); void submit(); }}
                  >
                    <label className="sec-field">
                      <span>{editing.mode === 'confirm' ? 'Gerät bestätigen, Name (optional)' : 'Name (leer = Namen entfernen)'}</span>
                      <input
                        type="text"
                        value={editing.value}
                        maxLength={NAME_MAX + 8}
                        autoComplete="off"
                        onChange={e => setEdit({ ...editing, value: e.target.value })}
                      />
                    </label>
                    <div className="sec-actions">
                      <button type="submit" className="diag-btn diag-btn--primary cfg-btn" disabled={action.busy}>
                        {editing.mode === 'confirm' ? 'Bestätigen' : 'Speichern'}
                      </button>
                      <button type="button" className="diag-btn cfg-btn" disabled={action.busy}
                        onClick={() => { setEdit(null); setNameError(null); action.clear(); }}>
                        Abbrechen
                      </button>
                    </div>
                    {nameError && <div className="cfg-notice cfg-notice--error" role="alert">{nameError}</div>}
                    {action.error !== null && <ErrorBox error={action.error} />}
                  </form>
                ) : (
                  <div className="sec-actions">
                    {editable && !d.confirmed && state !== 'known' && (
                      <button type="button" className="diag-btn cfg-btn"
                        onClick={() => { setEdit({ id: mac!, mode: 'confirm', value: d.name ?? '' }); setNameError(null); action.clear(); }}>
                        Als bekannt bestätigen
                      </button>
                    )}
                    {editable && (
                      <button type="button" className="diag-btn cfg-btn"
                        onClick={() => { setEdit({ id: mac!, mode: 'name', value: d.name ?? '' }); setNameError(null); action.clear(); }}>
                        Benennen
                      </button>
                    )}
                    {filterable && (
                      <button type="button" className="diag-btn cfg-btn" onClick={() => onShowEvents(mac!)}>
                        Ereignisse zeigen
                      </button>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
