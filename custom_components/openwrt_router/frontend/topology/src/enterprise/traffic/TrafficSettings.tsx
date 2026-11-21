/**
 * TrafficSettings — "Einstellungen" (administrators only; the section is not
 * offered to anyone else, and the routes answer 403 to them anyway).
 *
 * Read only: which routers have Traffic Analytics on and their history
 * profile (router options of the options flow). Editable, over
 * POST /settings: the external collector (on/off and its non-admin user,
 * chosen from GET /collector/users, which names users only by display name
 * and a per-run reference) and the clients that get client sensors (at most
 * 20, chosen from /clients, pseudonyms only).
 *
 * Only changed keys are sent. The form keeps its draft apart from what the
 * server stored: "Gespeichert" appears only after the route answered 200,
 * and the shown values are then the server's answer. A refused save says
 * why and keeps the draft.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { ClientList, CollectorUsers, SettingsDraft, SettingsView, TrafficApi } from './trafficTypes';
import {
  buildSettingsUpdate, clientLabel, routerName, settingsDraft, settingsErrorText, toggleClientSensor, userLabel,
} from './trafficLogic.ts';
import { ErrorBox, Fact, Notice, SectionBox, Unknown } from './trafficUi';

interface Loaded {
  view: SettingsView | null;
  users: CollectorUsers | null;
  clients: ClientList | null;
  error: unknown;
  usersError: unknown;
  clientsError: unknown;
}

const PROFILE_TEXT: Record<string, string> = {
  compact: 'compact (Standard)',
  standard: 'standard',
};

function useSettingsData(api: TrafficApi, rev: number): Loaded & { reload: () => void; setView: (v: SettingsView) => void; setUsers: (u: CollectorUsers) => void } {
  const [state, setState] = useState<Loaded>({ view: null, users: null, clients: null, error: null, usersError: null, clientsError: null });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let cancelled = false;
    const settle = <T,>(p: Promise<T>) => p.then(v => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e }));
    void Promise.all([settle(api.settings()), settle(api.collectorUsers()), settle(api.clients())]).then(([s, u, c]) => {
      if (cancelled) return;
      setState(prev => ({
        view: s.ok ? s.v : prev.view,
        users: u.ok ? u.v : prev.users,
        clients: c.ok ? c.v : prev.clients,
        error: s.ok ? null : s.e,
        usersError: u.ok ? null : u.e,
        clientsError: c.ok ? null : c.e,
      }));
    });
    return () => { cancelled = true; };
  }, [api, rev, tick]);
  const reload = useCallback(() => setTick(t => t + 1), []);
  const setView = useCallback((v: SettingsView) => setState(prev => ({ ...prev, view: v, error: null })), []);
  const setUsers = useCallback((u: CollectorUsers) => setState(prev => ({ ...prev, users: u, usersError: null })), []);
  return { ...state, reload, setView, setUsers };
}

export function SettingsForm({ view, users, clients, usersError, clientsError, onSave, onReload }: {
  view: SettingsView;
  users: CollectorUsers | null;
  clients: ClientList | null;
  usersError?: unknown;
  clientsError?: unknown;
  /** Resolves with the stored settings, rejects with the route's error. */
  onSave: (update: ReturnType<typeof buildSettingsUpdate>['update']) => Promise<void>;
  onReload?: () => void;
}) {
  const [draft, setDraft] = useState<SettingsDraft>(() => settingsDraft(view, users));
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  const built = buildSettingsUpdate(view, users, draft);
  const dirty = Object.keys(built.update).length > 0;

  // A fresh server state replaces the draft unless the admin is editing.
  useEffect(() => {
    if (!dirty) setDraft(settingsDraft(view, users));
  }, [view, users]);

  const patch = (next: SettingsDraft) => { setDraft(next); setSaved(false); setFailure(null); };

  const save = async () => {
    if (built.error) { setFailure(built.error); return; }
    if (!dirty || busy) return;
    setBusy(true);
    setFailure(null);
    setSaved(false);
    try {
      await onSave(built.update);
      if (alive.current) setSaved(true);
    } catch (err) {
      if (alive.current) setFailure(settingsErrorText(err));
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const max = view.clientSensorsMax;
  const listed = clients?.clients ?? [];
  const listedRefs = new Set(listed.map(c => c.clientRef));
  const missing = draft.clientSensors.filter(r => !listedRefs.has(r));
  const full = draft.clientSensors.length >= max;
  const locked = busy || !view.writable;

  return (
    <form className="trf-form" onSubmit={e => { e.preventDefault(); void save(); }}>
      {!view.writable && (
        <Notice tone="info">
          Speichern geht erst, wenn Traffic Analytics an mindestens einem Router läuft.
        </Notice>
      )}

      <SectionBox title="Externer Collector">
        <label className="trf-check">
          <input type="checkbox" checked={draft.collectorEnabled} disabled={locked}
            onChange={e => patch({ ...draft, collectorEnabled: e.target.checked })} />
          <span>
            Collector-Eingang einschalten. Ein externer Collector darf dann Flow-Daten an Home Assistant schicken
            (nur HTTPS, nur der gewählte Benutzer mit einem langlebigen Zugangstoken). Home Assistant ruft selbst
            keinen Collector auf.
          </span>
        </label>
        <label className="trf-field">
          <span>Benutzer des Collectors (ohne Admin-Rechte)</span>
          <select value={draft.userRef} disabled={locked || users === null}
            onChange={e => patch({ ...draft, userRef: e.target.value })}>
            <option value="">{view.collector.userConfigured ? '— eingetragener Benutzer bleibt —' : '— bitte wählen —'}</option>
            {(users?.users ?? []).map(u => <option key={u.userRef} value={u.userRef}>{userLabel(u)}</option>)}
          </select>
        </label>
        {usersError !== null && usersError !== undefined && <ErrorBox error={usersError} onRetry={onReload} />}
        {users !== null && users.users.length === 0 && (
          <Notice tone="warn">
            Es gibt keinen wählbaren Benutzer. Legen Sie in Home Assistant einen eigenen Benutzer ohne Admin-Rechte an und
            erzeugen Sie für ihn ein langlebiges Zugangstoken.
          </Notice>
        )}
        {users !== null && users.userConfigured && !users.selectedListed && (
          <Notice tone="warn">Der eingetragene Benutzer ist nicht mehr wählbar (gelöscht, deaktiviert oder Admin). Der Collector wird abgewiesen.</Notice>
        )}
        <Fact name="Schema">{view.collector.schema ?? <Unknown text="—" />}</Fact>
        <Fact name="Pfad">{view.collector.path ?? <Unknown text="—" />}</Fact>
        <div className="cfg-hint">Der Collector schickt nur Flows (Schema traffic.collector.v1). Zusammengefasste Werte werden abgelehnt.</div>
      </SectionBox>

      <SectionBox title={`Client-Sensoren (${draft.clientSensors.length} von ${max})`}>
        <div className="cfg-hint">
          Für ausgewählte Clients legt Home Assistant zwei Sensoren an: WLAN-Download und -Upload am Access Point (nicht der
          Internetverbrauch). Abwählen entfernt die Sensoren. Clients erscheinen nur mit Pseudonym.
        </div>
        {clientsError !== null && clientsError !== undefined && <ErrorBox error={clientsError} onRetry={onReload} />}
        {clients !== null && listed.length === 0 && missing.length === 0 && (
          <Unknown text="— noch kein Client erfasst (WLAN-Stationszähler der Access Points)" />
        )}
        <ul className="trf-checks">
          {listed.map(c => {
            const on = draft.clientSensors.includes(c.clientRef);
            return (
              <li key={c.clientRef}>
                <label className="trf-check">
                  <input type="checkbox" checked={on} disabled={locked || (!on && full)}
                    onChange={e => patch(toggleClientSensor(draft, c.clientRef, e.target.checked, max))} />
                  <span>{clientLabel(c.clientRef)} · {routerName(c.routerId)}</span>
                </label>
              </li>
            );
          })}
          {missing.map(ref => (
            <li key={ref}>
              <label className="trf-check">
                <input type="checkbox" checked disabled={locked}
                  onChange={e => patch(toggleClientSensor(draft, ref, e.target.checked, max))} />
                <span>{clientLabel(ref)} <span className="wifi-muted">· derzeit nicht erfasst</span></span>
              </label>
            </li>
          ))}
        </ul>
        {full && <div className="wifi-muted">Höchstens {max} Clients. Zum Hinzufügen erst einen anderen abwählen.</div>}
        {clients?.truncated && <div className="wifi-muted">Gezeigt werden die zuletzt gesehenen {listed.length} Clients.</div>}
      </SectionBox>

      {failure && <div className="cfg-notice cfg-notice--error" role="alert">{failure}</div>}
      {saved && !dirty && <Notice tone="ok">Gespeichert.</Notice>}
      <div className="trf-actions">
        <button type="submit" className="diag-btn diag-btn--primary cfg-btn" disabled={!dirty || locked}>
          {busy ? 'Speichert…' : 'Speichern'}
        </button>
        <button type="button" className="diag-btn cfg-btn" disabled={!dirty || busy}
          onClick={() => { setDraft(settingsDraft(view, users)); setFailure(null); }}>
          Zurücksetzen
        </button>
      </div>
    </form>
  );
}

export function RouterSettingsFacts({ view }: { view: SettingsView }) {
  return (
    <SectionBox title="Router">
      <Fact name="Eingeschaltet">{view.routersEnabled === null ? <Unknown text="—" /> : `${view.routersEnabled} von ${view.routers.length} Routern`}</Fact>
      <ul className="wifi-rows">
        {view.routers.map(r => (
          <li key={r.routerId} className="wifi-row">
            <span className="wifi-row__title">{routerName(r.routerId)}</span>
            <span>{r.enabled === null ? <Unknown text="—" /> : r.enabled ? 'an' : 'aus'}</span>
            <span className="wifi-muted">Profil {r.historyProfile ? PROFILE_TEXT[r.historyProfile] ?? r.historyProfile : '—'}</span>
          </li>
        ))}
      </ul>
      <div className="cfg-hint">
        Ein- und Ausschalten und das Profil stellen Sie je Router in den Integrationsoptionen ein (Einstellungen → Geräte &amp;
        Dienste → OpenWrt Router → Konfigurieren), nicht hier.
      </div>
    </SectionBox>
  );
}

export function TrafficSettings({ api, rev }: { api: TrafficApi; rev: number }) {
  const data = useSettingsData(api, rev);
  const { view, users, clients } = data;
  if (view === null) {
    if (data.error !== null) return <ErrorBox error={data.error} onRetry={data.reload} />;
    return <div className="cfg-skeleton" aria-busy="true" aria-label="Lädt"><div className="cfg-skeleton__row" /><div className="cfg-skeleton__row" /></div>;
  }
  const onSave = async (update: Parameters<TrafficApi['updateSettings']>[0]) => {
    const stored = await api.updateSettings(update); // throws: nothing counts as saved
    data.setView(stored);
    try {
      data.setUsers(await api.collectorUsers());
    } catch {
      data.reload();
    }
  };
  return (
    <div className="cfg-stack">
      {data.error !== null && <ErrorBox error={data.error} onRetry={data.reload} />}
      <RouterSettingsFacts view={view} />
      <SettingsForm view={view} users={users} clients={clients} usersError={data.usersError}
        clientsError={data.clientsError} onSave={onSave} onReload={data.reload} />
    </div>
  );
}
