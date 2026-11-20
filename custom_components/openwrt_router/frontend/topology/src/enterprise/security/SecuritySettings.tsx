/**
 * SecuritySettings — on/off, log path, syslog port, DNS names (administrators
 * edit; everyone else sees the values read-only).
 *
 * Only changed fields are sent. The collector is shown but cannot be chosen
 * ("noch nicht verfügbar"). Thresholds and subnet zones are not edited here.
 */

import React, { useEffect, useState } from 'react';
import type { SecurityApi, SettingsView } from './securityTypes';
import {
  PORT_MAX,
  PORT_MIN,
  buildSettingsUpdate,
  draftFromSettings,
  label,
  reasonText,
  LOG_PATH_LABEL,
  type SettingsDraft,
} from './securityLogic.ts';
import { ErrorBox, Fact, Notice, SectionBox, Skeleton, ToneBadge, Unknown, useAction, useResource } from './securityUi';

const PATHS: Array<{ id: string; label: string; help: string; available: boolean }> = [
  { id: 'off', label: LOG_PATH_LABEL.off, help: 'Firewall- und DNS-Erkennungen bleiben dann nicht verfügbar.', available: true },
  {
    id: 'syslog', label: LOG_PATH_LABEL.syslog,
    help: 'Home Assistant nimmt Syslog-Zeilen der Router entgegen. Die Router werden dabei nicht verändert; die Weiterleitung auf den Routern richten Sie selbst ein.',
    available: true,
  },
  { id: 'collector', label: LOG_PATH_LABEL.collector, help: 'Ein separater Log-Sammler.', available: false },
];

export function SecuritySettings({ api, rev, onChanged }: { api: SecurityApi; rev: number; onChanged: () => void }) {
  const res = useResource<SettingsView>(() => api.settings(), true, rev);
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const action = useAction();
  const view = res.data;

  useEffect(() => {
    if (view) setDraft(draftFromSettings(view.settings));
  }, [view]);

  if (view === null || draft === null) {
    return res.error !== null ? <ErrorBox error={res.error} onRetry={res.reload} /> : <Skeleton rows={4} />;
  }

  const canEdit = view.canEdit;
  const built = buildSettingsUpdate(view.settings, draft);
  const dirty = Object.keys(built.update).length > 0;
  const patch = (p: Partial<SettingsDraft>) => { setDraft({ ...draft, ...p }); setSaved(false); setFormError(null); action.clear(); };

  const save = async () => {
    if (built.error) { setFormError(built.error); return; }
    if (!dirty) return;
    const ok = await action.run(async () => { await api.updateSettings(built.update); });
    if (ok) {
      setSaved(true);
      res.reload();
      onChanged();
    }
  };

  const receiver = view.receiver;

  return (
    <div className="cfg-stack">
      {!canEdit && <Notice tone="info">Einstellungen kann nur ein Administrator ändern. Hier sehen Sie die aktuellen Werte.</Notice>}
      {res.error !== null && <ErrorBox error={res.error} onRetry={res.reload} />}

      <form className="cfg-stack" onSubmit={e => { e.preventDefault(); void save(); }}>
        <SectionBox title="Security Center">
          <label className="diag-check cfg-confirm">
            <input
              type="checkbox"
              checked={draft.enabled}
              disabled={!canEdit || action.busy}
              onChange={e => patch({ enabled: e.target.checked })}
            />
            <span>
              Security Center einschalten. Es wertet vorhandene Router-Daten aus und zeigt Hinweise an.
              Es beobachtet nur: keine Sperren, keine Scans. Ist es aus, wird nichts ausgewertet.
            </span>
          </label>
          {draft.enabled && !view.active && view.settings.enabled && (
            <Notice tone="warn">Eingeschaltet, aber noch nicht aktiv. Die Daten können unvollständig sein.</Notice>
          )}
        </SectionBox>

        <SectionBox title="Log-Pfad">
          <fieldset className="sec-fieldset" disabled={!canEdit || action.busy}>
            <legend className="sr-only">Log-Pfad</legend>
            {PATHS.map(p => (
              <label key={p.id} className={`diag-check cfg-radio sec-radio${p.available ? '' : ' sec-radio--off'}`}>
                <input
                  type="radio"
                  name="sec-log-path"
                  value={p.id}
                  checked={draft.logPath === p.id}
                  disabled={!p.available}
                  onChange={() => patch({ logPath: p.id })}
                />
                <span>
                  <span className="sec-radio__title">{p.label}</span>
                  {!p.available && <> <ToneBadge tone="muted">noch nicht verfügbar</ToneBadge></>}
                  <span className="cfg-hint sec-radio__help">{p.help}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {view.settings.logPath === 'collector' && (
            <Notice tone="warn">Der Collector ist eingestellt, aber noch nicht verfügbar. Es kommen keine Log-Daten an.</Notice>
          )}
          {draft.logPath === 'syslog' && (
            <label className="sec-field">
              <span>Syslog-Port (UDP, {PORT_MIN} bis {PORT_MAX})</span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={draft.syslogPort}
                disabled={!canEdit || action.busy}
                onChange={e => patch({ syslogPort: e.target.value })}
              />
            </label>
          )}
          {view.settings.logPath === 'syslog' && (
            <Fact name="Empfänger">
              {receiver === null || receiver.listening === null
                ? <Unknown />
                : receiver.listening
                  ? `hört auf Port ${receiver.port ?? '?'}`
                  : `hört nicht${receiver.reason ? `: ${reasonText([receiver.reason])}` : ''}`}
            </Fact>
          )}
        </SectionBox>

        <SectionBox title="Datenschutz">
          <label className="diag-check cfg-confirm">
            <input
              type="checkbox"
              checked={draft.keepDnsNames}
              disabled={!canEdit || action.busy}
              onChange={e => patch({ keepDnsNames: e.target.checked })}
            />
            <span>
              DNS-Namen behalten (Standard: aus). Ist die Option aus, werden aus DNS-Anfragen nur Zähler ausgewertet.
              Eingeschaltet können Domain-Namen in Belegen auftauchen. Sie zeigen, welche Seiten Geräte aufrufen.
              Nur einschalten, wenn das gewollt ist.
            </span>
          </label>
        </SectionBox>

        <SectionBox title="Weitere Einstellungen">
          <Fact name="Eigene Schwellwerte">{view.settings.thresholdCount === 0 ? 'keine (Standardwerte)' : view.settings.thresholdCount}</Fact>
          <Fact name="Subnetz-Zuordnungen">{view.subnetZoneCount === null ? <Unknown /> : view.subnetZoneCount}</Fact>
          <div className="cfg-hint">Diese Werte werden in dieser Ansicht nicht bearbeitet.</div>
        </SectionBox>

        {formError && <div className="cfg-notice cfg-notice--error" role="alert">{formError}</div>}
        {action.error !== null && <ErrorBox error={action.error} />}
        {saved && !dirty && <Notice tone="ok">Gespeichert.</Notice>}
        {canEdit && (
          <div className="sec-actions">
            <button type="submit" className="diag-btn diag-btn--primary cfg-btn" disabled={!dirty || action.busy}>
              {action.busy ? 'Speichert…' : 'Speichern'}
            </button>
            <button type="button" className="diag-btn cfg-btn" disabled={!dirty || action.busy}
              onClick={() => { setDraft(draftFromSettings(view.settings)); setFormError(null); action.clear(); }}>
              Zurücksetzen
            </button>
          </div>
        )}
      </form>
    </div>
  );
}
